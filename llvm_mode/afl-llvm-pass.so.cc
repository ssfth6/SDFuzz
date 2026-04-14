/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <set>

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <list>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CFGPrinter.h"

#if defined(LLVM34)
#include "llvm/DebugInfo.h"
#else
#include "llvm/IR/DebugInfo.h"
#endif

#if defined(LLVM34) || defined(LLVM35) || defined(LLVM36)
#define LLVM_OLD_DEBUG_API
#endif

using namespace llvm;

cl::opt<std::string> DistanceFile(
    "distance",
    cl::desc("Distance file containing the distance of each basic block to the provided targets."),
    cl::value_desc("filename")
);

cl::opt<std::string> TargetsFile(
    "targets",
    cl::desc("Input file containing the target states."),
    cl::value_desc("targets"));

cl::opt<std::string> OutDirectory(
    "outdir",
    cl::desc("Output directory where Ftargets.txt, Fnames.txt, and BBnames.txt are generated."),
    cl::value_desc("outdir"));

static std::string LLVMInstructionAsString(Instruction * I) {
  std::string instString;
  raw_string_ostream N(instString);
  I -> print(N);
  return N.str();
}


namespace llvm {

template<>
struct DOTGraphTraits<Function*> : public DefaultDOTGraphTraits {
  DOTGraphTraits(bool isSimple=true) : DefaultDOTGraphTraits(isSimple) {}

  static std::string getGraphName(Function *F) {
    return "CFG for '" + F->getName().str() + "' function";
  }

  std::string getNodeLabel(BasicBlock *Node, Function *Graph) {
    if (!Node->getName().empty()) {
      return Node->getName().str();
    }

    std::string Str;
    raw_string_ostream OS(Str);

    Node->printAsOperand(OS, false);
    return OS.str();
  }
};

} // namespace llvm

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}

char AFLCoverage::ID = 0;

static void getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line) {
#ifdef LLVM_OLD_DEBUG_API
  DebugLoc Loc = I->getDebugLoc();
  if (!Loc.isUnknown()) {
    DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
    DILocation oDILoc = cDILoc.getOrigLocation();

    Line = oDILoc.getLineNumber();
    Filename = oDILoc.getFilename().str();

    if (filename.empty()) {
      Line = cDILoc.getLineNumber();
      Filename = cDILoc.getFilename().str();
    }
  }
#else
  if (DILocation *Loc = I->getDebugLoc()) {
    Line = Loc->getLine();
    Filename = Loc->getFilename().str();

    if (Filename.empty()) {
      DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc) {
        Line = oDILoc->getLine();
        Filename = oDILoc->getFilename().str();
      }
    }
  }
#endif /* LLVM_OLD_DEBUG_API */
}

static bool isBlacklisted(const Function *F) {
  static const SmallVector<std::string, 8> Blacklist = {
    "asan.",
    "llvm.",
    "sancov.",
    "__ubsan_handle_",
    "free",
    "malloc",
    "calloc",
    "realloc"
  };

  for (auto const &BlacklistFunc : Blacklist) {
    if (F->getName().startswith(BlacklistFunc)) {
      return true;
    }
  }

  return false;
}
// Helper function to extract content within parentheses
static std::string extractParenthesesContent(const std::string& line) {
    size_t open_paren = line.find('(');
    size_t close_paren = line.find(')', open_paren);
    
    if (open_paren != std::string::npos && close_paren != std::string::npos) {
        return line.substr(open_paren + 1, close_paren - open_paren - 1);
    }
    
    return ""; // No parentheses found
}

// NEW: Helper function to extract function name
static std::string extractFunctionName(const std::string& line) {
    // Find the opening parenthesis
    size_t open_paren = line.find('(');
    
    if (open_paren != std::string::npos) {
        // Extract function name (everything before '(')
        std::string function_name = line.substr(0, open_paren);
        
        // Trim trailing whitespace from function name
        size_t func_end = function_name.find_last_not_of(" \t");
        if (func_end != std::string::npos) {
            function_name = function_name.substr(0, func_end + 1);
        }
        
        return function_name;
    } else {
        // No parentheses found, treat entire line as function name
        return line;
    }
}

// C++ version of hash_stack function
static unsigned long hash_stack(char** stack, int count) {
    unsigned long hash = 0;
    
    for (int i = 0; i < count; i++) {
        char* str = stack[i];
        unsigned long func_hash = 0;
        while (*str) {
            func_hash = (func_hash << 1) ^ *str++;
        }
        hash ^= func_hash + i; // Include position to make order matter
    }
    
    return hash;
}


bool AFLCoverage::runOnModule(Module &M) {

  bool is_aflgo = false;
  bool is_aflgo_preprocessing = false;
  float min_distance = 99999;


  std::list<std::string> targets;
  std::map<std::string, int> bb_to_dis;
  std::vector<std::string> basic_blocks;
  std::set<std::string> keep;
  std::ofstream debug( "/root/sdfuzz/debug.txt", std::ofstream::out | std::ofstream::app);
      struct CallStackPattern {
        std::string caller_key;
        unsigned long expected_hash;
    };
  std::vector<CallStackPattern> predefined_patterns;

  if (!TargetsFile.empty() && DistanceFile.empty()) {

    if (OutDirectory.empty()) {
      FATAL("Provide output directory '-outdir <directory>'");
      return false;
    }

    std::ifstream targetsfile(TargetsFile);
    std::string line;

    while (std::getline(targetsfile, line)) {
        // Trim whitespace first
        size_t start = line.find_first_not_of(" \t\r\n");
        size_t end = line.find_last_not_of(" \t\r\n");
        
        if (start == std::string::npos) {
            continue;
        }
        
        std::string trimmed = line.substr(start, end - start + 1);
        
        // Extract content within parentheses (e.g., "main.c:89")
        std::string target_location = extractParenthesesContent(trimmed);
        
        if (!target_location.empty()) {
            targets.push_back(target_location);
        } else {
            // If no parentheses found, use the trimmed line
            targets.push_back(trimmed);
        }
    }
    // while (std::getline(targetsfile, line))
    //   targets.push_back(line);
    targetsfile.close();

    is_aflgo_preprocessing = true;

  } else if (!DistanceFile.empty() && !TargetsFile.empty() ) {



    std::ifstream targetsfile(TargetsFile);
    std::string line;
    std::vector<std::string> call_stack_functions;

    while (std::getline(targetsfile, line)) {
        // Trim whitespace first
        size_t start = line.find_first_not_of(" \t\r\n");
        size_t end = line.find_last_not_of(" \t\r\n");
        
        if (start == std::string::npos) {
            continue;
        }
        
        std::string trimmed = line.substr(start, end - start + 1);
        
        // Extract content within parentheses (e.g., "main.c:89") - EXISTING LOGIC
        std::string target_location = extractParenthesesContent(trimmed);
        
        if (!target_location.empty()) {
            targets.push_back(target_location);
        } else {
            // If no parentheses found, use the trimmed line
            targets.push_back(trimmed);
        }
        // debug << "Target: " << target_location << "\n";
        
        // Extract function name for hash computation
        std::string function_name = extractFunctionName(trimmed);
        if (!function_name.empty()) {
            call_stack_functions.push_back(function_name);
        }
    }

    targetsfile.close();

    // Compute hash for each prefix of the call stack
    if (!call_stack_functions.empty()) {
        for (size_t i = 1; i <= call_stack_functions.size(); i++) {
            // Create array for the current prefix
            std::vector<const char*> func_names;
            for (size_t j = 0; j < i; j++) {
                func_names.push_back(call_stack_functions[j].c_str());
            }
            
            // Compute hash for this prefix
            unsigned long prefix_hash = hash_stack(const_cast<char**>(func_names.data()), func_names.size());
            
            // Create pattern and add to vector
            CallStackPattern pattern;
            pattern.caller_key = call_stack_functions[i-1];  // Last function in prefix
            pattern.expected_hash = prefix_hash;
            // debug << "Pattern: " << pattern.caller_key << ", Hash: " << pattern.expected_hash << "\n";
            predefined_patterns.push_back(pattern);
        }
    }

    std::ifstream cf(DistanceFile);

    std::string DdgFile = DistanceFile;
    DdgFile = DdgFile.substr(0, DdgFile.length()-16);
    DdgFile.append("ctrl-data.dot");

    std::ifstream ddgf(DdgFile);

    if (cf.is_open()) {

      std::string line;
      while (getline(cf, line)) {

        std::size_t pos = line.find(",");
        std::string bb_name = line.substr(0, pos);
        int bb_dis = (int) (atof(line.substr(pos + 1, line.length()).c_str()));

        bb_to_dis.emplace(bb_name, bb_dis);
        basic_blocks.push_back(bb_name);

      }
      cf.close();

      is_aflgo = true;

    } else {
      FATAL("Unable to find %s.", DistanceFile.c_str());
      return false;
    }

    //debug << "keep: "<< DdgFile << "\n";
    if (ddgf.is_open()) {
      //debug << "keep1: "<< DdgFile << "\n";
      std::string line;
      while (getline(ddgf, line)) { 
        std::string bb_name = line.substr(0, line.length());
        //debug << "keep: "<< bb_name << "\n";
        keep.insert(bb_name);
        
      }
      ddgf.close();
      is_aflgo = true;

    } else {
      FATAL("Unable to find %s.", DdgFile.c_str());
      return false;
    }
  }

  //for(auto i: keep) {
  //   debug << "keep: "<< i << "\n"; 
  //}

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    if (is_aflgo || is_aflgo_preprocessing)
      SAYF(cCYA "aflgo-llvm-pass (yeah!) " cBRI VERSION cRST " (%s mode)\n",
           (is_aflgo_preprocessing ? "preprocessing" : "distance instrumentation"));
    else
      SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");


  } else be_quiet = 1;

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Default: Not selective */
  char* is_selective_str = getenv("AFLGO_SELECTIVE");
  unsigned int is_selective = 0;

  if (is_selective_str && sscanf(is_selective_str, "%u", &is_selective) != 1)
    FATAL("Bad value of AFLGO_SELECTIVE (must be 0 or 1)");

  char* dinst_ratio_str = getenv("AFLGO_INST_RATIO");
  unsigned int dinst_ratio = 100;

  if (dinst_ratio_str) {

    if (sscanf(dinst_ratio_str, "%u", &dinst_ratio) != 1 || !dinst_ratio ||
        dinst_ratio > 100)
      FATAL("Bad value of AFLGO_INST_RATIO (must be between 1 and 100)");

  }

  /* Instrument all the things! */

  int inst_blocks = 0;

  if (is_aflgo_preprocessing) {

    std::ofstream bbnames(OutDirectory + "/BBnames.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream bbcalls(OutDirectory + "/BBcalls.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream fnames(OutDirectory + "/Fnames.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream ftargets(OutDirectory + "/Ftargets.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream iicalls(OutDirectory + "/IIcalls.txt", std::ofstream::out | std::ofstream::app);

    /* Create dot-files directory */
    std::string dotfiles(OutDirectory + "/dot-files");
    if (sys::fs::create_directory(dotfiles)) {
      FATAL("Could not create directory %s.", dotfiles.c_str());
    }


    for (auto &F : M) {

      //debug << "module: " << &M << "\n";
      //debug << "module: " << M.getSourceFileName() << "\n";

      bool has_BBs = false;
      std::string funcName = F.getName();

      /* Black list of function names */
      if (isBlacklisted(&F)) {
        continue;
      }

      bool is_target = false;
      for (auto &BB : F) {

        std::string bb_name("");
        std::string filename;
        unsigned line;

        for (auto &I : BB) {
          getDebugLoc(&I, filename, line);
	  
          /* Don't worry about external libs */
          static const std::string Xlibs("/usr/");
          if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
            continue;
	  
          
          if (bb_name.empty()) {

            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            bb_name = filename + ":" + std::to_string(line);
          }

          if (!is_target) {
              for (auto &target : targets) {
                std::size_t found = target.find_last_of("/\\");
                if (found != std::string::npos)
                  target = target.substr(found + 1);

                std::size_t pos = target.find_last_of(":");
                std::string target_file = target.substr(0, pos);
                unsigned int target_line = atoi(target.substr(pos + 1).c_str());

                if (!target_file.compare(filename) && target_line == line)
                  is_target = true;
		  
              }
            }

            if (auto *c = dyn_cast<CallInst>(&I)) {

              std::size_t found = filename.find_last_of("/\\");
              if (found != std::string::npos)
                filename = filename.substr(found + 1);

              if (auto *CalledF = c->getCalledFunction()) {
                if (!isBlacklisted(CalledF))
                  bbcalls << bb_name << "," << CalledF->getName().str() << "\n";
                  if (CalledF->getName().str()!="llvm.dbg.declare" && CalledF->getName().str()!="llvm.dbg.value" )
		  iicalls << filename + "," + std::to_string(line) << " " << CalledF->getName().str() << "\n";
              }
            }
        }

        if (!bb_name.empty()) {

          BB.setName(bb_name + ":");
          if (!BB.hasName()) {
            std::string newname = bb_name + ":";
            Twine t(newname);
            SmallString<256> NameData;
            StringRef NameRef = t.toStringRef(NameData);
            BB.setValueName(ValueName::Create(NameRef));
          }

          bbnames << BB.getName().str() << "\n";
          has_BBs = true;

#ifdef AFLGO_TRACING
          auto *TI = BB.getTerminator();
          IRBuilder<> Builder(TI);

          Value *bbnameVal = Builder.CreateGlobalStringPtr(bb_name);
          Type *Args[] = {
              Type::getInt8PtrTy(M.getContext()) //uint8_t* bb_name
          };
          FunctionType *FTy = FunctionType::get(Type::getVoidTy(M.getContext()), Args, false);
          Constant *instrumented = M.getOrInsertFunction("llvm_profiling_call", FTy);
          Builder.CreateCall(instrumented, {bbnameVal});
#endif

        }
      }

      if (has_BBs) {
        /* Print CFG */
        std::string cfgFileName = dotfiles + "/cfg." + funcName + ".dot";
        std::error_code EC;
        raw_fd_ostream cfgFile(cfgFileName, EC, sys::fs::F_None);
        if (!EC) {
          WriteGraph(cfgFile, &F, true);
        }

        if (is_target)
          ftargets << F.getName().str() << "\n";
        fnames << F.getName().str() << "\n";
      }
    }

  } else {
    /* Distance instrumentation */
    debug << "Distance instrumentation\n";
    LLVMContext &C = M.getContext();
    IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

#ifdef __x86_64__
    IntegerType *LargestType = Int64Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 8);
#else
    IntegerType *LargestType = Int32Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 4);
#endif
    ConstantInt *MapDistLoc = ConstantInt::get(LargestType, MAP_SIZE);
    ConstantInt *One = ConstantInt::get(LargestType, 1);

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */

    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

    GlobalVariable *AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
        0, GlobalVariable::GeneralDynamicTLSModel, 0, false);


    std::vector<Type*> StackPatternFields;
    StackPatternFields.push_back(ArrayType::get(Int8Ty, MAX_FUNC_NAME_LEN)); // caller_key[32]
    StackPatternFields.push_back(Int64Ty);                                   // expected_hash
    StructType *StackPatternTy = StructType::create(C, StackPatternFields, "stack_pattern_t");

    // Create array type for __afl_call_stack[MAX_PATTERNS]
    ArrayType *StackPatternArrayTy = ArrayType::get(StackPatternTy, MAX_PATTERNS);

    // Check if variables already exist, otherwise create external declarations
    GlobalVariable *AFLCallStack = M.getGlobalVariable("__afl_call_stack");
    if (!AFLCallStack) {
        AFLCallStack = new GlobalVariable(M, StackPatternArrayTy, false,
                                        GlobalValue::ExternalLinkage, nullptr, 
                                        "__afl_call_stack");
    }

    GlobalVariable *AFLCallStackCount = M.getGlobalVariable("__afl_call_stack_count");
    if (!AFLCallStackCount) {
        AFLCallStackCount = new GlobalVariable(M, Int32Ty, false,
                                            GlobalValue::ExternalLinkage, nullptr,
                                            "__afl_call_stack_count");
    }

    // Create array of pattern initializers (reuse your existing logic)
    std::vector<Constant*> pattern_inits;

    for (size_t i = 0; i < MAX_PATTERNS; i++) {
        if (i < predefined_patterns.size()) {
            // Create caller_key array
            std::vector<Constant*> key_chars;
            const std::string& key = predefined_patterns[i].caller_key;
            
            for (int j = 0; j < MAX_FUNC_NAME_LEN; j++) {
                if (j < key.length()) {
                    key_chars.push_back(ConstantInt::get(Int8Ty, key[j]));
                } else {
                    key_chars.push_back(ConstantInt::get(Int8Ty, 0));
                }
            }
            
            Constant *key_array = ConstantArray::get(ArrayType::get(Int8Ty, MAX_FUNC_NAME_LEN), key_chars);
            Constant *hash_val = ConstantInt::get(Int64Ty, predefined_patterns[i].expected_hash);
            
            std::vector<Constant*> struct_vals = {key_array, hash_val};
            Constant *pattern_struct = ConstantStruct::get(StackPatternTy, struct_vals);
            pattern_inits.push_back(pattern_struct);
        } else {
            // Fill remaining slots with zeros
            pattern_inits.push_back(Constant::getNullValue(StackPatternTy));
        }
    }

    // Create the complete array constant
    Constant *array_init = ConstantArray::get(StackPatternArrayTy, pattern_inits);

    // Find main function to insert initialization code
    Function *MainFunc = M.getFunction("main");
    if (MainFunc && !MainFunc->empty()) {
        BasicBlock &EntryBB = MainFunc->getEntryBlock();
        IRBuilder<> Builder(&EntryBB, EntryBB.getFirstInsertionPt());
        
        // Store the entire array with a single instruction
        Builder.CreateStore(array_init, AFLCallStack);
        
        // Store the count with a single instruction
        Builder.CreateStore(ConstantInt::get(Int32Ty, predefined_patterns.size()), 
                        AFLCallStackCount);
    }

    
    for (auto &F : M) {

      int distance = -1;
      static const std::string Xlibs("/usr/");

      for (auto &BB : F) {

        distance = -1;
        bool flag = true;

        if (true) {

          std::string bb_name("");
          for (auto &I : BB) {
            std::string filename;
            unsigned line;
            getDebugLoc(&I, filename, line);

            if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
              continue;
            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            bb_name = filename + ":" + std::to_string(line);
            debug << "debug: " << bb_name << "\n";
            break;
          }

          //find irrelevant bbs
          if(!bb_name.empty()) {
            //irrelevent
            if(keep.count(bb_name)==0) {
              flag=false;
            }
            else{
              //debug << "skip: " << bb_name << "\n";
            }
          }

          if (!bb_name.empty() && is_aflgo) {

            if (find(basic_blocks.begin(), basic_blocks.end(), bb_name) == basic_blocks.end()) {

              if (is_selective)
                continue;

            } else {

              /* Find distance for BB */

              if (AFL_R(100) < dinst_ratio) {
                std::map<std::string,int>::iterator it;
                for (it = bb_to_dis.begin(); it != bb_to_dis.end(); ++it)
                  if (it->first.compare(bb_name) == 0)
                    distance = it->second;

              }
            }
          }
        }

        if(flag==false){
          continue;
        }

    




        
        BasicBlock::iterator IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));

        if (AFL_R(100) >= inst_ratio) continue;

        /* Make up cur_loc */

        unsigned int cur_loc = AFL_R(MAP_SIZE);

        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

        /* Load prev_loc */

        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        /* Load SHM pointer */

        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MapPtrIdx =
            IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

        /* Update bitmap */

        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
        IRB.CreateStore(Incr, MapPtrIdx)
           ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        /* Set prev_loc to cur_loc >> 1 */

        StoreInst *Store =
            IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        if (distance >= 0) {


          ConstantInt *Distance =
              ConstantInt::get(LargestType, (unsigned) distance);
          ConstantInt *Zero =
              ConstantInt::get(LargestType, (unsigned) 0);


          /* Add distance to shm[MAPSIZE] */

          Value *MapDistPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapDistLoc), LargestType->getPointerTo());
          LoadInst *MapDist = IRB.CreateLoad(MapDistPtr);
          MapDist->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          //Value *PreDis = IRB.CreateAdd(MapDist, Zero);
          Value *Sub = IRB.CreateSub(Distance, MapDist);
          ConstantInt *Bits = ConstantInt::get(LargestType, 63);
          Value *Lshr = IRB.CreateLShr(Sub, Bits);
          Value *Mul1 = IRB.CreateMul(Lshr, Distance);
          Value *Sub1 = IRB.CreateSub(One, Lshr);
          Value *Mul2 = IRB.CreateMul(Sub1, MapDist);
          Value *Incr = IRB.CreateAdd(Mul1, Mul2);

          IRB.CreateStore(Incr, MapDistPtr)
           ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          /* Increase count at shm[MAPSIZE + (4 or 8)] */

          Value *MapCntPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapCntLoc), LargestType->getPointerTo());
          LoadInst *MapCnt = IRB.CreateLoad(MapCntPtr);
          MapCnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrCnt = IRB.CreateAdd(MapCnt, One);
          IRB.CreateStore(IncrCnt, MapCntPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        }

        inst_blocks++;

      }
    }
    
    for (auto &F : M) {
    bool calldone = false;
    // debug << "Processing function: " << F.getName().str() << "\n";
    
    for (auto &BB : F) {
        if (calldone) {
            // debug << "Function already instrumented, skipping BB\n";
            break;
        }
        
        // Collect all target calls and first instruction per line in this basic block
        std::map<std::string, std::pair<Instruction*, CallInst*>> line_instructions; // target -> {first_instr, last_call}
        
        for (auto &I : BB) {
            if (auto *callInst = dyn_cast<CallInst>(&I)) {
                std::string filename;
                unsigned line;
                getDebugLoc(&I, filename, line);
                
                // Skip invalid locations
                if (filename.empty() || line == 0) {
                    continue;
                }
                
                // Skip external libraries
                static const std::string Xlibs("/usr/");
                if (!filename.compare(0, Xlibs.size(), Xlibs)) {
                    continue;
                }
                
                // Extract just filename (remove path)
                std::size_t found = filename.find_last_of("/\\");
                if (found != std::string::npos) {
                    filename = filename.substr(found + 1);
                }
                
                // Check against all targets
                for (const auto &target : targets) {
                    // Parse target (make a copy to avoid modifying original)
                    std::string target_copy = target;
                    std::size_t target_found = target_copy.find_last_of("/\\");
                    if (target_found != std::string::npos) {
                        target_copy = target_copy.substr(target_found + 1);
                    }
                    
                    std::size_t pos = target_copy.find_last_of(":");
                    if (pos == std::string::npos) continue; // Skip malformed targets
                    
                    std::string target_file = target_copy.substr(0, pos);
                    unsigned int target_line = atoi(target_copy.substr(pos + 1).c_str());
                    
                    // Check for match
                    if (target_file == filename && target_line == line) {
                        // debug << "MATCH FOUND: " << target_copy << "\n";
                        
                        // Find first instruction on this line if not already found
                        if (line_instructions.find(target_copy) == line_instructions.end()) {
                            // Search for first instruction on this line
                            Instruction *firstInstr = nullptr;
                            for (auto &searchI : BB) {
                                std::string searchFilename;
                                unsigned searchLine;
                                getDebugLoc(&searchI, searchFilename, searchLine);
                                
                                if (!searchFilename.empty() && searchLine == target_line) {
                                    std::size_t searchFound = searchFilename.find_last_of("/\\");
                                    if (searchFound != std::string::npos) {
                                        searchFilename = searchFilename.substr(searchFound + 1);
                                    }
                                    
                                    if (searchFilename == target_file) {
                                        firstInstr = &searchI;
                                        break;
                                    }
                                }
                            }
                            line_instructions[target_copy] = {firstInstr, callInst};
                        } else {
                            // Update the last call (keep first instruction)
                            line_instructions[target_copy].second = callInst;
                        }
                        break; // Found match for this call, move to next call
                    }
                }
            }
        }
        
        // Insert instrumentation for all matched targets in this BB
        if (!line_instructions.empty()) {
            for (const auto &pair : line_instructions) {
                std::string target = pair.first;
                Instruction *firstInstr = pair.second.first;
                CallInst *lastCall = pair.second.second;
                
                // Insert checkbeforecall_2f2 before first instruction on line
                if (firstInstr) {
                    IRBuilder<> beforeIRB(firstInstr);
                    beforeIRB.SetInsertPoint(firstInstr);
                    
                    FunctionType *sig = FunctionType::get(Type::getVoidTy(M.getContext()), false);
                    auto checkbefore = M.getOrInsertFunction("checkbeforecall_2f2", sig);
                    beforeIRB.CreateCall(checkbefore);
                    
                    // debug << "Inserted checkbefore at start of line for: " << target << "\n";
                }
                
                // Insert checkaftercall_2f2 after last call on line
                if (lastCall) {
                    IRBuilder<> afterIRB(lastCall);
                    
                    // Safe insertion point
                    if (lastCall->getNextNode()) {
                        afterIRB.SetInsertPoint(lastCall->getNextNode());
                    } else {
                        // Insert at end of basic block if no next instruction
                        afterIRB.SetInsertPoint(lastCall->getParent());
                    }
                    
                    // Create and insert the check call
                    FunctionType *sig = FunctionType::get(Type::getVoidTy(M.getContext()), false);
                    auto checkafter = M.getOrInsertFunction("checkaftercall_2f2", sig);
                    afterIRB.CreateCall(checkafter);
                    
                    // debug << "Inserted checkafter at end of line for: " << target << "\n";
                }
            }
            calldone = true;
        }
    }
}
  }

  /* Say something nice. */

  if (!is_aflgo_preprocessing && !be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%, dist. ratio %u%%).",
             inst_blocks,
             getenv("AFL_HARDEN")
             ? "hardened"
             : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN"))
               ? "ASAN/MSAN" : "non-hardened"),
             inst_ratio, dinst_ratio);

  }

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);

