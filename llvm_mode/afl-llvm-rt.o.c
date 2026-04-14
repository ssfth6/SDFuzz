/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is the rewrite of afl-as.h's main_payload.

*/

#include "../config.h"
#include "../types.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>

#ifdef AFLGO_TRACING
#include "../hash.h"
#include "../hashset.h"
#include <assert.h>

/* Variables for profiling */
hashset_t edgeSet;
static FILE* filefd = NULL;
static char edgeStr[1024];

static const unsigned int prime_1 = 73;
static const unsigned int prime_2 = 5009;
/* End of profiling variables */
#endif /* ^AFLGO_TRACING */


/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifdef USE_TRACE_PC
#  define CONST_PRIO 5
#else
#  define CONST_PRIO 0
#endif /* ^USE_TRACE_PC */



typedef struct {
    char caller_key[MAX_FUNC_NAME_LEN];
    unsigned long expected_hash;
} stack_pattern_t;


/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

u8  __afl_area_initial[MAP_SIZE + 16];
u8* __afl_area_ptr = __afl_area_initial;

stack_pattern_t __afl_call_stack[MAX_PATTERNS] = {{0}};
int __afl_call_stack_count = 0;
int __afl_call_layer = 0;

__thread u32 __afl_prev_loc;


/* Running in persistent mode? */

static u8 is_persistent;


/* SHM setup. */

static void __afl_map_shm(void) {

  u8 *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */

    if (__afl_area_ptr == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;


  }

}


/* Fork server logic. */

static void __afl_start_forkserver(void) {

  static u8 tmp[4];
  s32 child_pid;

  u8  child_stopped = 0;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    }

    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */

      if (!child_pid) {

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        return;
  
      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}


/* A simplified persistent mode handler, used as explained in README.llvm. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {

      memset(__afl_area_ptr, 0, MAP_SIZE + 16);
      __afl_area_ptr[0] = 1;
      //memset(__afl_call_stack, 0, sizeof(__afl_call_stack));
      __afl_prev_loc = 0;
      __afl_call_layer = 0;
      
    }

    cycle_cnt  = max_cnt;
    first_pass = 0;
    return 1;

  }

  if (is_persistent) {

    if (--cycle_cnt) {

      raise(SIGSTOP);

      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
      __afl_call_layer = 0;

      return 1;

    } else {

      /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */

      __afl_area_ptr = __afl_area_initial;

    }

  }

  return 0;

}


/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

  static u8 init_done;

  if (!init_done) {

    __afl_map_shm();
    __afl_start_forkserver();
    init_done = 1;

  }

}


/* Proper initialization routine. */

__attribute__((constructor(CONST_PRIO))) void __afl_auto_init(void) {

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}


/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  __afl_area_ptr[*guard]++;
}


/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {

  u32 inst_ratio = 100;
  u8* x;

  if (start == stop || *start) return;

  x = getenv("AFL_INST_RATIO");
  if (x) inst_ratio = atoi(x);

  if (!inst_ratio || inst_ratio > 100) {
    fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
    abort();
  }

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  *(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {

    if (R(100) < inst_ratio) *start = R(MAP_SIZE - 1) + 1;
    else *start = 0;

    start++;

  }

}


#ifdef AFLGO_TRACING
/* Hashset implementation for C */
hashset_t hashset_create()
{
    hashset_t set = (hashset_t) calloc(1, sizeof(struct hashset_st));

    if (set == NULL) {
        return NULL;
    }
    set->nbits = 3;
    set->capacity = (size_t)(1 << set->nbits);
    set->mask = set->capacity - 1;
    set->items = (unsigned long*) calloc(set->capacity, sizeof(size_t));
    if (set->items == NULL) {
        hashset_destroy(set);
        return NULL;
    }
    set->nitems = 0;
    set->n_deleted_items = 0;
    return set;
}

size_t hashset_num_items(hashset_t set)
{
    return set->nitems;
}

void hashset_destroy(hashset_t set)
{
    if (set) {
        free(set->items);
    }
    free(set);
}

static int hashset_add_member(hashset_t set, void *item)
{
    size_t value = (size_t)item;
    size_t ii;

    if (value == 0 || value == 1) {
        return -1;
    }

    ii = set->mask & (prime_1 * value);

    while (set->items[ii] != 0 && set->items[ii] != 1) {
        if (set->items[ii] == value) {
            return 0;
        } else {
            /* search free slot */
            ii = set->mask & (ii + prime_2);
        }
    }
    set->nitems++;
    if (set->items[ii] == 1) {
        set->n_deleted_items--;
    }
    set->items[ii] = value;
    return 1;
}

static void maybe_rehash(hashset_t set)
{
    size_t *old_items;
    size_t old_capacity, ii;


    if (set->nitems + set->n_deleted_items >= (double)set->capacity * 0.85) {
        old_items = set->items;
        old_capacity = set->capacity;
        set->nbits++;
        set->capacity = (size_t)(1 << set->nbits);
        set->mask = set->capacity - 1;
        set->items = (unsigned long*) calloc(set->capacity, sizeof(size_t));
        set->nitems = 0;
        set->n_deleted_items = 0;
        assert(set->items);
        for (ii = 0; ii < old_capacity; ii++) {
            hashset_add_member(set, (void *)old_items[ii]);
        }
        free(old_items);
    }
}

int hashset_add(hashset_t set, void *item)
{
    int rv = hashset_add_member(set, item);
    maybe_rehash(set);
    return rv;
}

int hashset_remove(hashset_t set, void *item)
{
    size_t value = (size_t)item;
    size_t ii = set->mask & (prime_1 * value);

    while (set->items[ii] != 0) {
        if (set->items[ii] == value) {
            set->items[ii] = 1;
            set->nitems--;
            set->n_deleted_items++;
            return 1;
        } else {
            ii = set->mask & (ii + prime_2);
        }
    }
    return 0;
}

int hashset_is_member(hashset_t set, void *item)
{
    size_t value = (size_t)item;
    size_t ii = set->mask & (prime_1 * value);

    while (set->items[ii] != 0) {
        if (set->items[ii] == value) {
            return 1;
        } else {
            ii = set->mask & (ii + prime_2);
        }
    }
    return 0;
}

/*End of hashset implementation for C */

inline __attribute__((always_inline))
void writeBB(const char* bbname) {
    strcat(edgeStr, bbname);
    size_t cksum=(size_t)hash32(bbname, strlen(edgeStr), 0xa5b35705);
    if(!hashset_is_member(edgeSet,(void*)cksum)) {
        fprintf(filefd, "[BB]: %s\n", bbname);
        hashset_add(edgeSet, (void*)cksum);
    }
    strcpy(edgeStr, bbname);
    fflush(filefd);
}

void llvm_profiling_call(const char* bbname)
	__attribute__((visibility("default")));

void llvm_profiling_call(const char* bbname) {
    if (filefd != NULL) {
        writeBB(bbname);
    } else if (getenv("AFLGO_PROFILER_FILE")) {
        filefd = fopen(getenv("AFLGO_PROFILER_FILE"), "a+");
        if (filefd != NULL) {
            strcpy(edgeStr, "START");
            edgeSet = hashset_create();
            fprintf(filefd, "--------------------------\n");
            writeBB(bbname);
        }
    }
}
#endif /* ^AFLGO_TRACING */



void checkaftercall_2f2()
  __attribute__((visibility("default")));
void checkbeforecall_2f2()
  __attribute__((visibility("default")));

#include <execinfo.h>     // For backtrace functions



// Simple XOR hash function (fastest)
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

static char* extract_function_name(const char* symbol) {
    char* func_name = NULL;
    
    // Try to extract function name
    char* start = strchr(symbol, '(');
    char* end = strchr(symbol, '+');
    
    if (start && end && start < end) {
        start++; // Skip '('
        int len = end - start;
        func_name = malloc(len + 1);
        strncpy(func_name, start, len);
        func_name[len] = '\0';
    } else {
        func_name = strdup(symbol);
    }
    
    return func_name;

}

void checkbeforecall_2f2() {
    __afl_call_layer++;
}

void checkaftercall_2f2() {
    const int MAX_STACK_SIZE = 64;
    void* stack_addrs[MAX_STACK_SIZE];
    char* current_stack[MAX_STACK_SIZE];
    char* current_reversed[MAX_STACK_SIZE];
    
    // Get current call stack
    int stack_size = backtrace(stack_addrs, MAX_STACK_SIZE);
    char** stack_symbols = backtrace_symbols(stack_addrs, stack_size);
    
    
    if (!stack_symbols || stack_size < 2) {
        if (stack_symbols) free(stack_symbols);
        __afl_call_layer--;
        return;
    }
    
    // Extract function names, excluding checkaftercall_2f2 (index 0)
    int current_count = 0;
    for (int i = 1; i < stack_size && current_count < MAX_STACK_SIZE - 1; i++) {
        char* func_name = extract_function_name(stack_symbols[i]);
        if (func_name && strlen(func_name) > 0) {
            current_stack[current_count++] = func_name;
        }
    }
    
    // Find main and truncate stack from main upward
    int main_index = -1;
    for (int i = 0; i < current_count; i++) {
        if (strstr(current_stack[i], "main")) {
            main_index = i;
            break;
        }
    }
    
    if (main_index == -1) {
        for (int i = 0; i < current_count; i++) {
            free(current_stack[i]);
        }
        free(stack_symbols);
        __afl_call_layer--;
        return;
    }
    
    // Free the functions deeper than main
    for (int i = main_index + 1; i < current_count; i++) {
        free(current_stack[i]);
    }
    
    // Update count to only include functions from main upward
    current_count = main_index + 1;
    
    if (current_count < 1) {
        free(stack_symbols);
        __afl_call_layer--;
        return;
    }
    
    // LAYER DEPTH CHECK
    int expected_depth = current_count; // Subtract 1 for main
    
    if (__afl_call_layer != expected_depth) {
        for (int i = 0; i < current_count; i++) {
            free(current_stack[i]);
        }
        free(stack_symbols);
        __afl_call_layer--;
        return;
    }
    
    char* caller_key = current_stack[0];
    
    // Find predefined pattern for this caller
    stack_pattern_t* pattern = NULL;
    
    for (int i = 0; i < __afl_call_stack_count; i++) {
        if (strstr(caller_key, __afl_call_stack[i].caller_key) || 
            strstr(__afl_call_stack[i].caller_key, caller_key)) {
            pattern = &__afl_call_stack[i];
            break;
        }
    }
    
    if (!pattern) {
        for (int i = 0; i < current_count; i++) {
            free(current_stack[i]);
        }
        free(stack_symbols);
        __afl_call_layer--;
        return;
    }
    
    // Reverse current stack to match predefined order (main first)
    for (int i = 0; i < current_count; i++) {
        current_reversed[i] = current_stack[current_count - 1 - i];
    }
    
    // Compute hash of current stack
    unsigned long current_hash = hash_stack(current_reversed, current_count);
    
    // Compare hashes - TERMINATE if they MATCH (malicious pattern detected)
    if (current_hash == pattern->expected_hash) {
        for (int i = 0; i < current_count; i++) {
            free(current_stack[i]);
        }
        free(stack_symbols);
        exit(0);
    }

    
    // Cleanup and decrement layer
    for (int i = 0; i < current_count; i++) {
        free(current_stack[i]);
    }
    free(stack_symbols);
    __afl_call_layer--;
}
