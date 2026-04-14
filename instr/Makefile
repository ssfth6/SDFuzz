# Compiler and flags
CXX = g++
CXXFLAGS = -fPIC -shared -std=c++11 -fno-rtti -O2 -Wall

# LLVM flags
LLVM_CONFIG = llvm-config
LLVM_CXXFLAGS = $(shell $(LLVM_CONFIG) --cxxflags)
LLVM_LDFLAGS = $(shell $(LLVM_CONFIG) --ldflags)

# Files
TARGET = fuzzopt.so
SOURCE = fuzzopt.cpp

# Default target
all: $(TARGET)

# Build shared library - MAKE SURE this line includes the source file
$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) $(LLVM_CXXFLAGS) $(LLVM_LDFLAGS) $(SOURCE) -o $(TARGET)
	cp $(TARGET) ../$(TARGET)

# Clean
clean:
	rm -f $(TARGET)

.PHONY: all clean
