FROM ubuntu:16.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install basic dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    git \
    gdb \
    make \
    g++ \
    cmake \
    python \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    texinfo \
    xz-utils \
    bzip2 \
    wget \
    curl \
    bison \
    flex \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /root

# Clone SDFuzz repository
RUN git clone https://github.com/cuhk-seclab/sdfuzz.git

# Build gold linker
WORKDIR /root
RUN git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils && \
    mkdir -p build-binutils && \
    cd build-binutils && \
    ../binutils/configure --enable-gold --enable-plugins --disable-werror CXXFLAGS="-std=c++11" && \
    make all-gold -j$(nproc)

# Extract and build LLVM with Clang
WORKDIR /root/sdfuzz/temporal-specialization
RUN tar -Jxvf llvm-7.0.0.src.wclang.tar.xz && \
    cd llvm-7.0.0.src && \
    mkdir -p build && \
    cd build && \
    cmake -G "Unix Makefiles" \
        -DLLVM_BINUTILS_INCDIR=/root/binutils/include \
        -DLLVM_TARGETS_TO_BUILD="X86" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=../install \
        ../ && \
    make -j$(nproc) && \
    make install

# Set environment variables for SVF build
ENV LLVM_DIR=/root/sdfuzz/temporal-specialization/llvm-7.0.0.src/install/bin
ENV PATH=$LLVM_DIR:$PATH

# Build SVF
WORKDIR /root/sdfuzz/temporal-specialization/SVF
RUN ./build.sh

# Build SDFuzz main components
WORKDIR /root/sdfuzz
RUN make clean all

# Build instr component
WORKDIR /root/sdfuzz/instr
RUN make clean all

# Build llvm_mode component
WORKDIR /root/sdfuzz/llvm_mode
RUN make clean all

# Set final working directory
WORKDIR /root/sdfuzz

# Default command
CMD ["/bin/bash"]
