FROM static-analyzers-eval-base:22.04

RUN apt-get update -y && apt-get install -y \
    ca-certificates \
    wget \
    python3-dev \
    && pip3 install codechecker==6.27.1 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-21.1.8/LLVM-21.1.8-Linux-X64.tar.xz \
    && tar -xvf LLVM-21.1.8-Linux-X64.tar.xz \
    && rm LLVM-21.1.8-Linux-X64.tar.xz

# Set LLVM Path so 'clang' is available globally
ENV PATH="/opt/LLVM-21.1.8-Linux-X64/bin:${PATH}"

RUN clang --version && CodeChecker version

# Get files from the project directory
COPY tools/codechecker/ $SRC_DIR/tools/codechecker/

WORKDIR $SRC_DIR