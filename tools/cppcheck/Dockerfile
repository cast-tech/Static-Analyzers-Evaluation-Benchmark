FROM static-analyzers-eval-base:22.04

RUN apt-get update -y && apt-get install -y \
    bear \
    ca-certificates \
    wget \
    clang \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN wget https://github.com/danmar/cppcheck/archive/refs/tags/2.19.0.tar.gz && \
    tar -xvzf 2.19.0.tar.gz

# Build Cppcheck
WORKDIR /opt/cppcheck-2.19.0
RUN mkdir build && cd build && cmake .. && make && make install

# Get files from the project directory
COPY tools/cppcheck/ $SRC_DIR/tools/cppcheck/

WORKDIR $SRC_DIR
