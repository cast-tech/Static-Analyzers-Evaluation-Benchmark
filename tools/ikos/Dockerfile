FROM static-analyzers-eval-base:22.04

RUN apt-get update -y && apt-get install -y \
    libboost-all-dev \
    libgmp-dev \
    libmpfr-dev \
    libclang-dev \
    clang \
    llvm \
    libz3-dev \
    libsqlite3-dev \
    libtbb-dev \
 && rm -rf /var/lib/apt/lists/*

# Get files from the project directory
COPY tools/ikos/ $SRC_DIR/tools/ikos/

RUN cd $SRC_DIR/tools/ikos && \
    echo "Extracting ikos-v3.5.tar.xz..." && \
    tar xf ikos-v3.5.tar.xz

WORKDIR $SRC_DIR
