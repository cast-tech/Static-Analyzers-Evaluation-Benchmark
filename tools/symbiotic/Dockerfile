FROM static-analyzers-eval-base:22.04

RUN apt-get update -y && apt-get install -y \
    llvm \
    zlib1g-dev clang g++ \
    curl wget rsync make \
    unzip gcc-multilib xz-utils libz3-dev libsqlite3-dev \
    libboost-all-dev \
 && rm -rf /var/lib/apt/lists/*

RUN pip3 install "z3-solver>=4.13,<5" "pyinstaller>=6.0,<7" "numpy>=1.26,<2"

# Get files from the project directory
COPY tools/symbiotic/ $SRC_DIR/tools/symbiotic/

RUN cd $SRC_DIR/tools/symbiotic && \
    echo "Extracting symbiotic-v10.tar.xz..." && tar xf symbiotic-v10.tar.xz