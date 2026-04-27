FROM static-analyzers-eval-base:22.04

RUN apt-get update -y && apt-get install -y \
    python3-distutils libtinfo5 \
 && rm -rf /var/lib/apt/lists/*

# Get files from the project directory
COPY tools/klee/ $SRC_DIR/tools/klee/

# Extract KLEE, install its required packages, and install wllvm
RUN cd $SRC_DIR/tools/klee && mkdir -p /klee/klee-3.1 && \
    echo "Extracting klee-bin-Ubuntu-20.04.6-LTS.tar.gz..." && \
    tar xf klee-bin-Ubuntu-20.04.6-LTS.tar.gz -C /klee/klee-3.1 --strip-components=1 && \
    echo "Running install_required_packages.sh..." && \
    cd /klee/klee-3.1/ && ./install_required_packages.sh && pip install "wllvm>=1.3,<2.0"

WORKDIR $SRC_DIR
