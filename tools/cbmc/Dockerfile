FROM static-analyzers-eval-base:22.04

RUN apt-get update -y && apt-get install -y \
    llvm \
    bash-completion \
 && rm -rf /var/lib/apt/lists/*

COPY tools/cbmc/ $SRC_DIR/tools/cbmc/
COPY tools/build.py $SRC_DIR/tools/

RUN dpkg -i $SRC_DIR/tools/cbmc/ubuntu-22.04-cbmc-6.5.0-Linux.deb

WORKDIR $SRC_DIR
