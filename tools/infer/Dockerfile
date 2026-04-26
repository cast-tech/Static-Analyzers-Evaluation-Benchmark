FROM static-analyzers-eval-base:22.04

RUN apt-get update -y && apt-get install -y \
    clang \
 && rm -rf /var/lib/apt/lists/*

# Get files from the project directory
COPY tools/infer/ $SRC_DIR/tools/infer/

RUN cd $SRC_DIR/tools/infer && \
    echo "Extracting infer-linux-x86_64-v1.2.0.tar.xz..." && \
    tar xf infer-linux-x86_64-v1.2.0.tar.xz --strip-components=1

WORKDIR $SRC_DIR