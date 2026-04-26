FROM static-analyzers-eval-base:22.04

RUN apt-get update -y && apt-get install -y \
    python3-distutils \
 && rm -rf /var/lib/apt/lists/*

# Get files from the project directory
COPY tools/smatch/ $SRC_DIR/tools/smatch/

# Install Smatch with its deps
RUN cd $SRC_DIR/tools/smatch && \
    echo "Installing Smatch with its dependencies..." && \
    chmod +x install_smatch.sh && ./install_smatch.sh

WORKDIR $SRC_DIR
