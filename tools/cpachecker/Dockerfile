FROM static-analyzers-eval-base:22.04

RUN apt-get update -y && apt-get install -y \
    python3-distutils \
 && rm -rf /var/lib/apt/lists/*

# Get files from the project directory
COPY tools/cpachecker/ $SRC_DIR/tools/cpachecker/

# Install CPAchecker with its deps
RUN cd $SRC_DIR/tools/cpachecker && \
    echo "Installing CPAchecker with its dependencies..." && \
    chmod +x install_cpachecker.sh && ./install_cpachecker.sh && \
    echo "Installing frama-c for preprocessing..." && \
    chmod +x install_framac.sh && ./install_framac.sh

WORKDIR $SRC_DIR
