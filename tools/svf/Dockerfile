FROM static-analyzers-eval-base:24.04

# Define LLVM version.
ENV llvm_version=18.1.0

# Define home directory
ENV HOME=/home/SVF-tools

# Get files from the project directory
COPY tools/svf/ $SRC_DIR/tools/svf/

RUN $SRC_DIR/tools/svf/build_svf.sh

# Export SVF, llvm, z3 paths
ENV PATH=${HOME}/SVF/Release-build/bin:$PATH
ENV PATH=${HOME}/SVF/llvm-$llvm_version.obj/bin:$PATH
ENV SVF_DIR=${HOME}/SVF
ENV LLVM_DIR=${HOME}/SVF/llvm-$llvm_version.obj
ENV Z3_DIR=${HOME}/SVF/z3.obj
RUN ln -s ${Z3_DIR}/bin/libz3.so ${Z3_DIR}/bin/libz3.so.4

# Install deps of the project
RUN pip install "wllvm>=1.3,<2.0" --break-system-packages
