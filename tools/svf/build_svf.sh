#!/bin/bash

set -e

apt-get install -y wget xz-utils git tcl software-properties-common \
    cmake g++ gcc zlib1g-dev libncurses-dev libtinfo6 \
    build-essential libssl-dev libpcre2-dev zip libzstd-dev

LIB_DIR="/usr/lib/x86_64-linux-gnu"
[ -f "$LIB_DIR/libffi.so.6" ] || ln -s "$(find $LIB_DIR -name 'libffi.so.?.?*' | head -n 1)" "$LIB_DIR/libffi.so.6"
[ -f "$LIB_DIR/libtinfo.so" ] || ln -s "$(find $LIB_DIR -name 'libtinfo.so.?.?*' | head -n 1)" "$LIB_DIR/libtinfo.so"
[ -f "$LIB_DIR/libedit.so" ] || ln -s "$(find $LIB_DIR -name 'libedit.so.?.?*' | head -n 1)" "$LIB_DIR/libedit.so"

echo "Downloading LLVM and building SVF to /home/SVF-tools"
mkdir "/home/SVF-tools"
cd "/home/SVF-tools"
git clone --branch SVF-3.2 --depth=1 https://github.com/SVF-tools/SVF.git
cd SVF
echo "Building SVF ..."
bash ./build.sh
