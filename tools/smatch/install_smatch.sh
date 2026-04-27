#!/bin/bash

SMATCH_DIR=$(dirname "$(realpath "$0")")

cd "$SMATCH_DIR" || exit

apt update -y && apt upgrade -y
apt-get install -y libxml2-dev libsqlite3-dev libgtk-3-dev
apt install -y xz-utils make build-essential libssl-dev

tar -xzf smatch_v0.5.0-8814-g34981e51_x86-64-ubuntu-22.04_llvm-12.0.1.tar.gz
