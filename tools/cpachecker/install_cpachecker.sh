#!/bin/bash

SMATCH_DIR=$(dirname "$(realpath "$0")")

cd "$SMATCH_DIR" || exit

apt update -y && apt upgrade -y
apt-get install -y openjdk-17-jre
apt install -y xz-utils make build-essential gcc libc6-dev cpp

tar -xzf CPAchecker_4.0-603-g9c8152baa7_ubuntu-22.04_openjdk-17-jre.tar.gz