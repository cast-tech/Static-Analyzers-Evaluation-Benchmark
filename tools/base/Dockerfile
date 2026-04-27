ARG UBUNTU_VERSION=22.04
FROM ubuntu:${UBUNTU_VERSION}

ARG DEBIAN_FRONTEND=noninteractive
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
ENV SRC_DIR=/memory-tracer-tests

RUN apt-get update -y && apt-get install -y \
    build-essential \
    autoconf \
    tzdata \
    cmake \
    git \
    vim \
    file \
    python3 \
    python3-pip \
    python3-venv \
 && rm -rf /var/lib/apt/lists/*

COPY test_suites/                $SRC_DIR/test_suites/
COPY tools/tool_runner_docker.py $SRC_DIR/tools/
COPY tools/run_tool.py           $SRC_DIR/tools/
COPY tools/base.py               $SRC_DIR/tools/
COPY tools/support.py            $SRC_DIR/tools/
COPY tools/extractors.py         $SRC_DIR/tools/
COPY tools/rate.py               $SRC_DIR/tools/
COPY tools/build.py              $SRC_DIR/tools/
COPY tools/classifier.py         $SRC_DIR/tools/

WORKDIR $SRC_DIR
