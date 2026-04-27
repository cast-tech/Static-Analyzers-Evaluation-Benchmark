FROM static-analyzers-eval-base:22.04

RUN apt-get update -y && apt-get install -y \
    opam

ENV OPAMROOT=/opt/opam
RUN opam init --root=$OPAMROOT --disable-sandboxing --yes --no-setup  --confirm-level=unsafe-yes && \
    opam install --root=$OPAMROOT  --confirm-level=unsafe-yes  -y frama-c.32.0 && \
    chmod -R a+rX /opt/opam

ENV PATH=/opt/opam/default/bin:$PATH
# Get files from the project directory
COPY tools/frama_c/ $SRC_DIR/tools/frama_c/

WORKDIR $SRC_DIR
