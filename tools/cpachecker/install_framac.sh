#!/bin/bash
# frama-c is needed for test case preprocessing

apt-get update -y && apt-get install -y opam && apt-get install -y graphviz libcairo2-dev libgmp-dev libgtk-3-dev libgtksourceview-3.0-dev pkg-config

OPAMROOT=/opt/opam
opam init --root=$OPAMROOT --disable-sandboxing --yes --no-setup  --confirm-level=unsafe-yes
opam install --root=$OPAMROOT  --confirm-level=unsafe-yes  -y frama-c.32.0
chmod -R a+rX /opt/opam
