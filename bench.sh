#!/bin/bash

# generate shared library
make lib

# run benchmark using python interface
pushd wrapper/python
python3 -m pytest -k bench --cache-clear -v
popd

# clean it up
make clean
