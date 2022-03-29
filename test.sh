#!/bin/bash

# generate shared library
make lib

# bring in Ascon python implementation which can generate Known Answer Tests
git clone https://github.com/meichlseder/pyascon.git

# --- --- ---- --- --- #

# generate KAT for Ascon Hash
pushd pyascon

git checkout 236aadd9e09f40bc57064eba7cbade6f46a4c532
python3 genkat.py Ascon-Hash
mv LWC_HASH_KAT_256.txt ..

popd

mv LWC_HASH_KAT_256.txt wrapper/python

# test Ascon Hash implementation
pushd wrapper/python

pytest -k hash_kat --cache-clear -v -s

popd

# --- --- ---- --- --- #

# generate KAT for Ascon HashA
pushd pyascon

python3 genkat.py Ascon-Hasha
mv LWC_HASH_KAT_256.txt ..

popd

mv LWC_HASH_KAT_256.txt wrapper/python

# test Ascon HashA implementation
pushd wrapper/python

pytest -k hashA_kat --cache-clear -v -s
rm LWC_HASH_KAT_256.txt

popd

# --- --- ---- --- --- #

# generate KAT for Ascon-128
pushd pyascon

python3 genkat.py Ascon-128
mv LWC_AEAD_KAT_128_128.txt ..

popd

mv LWC_AEAD_KAT_128_128.txt wrapper/python

# test Ascon-128 implementation
pushd wrapper/python

pytest -k ascon_128_kat --cache-clear -v -s
rm LWC_AEAD_KAT_128_128.txt

popd

# --- --- ---- --- --- #

# generate KAT for Ascon-128a
pushd pyascon

python3 genkat.py Ascon-128a
mv LWC_AEAD_KAT_128_128.txt ..

popd

mv LWC_AEAD_KAT_128_128.txt wrapper/python

# test Ascon-128a implementation
pushd wrapper/python

pytest -k ascon_128a_kat --cache-clear -v -s
rm LWC_AEAD_KAT_128_128.txt

popd

# --- --- ---- --- --- #

# clean it up
rm -rf pyascon
make clean
