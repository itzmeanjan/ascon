#!/bin/bash

# Script for ease of execution of Known Answer Tests against Ascon AEAD, Hash and XOF implementation

# generate shared library object
make lib

# ---

mkdir -p tmp
pushd tmp

# download compressed NIST LWC submission of ASCON
wget -O ascon.zip https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/ascon.zip
# uncomress
unzip ascon.zip

# copy Known Answer Tests outside of uncompressed NIST LWC submission directory
cp ascon/Implementations/crypto_aead/ascon128v12/LWC_AEAD_KAT_128_128.txt ../LWC_AEAD_KAT_128_128.txt.ascon128
cp ascon/Implementations/crypto_aead/ascon128av12/LWC_AEAD_KAT_128_128.txt ../LWC_AEAD_KAT_128_128.txt.ascon128a
cp ascon/Implementations/crypto_aead/ascon80pqv12/LWC_AEAD_KAT_160_128.txt ../LWC_AEAD_KAT_160_128.txt.ascon80pq
cp ascon/Implementations/crypto_hash/asconhashv12/LWC_HASH_KAT_256.txt ../LWC_HASH_KAT_256.txt.asconhash
cp ascon/Implementations/crypto_hash/asconhashav12/LWC_HASH_KAT_256.txt ../LWC_HASH_KAT_256.txt.asconhasha
cp ascon/Implementations/crypto_hash/asconxofv12/LWC_HASH_KAT_256.txt ../LWC_HASH_KAT_256.txt.asconxof
cp ascon/Implementations/crypto_hash/asconxofav12/LWC_HASH_KAT_256.txt ../LWC_HASH_KAT_256.txt.asconxofa

popd

# ---

# remove NIST LWC submission zip
rm -rf tmp

# ---

pushd wrapper/python

# run tests
mv ../../LWC_AEAD_KAT_128_128.txt.ascon128 LWC_AEAD_KAT_128_128.txt
python3 -m pytest -k ascon_128_kat --cache-clear -v

mv ../../LWC_AEAD_KAT_128_128.txt.ascon128a LWC_AEAD_KAT_128_128.txt
python3 -m pytest -k ascon_128a_kat --cache-clear -v

mv ../../LWC_AEAD_KAT_160_128.txt.ascon80pq LWC_AEAD_KAT_160_128.txt
python3 -m pytest -k ascon_80pq_kat --cache-clear -v

mv ../../LWC_HASH_KAT_256.txt.asconhash LWC_HASH_KAT_256.txt
python3 -m pytest -k ascon_hash_kat --cache-clear -v

mv ../../LWC_HASH_KAT_256.txt.asconhasha LWC_HASH_KAT_256.txt
python3 -m pytest -k ascon_hasha_kat --cache-clear -v

mv ../../LWC_HASH_KAT_256.txt.asconxof LWC_HASH_KAT_256.txt
python3 -m pytest -k ascon_xof_kat --cache-clear -v

mv ../../LWC_HASH_KAT_256.txt.asconxofa LWC_HASH_KAT_256.txt
python3 -m pytest -k ascon_xofa_kat --cache-clear -v


# clean up
rm LWC_AEAD_KAT_*.txt
rm LWC_HASH_KAT_*.txt

popd

make clean

# ---
