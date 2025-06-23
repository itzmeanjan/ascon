#!/bin/bash

git clone https://github.com/usnistgov/ACVP-Server.git

cat ./ACVP-Server/gen-val/json-files/Ascon-AEAD128-SP800-232/internalProjection.json | python parse_ascon_aead128_acvp_kat.py > ../ascon_aead128.acvp.kat
cat ./ACVP-Server/gen-val/json-files/Ascon-Hash256-SP800-232/internalProjection.json | python parse_ascon_hash256_acvp_kat.py > ../ascon_hash256.acvp.kat
cat ./ACVP-Server/gen-val/json-files/Ascon-XOF128-SP800-232/internalProjection.json | python parse_ascon_xof128_acvp_kat.py > ../ascon_xof128.acvp.kat
cat ./ACVP-Server/gen-val/json-files/Ascon-CXOF128-SP800-232/internalProjection.json | python parse_ascon_cxof128_acvp_kat.py > ../ascon_cxof128.acvp.kat
