#!/bin/bash

ACVP_SERVER_REPO_PATH="ACVP-Server"
if [ -d "$ACVP_SERVER_REPO_PATH" ]; then
    echo "> $ACVP_SERVER_REPO_PATH repository exists, let's just fetch latest."

    pushd $ACVP_SERVER_REPO_PATH
    git checkout master
    git fetch
    git pull origin master
    popd
else
    echo "> $ACVP_SERVER_REPO_PATH repository doesn't exist, let's clone it."
    git clone https://github.com/usnistgov/ACVP-Server.git
fi

cat ./ACVP-Server/gen-val/json-files/Ascon-AEAD128-SP800-232/internalProjection.json | python parse_ascon_aead128_acvp_kat.py > ../ascon_aead128.acvp.kat
cat ./ACVP-Server/gen-val/json-files/Ascon-Hash256-SP800-232/internalProjection.json | python parse_ascon_hash256_acvp_kat.py > ../ascon_hash256.acvp.kat
cat ./ACVP-Server/gen-val/json-files/Ascon-XOF128-SP800-232/internalProjection.json | python parse_ascon_xof128_acvp_kat.py > ../ascon_xof128.acvp.kat
cat ./ACVP-Server/gen-val/json-files/Ascon-CXOF128-SP800-232/internalProjection.json | python parse_ascon_cxof128_acvp_kat.py > ../ascon_cxof128.acvp.kat

echo "> Generated all NIST ACVP KATs."
