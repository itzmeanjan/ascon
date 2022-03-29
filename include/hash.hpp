#pragma once
#include "hash_utils.hpp"

// Ascon Light Weight Cryptography ( i.e. authenticated encryption, verified
// decryption and hashing ) Implementation
namespace ascon {

// Given N -many input message bytes this function computes 32 -bytes digest
// using `Ascon Hash` algorithm; see section 2.5 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static void
hash(const uint8_t* const __restrict msg,
     const size_t msg_len,            // in terms of bytes, can be >= 0
     uint8_t* const __restrict digest // len(digest) == 32
)
{
  using namespace ascon_hash_utils;

  uint64_t state[5] = { ASCON_HASH_INIT_STATE[0],
                        ASCON_HASH_INIT_STATE[1],
                        ASCON_HASH_INIT_STATE[2],
                        ASCON_HASH_INIT_STATE[3],
                        ASCON_HASH_INIT_STATE[4] };

  absorb<12>(state, msg, msg_len);
  squeeze<12, 12>(state, digest);
}

// Given N -many input message bytes this function computes 32 -bytes digest
// using `Ascon HashA` algorithm; see section 2.5 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static void
hash_a(const uint8_t* const __restrict msg,
       const size_t msg_len,            // in terms of bytes, can be >= 0
       uint8_t* const __restrict digest // len(digest) == 32
)
{
  using namespace ascon_hash_utils;

  uint64_t state[5] = { ASCON_HASHA_INIT_STATE[0],
                        ASCON_HASHA_INIT_STATE[1],
                        ASCON_HASHA_INIT_STATE[2],
                        ASCON_HASHA_INIT_STATE[3],
                        ASCON_HASHA_INIT_STATE[4] };

  absorb<8>(state, msg, msg_len);
  squeeze<12, 8>(state, digest);
}

}
