#pragma once
#include "permutation.hpp"
#include "utils.hpp"

// Common functions used for implementing Ascon based authentication schemes
// such as PRF and MAC.
namespace ascon_auth {

// 320 -bit Ascon permutation state is initialized by applying a 12 -rounds
// Ascon permutation on compile-time computed 64 -bit initialization value and
// 128 -bit ( i.e. 16 -bytes ) secret key, following section 2.4.1 of spec.
// https://eprint.iacr.org/2021/1574.pdf. Initialized permutation state can be
// used for Ascon based authentication scheme.
template<const size_t rounds_a,     // a -rounds permutation p^a | a <= 12
         const size_t in_rate,      // in bits
         const size_t out_rate,     // in bits
         const size_t klen,         // key length, in bits
         const uint32_t max_out_len // max. output length, in bits
         >
static inline void
initialize(uint64_t* const __restrict state,
           const uint8_t* const __restrict key)
  requires((klen == 128) && (rounds_a == ascon_permutation::MAX_ROUNDS))
{
  // Compile-time compute initialization value
  constexpr uint64_t iv =
    (klen << 56) |                    // 8 -bit wide bit length of secret key
    (out_rate << 48) |                // 8 -bit wide bit length of output rate
    (((1ul << 7) ^ rounds_a) << 40) | // 8 -bit wide, 2^7 ⊕ a
    (0b00000000ul << 32) |            // 8 zero bits
    max_out_len                       // 32 -bit wide max. output bit length
    ;

  state[0] = iv;
  state[1] = ascon_utils::from_be_bytes<uint64_t>(key);
  state[2] = ascon_utils::from_be_bytes<uint64_t>(key + 8);
  state[3] = 0;
  state[4] = 0;

  ascon_permutation::permute<rounds_a>(state);
}

}
