#pragma once
#include "permutation.hpp"
#include "utils.hpp"
#include <cstdint>

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
initialize(
  uint64_t* const __restrict state,   // 40 -bytes Ascon permutation state
  const uint8_t* const __restrict key // 16 -bytes key
  )
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

// Absorbs arbitrary many message bytes into RATE portion of Ascon permutation
// state s.t. `offset` many bytes can already be absorbed into it. `offset` can
// have value from [0, rbytes). This routine is an implementation following
// section 2.4.2 of spec. https://eprint.iacr.org/2021/1574.pdf.
//
// One can invoke absorb routine arbitrary many times for absorbing arbitrary
// many message bytes, until the state is finalized.
template<const size_t rounds_a, // a -rounds permutation p^a | a <= 12
         const size_t rate      // in bits
         >
static inline void
absorb(uint64_t* const __restrict state,    // 40 -bytes Ascon permutation state
       size_t* const __restrict offset,     // ∈ [0, rbytes)
       const uint8_t* const __restrict msg, // Message to be absorbed
       const size_t mlen                    // Byte length of message, >= 0
       )
  requires((rounds_a == ascon_permutation::MAX_ROUNDS) && (rate == 256))
{
  constexpr size_t rbytes = rate / 8;
  const size_t blk_cnt = (*offset + mlen) / rbytes;

  uint8_t chunk[rbytes];
  size_t moff = 0;

  for (size_t i = 0; i < blk_cnt; i++) {
    std::memset(chunk, 0, *offset);
    std::memcpy(chunk + *offset, msg + moff, rbytes - *offset);

    const auto word0 = ascon_utils::from_be_bytes<uint64_t>(chunk);
    const auto word1 = ascon_utils::from_be_bytes<uint64_t>(chunk + 8);
    const auto word2 = ascon_utils::from_be_bytes<uint64_t>(chunk + 16);
    const auto word3 = ascon_utils::from_be_bytes<uint64_t>(chunk + 24);

    state[0] ^= word0;
    state[1] ^= word1;
    state[2] ^= word2;
    state[3] ^= word3;

    moff += (rbytes - *offset);

    ascon_permutation::permute<rounds_a>(state);
    *offset = 0;
  }

  const size_t rm_bytes = mlen - moff;

  std::memset(chunk, 0, rbytes);
  std::memcpy(chunk + *offset, msg + moff, rm_bytes);

  const auto word0 = ascon_utils::from_be_bytes<uint64_t>(chunk);
  const auto word1 = ascon_utils::from_be_bytes<uint64_t>(chunk + 8);
  const auto word2 = ascon_utils::from_be_bytes<uint64_t>(chunk + 16);
  const auto word3 = ascon_utils::from_be_bytes<uint64_t>(chunk + 24);

  state[0] ^= word0;
  state[1] ^= word1;
  state[2] ^= word2;
  state[3] ^= word3;

  *offset += rm_bytes;
}

// Given that arbitrary many message bytes are already absorbed into RATE
// portion of Ascon permutation state, this function can be used for finalizing
// it so that it becomes ready for squeezing. This is an implementation,
// following section 2.4.2 and (last message block absorption step of) algorithm
// 1 of spec. https://eprint.iacr.org/2021/1574.pdf.
template<const size_t rounds_a, // a -rounds permutation p^a | a <= 12
         const size_t rate      // in bits
         >
static inline void
finalize(uint64_t* const __restrict state, // 40 -bytes Ascon permutation state
         size_t* const __restrict offset   // ∈ [0, rbytes)
         )
  requires((rounds_a == ascon_permutation::MAX_ROUNDS) && (rate == 256))
{
  constexpr size_t rbytes = rate / 8;
  uint8_t chunk[rbytes];

  std::memset(chunk, 0x00, rbytes);
  std::memset(chunk + *offset, 0x80, 1);

  state[0] ^= ascon_utils::from_be_bytes<uint64_t>(chunk);
  state[1] ^= ascon_utils::from_be_bytes<uint64_t>(chunk + 8);
  state[2] ^= ascon_utils::from_be_bytes<uint64_t>(chunk + 16);
  state[3] ^= ascon_utils::from_be_bytes<uint64_t>(chunk + 24);
  state[4] ^= 1;

  ascon_permutation::permute<rounds_a>(state);

  *offset = 0;
}

}
