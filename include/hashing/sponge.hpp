#pragma once
#include "permutation.hpp"
#include "utils.hpp"

// Common functions required for implementing sponge-based hash functions.
namespace sponge {

// Given `mlen` (>=0) -bytes message, this routine consumes it into RATE portion
// of Ascon permutation state, s.t. `offset` ( second parameter ) denotes how
// many bytes are already consumed into RATE portion of the state.
//
// - `rate` portion of sponge will have bitwidth = 64.
// - `offset` must ∈ [0, `rbytes`).
//
// One may invoke this function arbitrary many times, for absorbing arbitrary
// many message bytes, until permutation state is finalized.
template<const size_t rounds_b, const size_t rate>
static inline void
absorb(uint64_t* const __restrict state,
       size_t* const __restrict offset,
       const uint8_t* const __restrict msg,
       const size_t mlen)
{
  constexpr size_t rbytes = rate / 8;

  uint8_t blk_bytes[rbytes];

  const size_t blk_cnt = (*offset + mlen) / rbytes;
  size_t moff = 0;

  for (size_t i = 0; i < blk_cnt; i++) {
    std::memset(blk_bytes, 0, *offset);
    std::memcpy(blk_bytes + *offset, msg + moff, rbytes - *offset);

    const auto word = ascon_utils::from_be_bytes<uint64_t>(blk_bytes);
    state[0] ^= word;

    moff += (rbytes - *offset);

    ascon_permutation::permute<rounds_b>(state);
    *offset = 0;
  }

  const size_t rm_bytes = mlen - moff;

  std::memset(blk_bytes, 0, rbytes);
  std::memcpy(blk_bytes + *offset, msg + moff, rm_bytes);

  const auto word = ascon_utils::from_be_bytes<uint64_t>(blk_bytes);
  state[0] ^= word;

  *offset += rm_bytes;
}

}
