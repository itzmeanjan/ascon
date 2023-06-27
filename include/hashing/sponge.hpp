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

// Given arbitrary many message bytes are already absorbed into RATE portion of
// Ascon permutation state, this routine finalizes sponge state and makes it
// ready for squeezing.
//
// - `rate` portion of sponge will have bitwidth = 64.
// - `offset` must ∈ [0, `rbytes`).
//
// Once Ascon permutation state is finalized, it can't absorb any more message
// bytes, though you can squeeze output bytes from it.
template<const size_t rounds_a, const size_t rate>
static inline void
finalize(uint64_t* const __restrict state, size_t* const __restrict offset)
{
  constexpr size_t rbytes = rate / 8;

  const size_t pad_bytes = rbytes - *offset;
  const size_t pad_bits = pad_bytes * 8;
  const uint64_t pad_mask = 1ul << (pad_bits - 1);

  state[0] ^= pad_mask;
  ascon_permutation::permute<rounds_a>(state);

  *offset = 0;
}

// Given that sponge state is already finalized, this routine can be invoked for
// squeezing `olen` -bytes out of rate portion of the Ascon permutation state.
//
// - `rate` portion of sponge will have bitwidth = 64.
// - `readable` denotes how many bytes can be squeezed without permutating the
// sponge state.
// - When `readable` becomes 0, sponge state needs to be permutated again, after
// which `rbytes` can again be squeezed from rate portion of the state.
template<const size_t rounds_b, const size_t rate>
static inline void
squeeze(uint64_t* const __restrict state,
        size_t* const __restrict readable,
        uint8_t* const __restrict out,
        const size_t olen)
{
  constexpr size_t rbytes = rate / 8;

  size_t ooff = 0;
  while (ooff < olen) {
    const size_t elen = std::min(*readable, olen - ooff);
    const size_t soff = rbytes - *readable;

    uint64_t word = state[0];

    if constexpr (std::endian::native == std::endian::little) {
      word = ascon_utils::bswap(word);
    }

    std::memcpy(out + ooff, reinterpret_cast<uint8_t*>(&word) + soff, elen);

    *readable -= elen;
    ooff += elen;

    if (*readable == 0) {
      ascon_permutation::permute<rounds_b>(state);
      *readable = rbytes;
    }
  }
}

}
