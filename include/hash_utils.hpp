#pragma once
#include "permutation.hpp"
#include "utils.hpp"

// Utility functions for Ascon-Hash and Ascon-HashA implementation
namespace hash_utils {

// Absorb N (>=0) -many message bytes into hash state; following absorption rule
// described in section 2.5.2 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
//
// For possible values of template parameter `b`, follow table 2 in
// specification
template<const size_t b>
static inline void
absorb(uint64_t* const __restrict state,
       const uint8_t* const __restrict msg,
       const size_t mlen // in terms of bytes, can be >= 0
)
{
  const size_t mbits = mlen << 3;
  const size_t rm_bits = mbits & 63ul;
  const size_t zero_pad_bits = 63ul - rm_bits;
  constexpr size_t one_pad_bit = 1ul;
  const size_t pad_bytes = (one_pad_bit + zero_pad_bits) >> 3;

  const size_t till = mlen - (rm_bits >> 3);
  size_t off = 0ul;

  while (off < till) {
    const auto word = ascon_utils::from_be_bytes<uint64_t>(msg + off);
    state[0] ^= word;
    ascon_perm::permute<b>(state);

    off += 8ul;
  }

  const auto word = ascon_utils::pad64(msg + off, pad_bytes);
  state[0] ^= word;
}

// Extract out four 64 -bit blocks from hash state, producing total 256 -bit
// Ascon digest; see section 2.5.3 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
//
// For possible values of template parameter `a`, `b`, follow table 2 in Ascon
// specification
template<const size_t a, const size_t b>
static inline void
squeeze(uint64_t* const __restrict state, uint8_t* const __restrict digest)
{
  ascon_perm::permute<a>(state);

#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC unroll 4
#endif
  for (size_t i = 0; i < 4; i++) {
    ascon_utils::to_be_bytes(state[0], digest + i * 8);
    ascon_perm::permute<b>(state);
  }
}

}
