#pragma once
#include "permutation.hpp"
#include "utils.hpp"

// Utility functions for Ascon-Hash and Ascon-HashA implementation
namespace ascon_hash_utils {

// Precomputed initial hash state for `Ascon Hash`; taken from section 2.5.1 of
// Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint64_t ASCON_HASH_INIT_STATE[5]{ 0xee9398aadb67f03d,
                                             0x8bb21831c60f1002,
                                             0xb48a92db98d5da62,
                                             0x43189921b8f8e3e8,
                                             0x348fa5c9d525e140 };

// Precomputed initial hash state for `Ascon HashA`; taken from section 2.5.1 of
// Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint64_t ASCON_HASHA_INIT_STATE[5]{ 0x01470194fc6528a6,
                                              0x738ec38ac0adffa7,
                                              0x2ec8e3296c76384c,
                                              0xd6f6a54d7f52377d,
                                              0xa13c42a223be8d87 };

// Absorb N ( >= 1 ) -many message blocks ( each of length 64 -bit ) into hash
// state; see message block processing rules in section 2.5.2 of Ascon
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
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
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
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
