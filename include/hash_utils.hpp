#pragma once
#include "permutation.hpp"
#include "utils.hpp"

// Utility functions for Ascon-Hash and Ascon-HashA implementation
namespace ascon_hash_utils {

// Precomputed initial hash state for `Ascon Hash`; taken from section 2.5.1 of
// Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint64_t ASCON_HASH_INIT_STATE[5] = { 0xee9398aadb67f03d,
                                                0x8bb21831c60f1002,
                                                0xb48a92db98d5da62,
                                                0x43189921b8f8e3e8,
                                                0x348fa5c9d525e140 };

// Precomputed initial hash state for `Ascon HashA`; taken from section 2.5.1 of
// Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint64_t ASCON_HASHA_INIT_STATE[5] = { 0x01470194fc6528a6,
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
static void
absorb(uint64_t* const __restrict state,
       const uint8_t* const __restrict msg,
       const size_t msg_len // in terms of bytes, can be >= 0
       ) requires(ascon_perm::check_b(b))
{
  // these many 0 -bits to be appended to input message
  const size_t tmp = (msg_len << 3) % 64;              // bits
  const size_t zero_pad_len = 64 - 1 - tmp;            // bits
  const size_t pad_byte_len = (zero_pad_len + 1) >> 3; // bytes

  const uint8_t* msg_ = msg + msg_len - (8 - pad_byte_len); // slice out
  const uint64_t last_msg_blk = ascon_utils::pad_data(msg_, pad_byte_len);

  const size_t msg_blk_cnt = ((msg_len + pad_byte_len) << 3) >> 6;

  for (size_t i = 0; i < msg_blk_cnt - 1; i++) {
    const uint64_t msg_blk = ascon_utils::from_be_bytes(msg + (i << 3));

    state[0] ^= msg_blk;
    ascon_perm::p_b<b>(state);
  }

  state[0] ^= last_msg_blk;
}

// Extract out four 64 -bit blocks from hash state, producing total 256 -bit
// Ascon digest; see section 2.5.3 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
//
// For possible values of template parameter `a`, `b`, follow table 2 in Ascon
// specification
template<const size_t a, const size_t b>
static void
squeeze(uint64_t* const __restrict state,
        uint8_t* const __restrict digest) requires(ascon_perm::check_a(a) &&
                                                   ascon_perm::check_b(b))
{
  ascon_perm::p_a<a>(state);

  for (size_t i = 0; i < 4; i++) {
    const uint64_t block = state[0];
    ascon_utils::to_be_bytes(block, digest + (i << 3));

    ascon_perm::p_b<b>(state);
  }
}

}
