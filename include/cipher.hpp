#pragma once
#include "permutation.hpp"
#include "types.hpp"
#include "utils.hpp"
#include <cstring>
#include <type_traits>

// Utility functions for implementing Ascon-{128, 128a, 80pq} authenticated
// encryption & verified decryption
namespace ascon_cipher {

// Ascon-128 initial state value ( only first 64 -bits ); taken from
// section 2.4.1 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint64_t ASCON_128_IV = 0X80400c0600000000ul;

// Ascon-128a initial state value ( only first 64 -bits ); taken from
// section 2.4.1 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint64_t ASCON_128a_IV = 0x80800c0800000000ul;

// Ascon-80pq initial state value ( only first 32 -bits );
// taken from section 2.4.1 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint32_t ASCON_80pq_IV = 0xa0400c06ul;

// = (1 << 64) - 1; maximum number that can be represented using 64 -bits
constexpr uint64_t MAX_ULONG = 0xfffffffffffffffful;

// Compile-time check that correct initial state is used for either Ascon-128 or
// Ascon-128a
consteval bool
check_iv(const uint64_t iv)
{
  return !static_cast<bool>(iv ^ ASCON_128_IV) |
         !static_cast<bool>(iv ^ ASCON_128a_IV);
}

// Initialize cipher state for Ascon authenticated encryption/ decryption;
// see section 2.4.1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
//
// # -of rounds `a` should be 12 for both Ascon-128 & Ascon-128a, though still
// it's parameterized
template<const uint64_t IV, const size_t a>
static inline void
initialize(uint64_t* const state,            // uninitialized hash state
           const ascon::secret_key_128_t& k, // 128 -bit secret key
           const ascon::nonce_t& n           // 128 -bit nonce
           )
  requires(check_iv(IV))
{
  state[0] = IV;
  state[1] = k.limbs[0];
  state[2] = k.limbs[1];
  state[3] = n.limbs[0];
  state[4] = n.limbs[1];

  ascon_perm::permute<a>(state);

  state[3] ^= k.limbs[0];
  state[4] ^= k.limbs[1];
}

// Initialize cipher state for Ascon-80pq authenticated cipher;
// see section 2.4.1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
//
// # -of rounds `a` should be 12 for Ascon-80pq, though still it's parameterized
template<const size_t a>
static inline void
initialize(uint64_t* const state,            // uninitialized hash state
           const ascon::secret_key_160_t& k, // 160 -bit secret key
           const ascon::nonce_t& n           // 128 -bit nonce
)
{
  state[0] = (static_cast<uint64_t>(ASCON_80pq_IV) << 32) | (k.limbs[0] >> 32);
  state[1] = ((k.limbs[0] & 0xfffffffful) << 32) | (k.limbs[1] >> 32);
  state[2] = ((k.limbs[1] & 0xfffffffful) << 32) | (k.limbs[2] & 0xfffffffful);
  state[3] = n.limbs[0];
  state[4] = n.limbs[1];

  ascon_perm::permute<a>(state);

  const uint64_t l_u32 = k.limbs[2] & 0xfffffffful;

  state[2] ^= (k.limbs[0] >> 32);
  state[3] ^= (((k.limbs[0] & 0xfffffffful) << 32) | (k.limbs[1] >> 32));
  state[4] ^= (((k.limbs[1] & 0xfffffffful) << 32) | l_u32);
}

// Compile-time check that rate bit length is 64
static inline constexpr bool
check_r64(const size_t r)
{
  return !static_cast<bool>(r ^ 64);
}

// Compile-time check that rate bit length is 128
static inline constexpr bool
check_r128(const size_t r)
{
  return !static_cast<bool>(r ^ 128);
}

// Compile-time check rate bit length for Ascon-128 & Ascon-128a; see table 1 of
// Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
consteval bool
check_r(const size_t r)
{
  return check_r64(r) || check_r128(r);
}

// Process `s` -many blocks of associated data, each of with rate ( = {64, 128}
// ) -bits; see section 2.4.2 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t b, const size_t rate>
static inline void
process_associated_data(uint64_t* const __restrict state,
                        const uint8_t* const __restrict data, // associated data
                        const size_t dlen // in terms of bytes, can be >= 0
                        )
  requires(check_r(rate))
{
  if (dlen > 0) {
    const size_t dbits = dlen << 3;
    const size_t rm_bits = dbits & (rate - 1ul);
    const size_t zero_pad_bits = rate - 1ul - rm_bits;
    const size_t pad_bytes = (1ul + zero_pad_bits) >> 3;

    const size_t till = dlen - (rm_bits >> 3);
    size_t off = 0;

    // first mix all bytes which can form full words ( rate bits wide )
    while (off < till) {
      if constexpr (check_r64(rate)) {
        // force compile-time branch evaluation
        static_assert(rate == 64, "Rate must be 64 -bits");

        const auto word = ascon_utils::from_be_bytes(data + off);
        state[0] ^= word;
        ascon_perm::permute<b>(state);

        off += 8ul;
      } else {
        // force compile-time branch evaluation
        static_assert(rate == 128, "Rate must be 128 -bits");

        const auto word0 = ascon_utils::from_be_bytes(data + off);
        const auto word1 = ascon_utils::from_be_bytes(data + off + 8ul);
        state[0] ^= word0;
        state[1] ^= word1;
        ascon_perm::permute<b>(state);

        off += 16ul;
      }
    }

    // finally do padding and then mixing of padded word ( rate bits wide )
    if constexpr (check_r64(rate)) {
      // force compile-time branch evaluation
      static_assert(rate == 64, "Rate must be 64 -bits");

      const auto word = ascon_utils::pad_data(data + off, pad_bytes);
      state[0] ^= word;
      ascon_perm::permute<b>(state);
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      uint64_t buf[2];
      ascon_utils::pad_data(data + off, pad_bytes, buf);
      state[0] ^= buf[0];
      state[1] ^= buf[1];
      ascon_perm::permute<b>(state);
    }
  }

  // final 1 -bit domain seperator constant mixing is mandatory
  state[4] ^= 0b1ul;
}

// Process plain text in blocks ( same as rate bits wide ) and produce cipher
// text is equal sized blocks; see section 2.4.3 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t b, const size_t rate>
static inline void
process_plaintext(uint64_t* const __restrict state,
                  const uint8_t* const __restrict text,
                  const size_t ctlen, // in terms of bytes, can be >= 0
                  uint8_t* const __restrict cipher // has length same as `text`
                  )
  requires(check_r(rate))
{
  const size_t tbits = ctlen << 3;
  const size_t rm_bits = tbits & (rate - 1ul);
  const size_t zero_pad_bits = rate - 1ul - rm_bits;
  const size_t pad_bytes = (1ul + zero_pad_bits) >> 3;

  const size_t till = ctlen - (rm_bits >> 3);
  size_t off = 0ul;

  // first encrypt all bytes which can be packed into rate bits wide full words
  while (off < till) {
    if constexpr (check_r64(rate)) {
      // force compile-time branch evaluation
      static_assert(rate == 64, "Rate must be 64 -bits");

      const auto word = ascon_utils::from_be_bytes(text + off);

      state[0] ^= word;
      ascon_utils::to_be_bytes(state[0], cipher + off);

      ascon_perm::permute<b>(state);

      off += 8ul;
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      const auto word0 = ascon_utils::from_be_bytes(text + off);
      const auto word1 = ascon_utils::from_be_bytes(text + off + 8ul);

      state[0] ^= word0;
      state[1] ^= word1;

      ascon_utils::to_be_bytes(state[0], cipher + off);
      ascon_utils::to_be_bytes(state[1], cipher + off + 8ul);

      ascon_perm::permute<b>(state);

      off += 16ul;
    }
  }

  // then encrypt remaining bytes which can't be packed into full words i.e.
  // padding will be required
  if constexpr (check_r64(rate)) {
    // force compile-time branch evaluation
    static_assert(rate == 64, "Rate must be 64 -bits");

    const auto word = ascon_utils::pad_data(text + off, pad_bytes);
    state[0] ^= word;

    const size_t rm_bytes = rm_bits >> 3;

    if constexpr (std::endian::native == std::endian::little) {
      const auto swapped = ascon_utils::bswap64(state[0]);
      std::memcpy(cipher + off, &swapped, rm_bytes);
    } else {
      std::memcpy(cipher + off, &state[0], rm_bytes);
    }
  } else {
    // force compile-time branch evaluation
    static_assert(rate == 128, "Rate must be 128 -bits");

    uint64_t buf[2];
    ascon_utils::pad_data(text + off, pad_bytes, buf);

    state[0] ^= buf[0];
    state[1] ^= buf[1];

    const size_t rm_bytes = rm_bits >> 3;
    const size_t fbytes = std::min(rm_bytes, 8ul);
    const size_t lbytes = std::min(rm_bytes - fbytes, 8ul);

    if constexpr (std::endian::native == std::endian::little) {
      const auto word0 = ascon_utils::bswap64(state[0]);
      const auto word1 = ascon_utils::bswap64(state[1]);

      std::memcpy(cipher + off, &word0, fbytes);
      std::memcpy(cipher + off + fbytes, &word1, lbytes);
    } else {
      std::memcpy(cipher + off, &state[0], fbytes);
      std::memcpy(cipher + off + fbytes, &state[1], lbytes);
    }
  }
}

// Process cipher text in blocks ( same as rate bits wide ) and keep producing
// plain text blocks is equal sized blocks; see section 2.4.3 of Ascon
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t b, const size_t r>
static inline void
process_ciphertext(uint64_t* const __restrict state,
                   const uint8_t* const __restrict cipher,
                   const size_t cipher_len,       // in terms of bytes
                   uint8_t* const __restrict text // has length same as `cipher`
                   )
  requires(check_r(r))
{
  const size_t cipher_bit_len = cipher_len << 3;
  const size_t cipher_blocks = cipher_bit_len / r;
  const size_t remaining_bit_len = cipher_bit_len % r;

  for (size_t i = 0; i < cipher_blocks; i++) {
    if constexpr (check_r64(r)) {
      const size_t offset = i << 3;

      const uint64_t cipher_blk = ascon_utils::from_be_bytes(cipher + offset);
      const uint64_t text_blk = cipher_blk ^ state[0]; // de-ciphered

      ascon_utils::to_be_bytes(text_blk, text + offset);

      state[0] = cipher_blk;
      ascon_perm::permute<b>(state);
    } else if constexpr (check_r128(r)) {
      const size_t off0 = (i << 1) << 3;
      const size_t off1 = ((i << 1) + 1) << 3;

      const uint64_t cipher_blk_0 = ascon_utils::from_be_bytes(cipher + off0);
      const uint64_t cipher_blk_1 = ascon_utils::from_be_bytes(cipher + off1);

      const uint64_t text_blk_0 = cipher_blk_0 ^ state[0]; // de-ciphered
      const uint64_t text_blk_1 = cipher_blk_1 ^ state[1]; // de-ciphered

      ascon_utils::to_be_bytes(text_blk_0, text + off0);
      ascon_utils::to_be_bytes(text_blk_1, text + off1);

      state[0] = cipher_blk_0;
      state[1] = cipher_blk_1;
      ascon_perm::permute<b>(state);
    }
  }

  if (remaining_bit_len > 0) {
    const size_t rem_byte_len = remaining_bit_len >> 3;          // bytes
    const uint8_t* cipher_ = cipher + cipher_len - rem_byte_len; // slice out
    uint8_t* text_ = text + cipher_len - rem_byte_len;           // slice out

    if constexpr (check_r64(r)) {
      uint64_t rem_cipher = 0ul;
      for (size_t i = 0; i < rem_byte_len; i++) {
        rem_cipher |= static_cast<uint64_t>(cipher_[i]) << ((7ul - i) << 3);
      }

      const uint64_t rem_text = state[0] ^ rem_cipher;

      for (size_t i = 0; i < rem_byte_len; i++) {
        text_[i] = static_cast<uint8_t>(rem_text >> ((7ul - i) << 3));
      }

      const uint64_t shifted = MAX_ULONG << ((8ul - rem_byte_len) << 3);
      const uint64_t selected = rem_text & shifted;

      state[0] ^= selected | (0b1ul << (((8ul - rem_byte_len) << 3) - 1ul));
    } else if constexpr (check_r128(r)) {
      uint64_t rem_cipher_0 = 0ul;
      uint64_t rem_cipher_1 = 0ul;
      for (size_t i = 0; i < rem_byte_len; i++) {
        if (i < 8) {
          rem_cipher_0 |= static_cast<uint64_t>(cipher_[i]) << ((7 - i) << 3);
        } else {
          rem_cipher_1 |= static_cast<uint64_t>(cipher_[i]) << ((15 - i) << 3);
        }
      }

      const uint64_t rem_text_0 = state[0] ^ rem_cipher_0;
      const uint64_t rem_text_1 = state[1] ^ rem_cipher_1;

      for (size_t i = 0; i < rem_byte_len; i++) {
        if (i < 8) {
          text_[i] = static_cast<uint8_t>((rem_text_0 >> ((7 - i) << 3)));
        } else {
          text_[i] = static_cast<uint8_t>((rem_text_1 >> ((15 - i) << 3)));
        }
      }

      if (rem_byte_len < 8) {
        const uint64_t shifted = MAX_ULONG << ((8ul - rem_byte_len) << 3);
        const uint64_t selected = rem_text_0 & shifted;

        state[0] ^= (selected | (0b1ul << (((8 - rem_byte_len) << 3) - 1)));
      } else if (rem_byte_len == 8) {
        state[0] ^= rem_text_0;
        state[1] ^= (0b1ul << 63);
      } else {
        const uint64_t shifted = MAX_ULONG << ((16ul - rem_byte_len) << 3);
        const uint64_t selected = rem_text_1 & shifted;

        state[0] ^= rem_text_0;
        state[1] ^= (selected | (0b1ul << (((16 - rem_byte_len) << 3) - 1)));
      }
    }

  } else {
    state[0] ^= 0b1ul << 63;
  }
}

// Ascon-128/128a finalization step, generates 128 -bit tag; taken from
// section 2.4.4 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t a, const size_t r>
static inline const ascon::tag_t
finalize(uint64_t* const state,
         const ascon::secret_key_128_t& k // 128 -bit secret key
         )
  requires(check_r(r))
{
  if constexpr (check_r64(r)) {
    state[1] ^= k.limbs[0];
    state[2] ^= k.limbs[1];
  } else if constexpr (check_r128(r)) {
    state[2] ^= k.limbs[0];
    state[3] ^= k.limbs[1];
  }

  ascon_perm::permute<a>(state);

  // 128 -bit tag
  ascon::tag_t t(state[3] ^ k.limbs[0], state[4] ^ k.limbs[1]);
  return t;
}

// Ascon-80pq finalization step, generates 128 -bit tag; taken from
// section 2.4.4 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t a, const size_t r>
static inline const ascon::tag_t
finalize(uint64_t* const state,
         const ascon::secret_key_160_t& k // 160 -bit secret key
         )
  requires(check_r(r))
{
  if constexpr (check_r64(r)) {
    state[1] ^= k.limbs[0];
    state[2] ^= k.limbs[1];
    state[3] ^= ((k.limbs[2] & 0xfffffffful) << 32);
  } else if constexpr (check_r128(r)) {
    state[2] ^= k.limbs[0];
    state[3] ^= k.limbs[1];
    state[4] ^= ((k.limbs[2] & 0xfffffffful) << 32);
  }

  ascon_perm::permute<a>(state);

  // keeps 32 to 63 -bits of 160 -bit secret key, on upper 32 -bits of
  // 64 -bit unsigned integer
  const uint64_t tmp0 = (k.limbs[0] & 0xfffffffful) << 32;
  // keeps 64 to 95 -bits of 160 -bit secret key, on lower 32 -bits of
  // 64 -bit unsigned integer
  const uint64_t tmp1 = k.limbs[1] >> 32;

  // keeps 96 to 127 -bits of 160 -bit secret key, on upper 32 -bits of
  // 64 -bit unsigned integer
  const uint64_t tmp2 = (k.limbs[1] & 0xffffffff) << 32;
  // secret key's last 32 -bits ( i.e. from bit 128 to 159 ) are placed on lower
  // 32 -bits of 64 -bit unsigned integer
  const uint64_t tmp3 = k.limbs[2] & 0xfffffffful;

  // last 128 -bits of secret key, as two 64 -bit words
  const uint64_t k_64_a = tmp0 | tmp1;
  const uint64_t k_64_b = tmp2 | tmp3;

  // 128 -bit tag
  const ascon::tag_t t(state[3] ^ k_64_a, state[4] ^ k_64_b);
  return t;
}

}
