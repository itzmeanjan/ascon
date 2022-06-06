#pragma once
#include "permutation.hpp"
#include "types.hpp"
#include "utils.hpp"

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
static inline consteval bool
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
           ) requires(ascon_perm::check_a(a) && check_iv(IV))
{
  state[0] = IV;
  state[1] = k.limbs[0];
  state[2] = k.limbs[1];
  state[3] = n.limbs[0];
  state[4] = n.limbs[1];

  ascon_perm::p_a<a>(state);

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
           ) requires(ascon_perm::check_a(a))
{
  state[0] = (static_cast<uint64_t>(ASCON_80pq_IV) << 32) | (k.limbs[0] >> 32);
  state[1] = ((k.limbs[0] & 0xfffffffful) << 32) | (k.limbs[1] >> 32);
  state[2] = ((k.limbs[1] & 0xfffffffful) << 32) | (k.limbs[2] & 0xfffffffful);
  state[3] = n.limbs[0];
  state[4] = n.limbs[1];

  ascon_perm::p_a<a>(state);

  const uint64_t l_u32 = k.limbs[2] & 0xfffffffful;

  state[2] ^= (k.limbs[0] >> 32);
  state[3] ^= (((k.limbs[0] & 0xfffffffful) << 32) | (k.limbs[1] >> 32));
  state[4] ^= (((k.limbs[1] & 0xfffffffful) << 32) | l_u32);
}

// Compile-time check that rate bit length is 64
static inline consteval bool
check_r64(const size_t r)
{
  return !static_cast<bool>(r ^ 64);
}

// Compile-time check that rate bit length is 128
static inline consteval bool
check_r128(const size_t r)
{
  return !static_cast<bool>(r ^ 128);
}

// Compile-time check rate bit length for Ascon-128 & Ascon-128a; see table 1 of
// Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline consteval bool
check_r(const size_t r)
{
  return check_r64(r) | check_r128(r);
}

// Process `s` -many blocks of associated data, each of with rate ( = {64, 128}
// ) -bits; see section 2.4.2 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t b, const size_t r>
static inline void
process_associated_data(uint64_t* const __restrict state,
                        const uint8_t* const __restrict data, // associated data
                        const size_t data_len // in terms of bytes
                        ) requires(ascon_perm::check_b(b) && check_r(r))
{
  // only when associated data is non-empty; do padding and then mixing
  if (data_len > 0) {
    constexpr const size_t rb8 = r >> 3;                 // r divided by 8
    const size_t tmp = (data_len << 3) % r;              // bits
    const size_t zero_pad_len = r - 1 - tmp;             // bits
    const size_t pad_byte_len = (zero_pad_len + 1) >> 3; // bytes

    const uint8_t* data_ = data + data_len - (rb8 - pad_byte_len);

    if constexpr (check_r64(r)) {
      const uint64_t last_data_blk = ascon_utils::pad_data(data_, pad_byte_len);

      const size_t data_blk_cnt = ((data_len + pad_byte_len) << 3) >> 6;

      for (size_t i = 0; i < data_blk_cnt - 1; i++) {
        const uint64_t data_blk = ascon_utils::from_be_bytes(data + (i << 3));

        state[0] ^= data_blk;
        ascon_perm::p_b<b>(state);
      }

      state[0] ^= last_data_blk;
      ascon_perm::p_b<b>(state);

    } else if constexpr (check_r128(r)) {
      uint64_t last_data_blk[2];
      ascon_utils::pad_data(data_, pad_byte_len, last_data_blk);

      const size_t data_blk_cnt = ((data_len + pad_byte_len) << 3) >> 7;

      for (size_t i = 0; i < data_blk_cnt - 1; i++) {
        const size_t offset0 = ((i << 1) << 3);
        const size_t offset1 = (((i << 1) + 1) << 3);

        const uint64_t data_blk_0 = ascon_utils::from_be_bytes(data + offset0);
        const uint64_t data_blk_1 = ascon_utils::from_be_bytes(data + offset1);

        state[0] ^= data_blk_0;
        state[1] ^= data_blk_1;
        ascon_perm::p_b<b>(state);
      }

      state[0] ^= last_data_blk[0];
      state[1] ^= last_data_blk[1];
      ascon_perm::p_b<b>(state);
    }
  }

  // final 1 -bit domain seperator constant mixing is mandatory
  state[4] ^= 0b1ul;
}

// Process plain text in blocks ( same as rate bits wide ) and produce cipher
// text is equal sized blocks; see section 2.4.3 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t b, const size_t r>
static inline void
process_plaintext(uint64_t* const __restrict state,
                  const uint8_t* const __restrict text,
                  const size_t text_len,           // in terms of bytes
                  uint8_t* const __restrict cipher // has length same as `text`
                  ) requires(ascon_perm::check_b(b) && check_r(r))
{
  constexpr const size_t rb8 = r >> 3;                 // r divided by 8
  const size_t tmp = (text_len << 3) % r;              // bits
  const size_t zero_pad_len = r - 1 - tmp;             // bits
  const size_t pad_byte_len = (zero_pad_len + 1) >> 3; // bytes

  const uint8_t* text_ = text + text_len - (rb8 - pad_byte_len);

  if constexpr (check_r64(r)) {
    const uint64_t last_text_blk = ascon_utils::pad_data(text_, pad_byte_len);

    const size_t text_blk_cnt = ((text_len + pad_byte_len) << 3) >> 6;

    for (size_t i = 0; i < text_blk_cnt - 1; i++) {
      const uint64_t text_blk = ascon_utils::from_be_bytes(text + (i << 3));

      state[0] ^= text_blk; // ciphered
      ascon_utils::to_be_bytes(state[0], cipher + (i << 3));

      ascon_perm::p_b<b>(state);
    }

    state[0] ^= last_text_blk; // ciphered last text block

    const size_t remaining_len = text_len & 7ul; // bytes
    if (remaining_len > 0) {
      uint8_t* cipher_ = cipher + text_len - remaining_len; // slice out

      for (size_t i = 0; i < remaining_len; i++) {
        cipher_[i] = static_cast<uint8_t>((state[0] >> ((7ul - i) << 3)));
      }
    }
  } else if constexpr (check_r128(r)) {
    uint64_t last_text_blk[2];
    ascon_utils::pad_data(text_, pad_byte_len, last_text_blk);

    const size_t text_blk_cnt = ((text_len + pad_byte_len) << 3) >> 7;

    for (size_t i = 0; i < text_blk_cnt - 1; i++) {
      const size_t offset_0 = (i << 1) << 3;
      const size_t offset_1 = ((i << 1) + 1) << 3;

      const uint64_t text_blk_0 = ascon_utils::from_be_bytes(text + offset_0);
      const uint64_t text_blk_1 = ascon_utils::from_be_bytes(text + offset_1);

      // ciphered
      state[0] ^= text_blk_0;
      state[1] ^= text_blk_1;
      ascon_utils::to_be_bytes(state[0], cipher + offset_0);
      ascon_utils::to_be_bytes(state[1], cipher + offset_1);

      ascon_perm::p_b<b>(state);
    }

    // ciphered last text block
    state[0] ^= last_text_blk[0];
    state[1] ^= last_text_blk[1];

    const size_t remaining_len = text_len & 15ul; // bytes
    if (remaining_len > 0) {
      uint8_t* cipher_ = cipher + text_len - remaining_len; // slice out

      const uint64_t br0[2] = { state[1], state[0] };
      constexpr size_t br1[2] = { 15ul, 7ul };

      for (size_t i = 0; i < remaining_len; i++) {
        const bool f = i < 8;
        cipher_[i] = static_cast<uint8_t>((br0[f] >> ((br1[f] - i) << 3)));
      }
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
                   ) requires(ascon_perm::check_b(b) && check_r(r))
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
      ascon_perm::p_b<b>(state);
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
      ascon_perm::p_b<b>(state);
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
         ) requires(ascon_perm::check_a(a) && check_r(r))
{
  if constexpr (check_r64(r)) {
    state[1] ^= k.limbs[0];
    state[2] ^= k.limbs[1];
  } else if constexpr (check_r128(r)) {
    state[2] ^= k.limbs[0];
    state[3] ^= k.limbs[1];
  }

  ascon_perm::p_a<a>(state);

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
         ) requires(ascon_perm::check_a(a) && check_r(r))
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

  ascon_perm::p_a<a>(state);

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
