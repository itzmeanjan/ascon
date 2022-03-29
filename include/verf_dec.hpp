#pragma once
#include "cipher.hpp"

namespace ascon {

// Process cipher text in blocks ( same as rate bits wide ) and keep producing
// plain text blocks is equal sized blocks; see section 2.4.3 of Ascon
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t b, const size_t r>
static inline void
process_ciphertext(uint64_t* const __restrict state,
                   const uint8_t* const __restrict cipher,
                   const size_t cipher_len, // in terms of bytes
                   uint8_t* const __restrict text) requires(check_b(b) &&
                                                            check_r(r))
{
  const size_t cipher_bit_len = cipher_len << 3;
  const size_t cipher_blocks = cipher_bit_len / r;
  const size_t remaining_bit_len = cipher_bit_len % r;

  for (size_t i = 0; i < cipher_blocks; i++) {
    if (r == 64) {
      const size_t offset = i << 3;

      const uint64_t cipher_blk = ascon_utils::from_be_bytes(cipher + offset);
      const uint64_t text_blk = cipher_blk ^ state[0];

      ascon_utils::to_be_bytes(text_blk, text + offset);

      state[0] = cipher_blk;
      p_b<b>(state);
    } else if (r == 128) {
      const size_t offset_0 = (i << 1) << 3;
      const size_t offset_1 = ((i << 1) + 1) << 3;

      const uint64_t cipher_blk_0 =
        ascon_utils::from_be_bytes(cipher + offset_0);
      const uint64_t cipher_blk_1 =
        ascon_utils::from_be_bytes(cipher + offset_1);

      const uint64_t text_blk_0 = cipher_blk_0 ^ state[0];
      const uint64_t text_blk_1 = cipher_blk_1 ^ state[1];

      ascon_utils::to_be_bytes(text_blk_0, text + offset_0);
      ascon_utils::to_be_bytes(text_blk_1, text + offset_1);

      state[0] = cipher_blk_0;
      state[1] = cipher_blk_1;
      p_b<b>(state);
    }
  }

  if (remaining_bit_len > 0) {
    const size_t rem_byte_len = remaining_bit_len >> 3;
    const uint8_t* cipher_ = cipher + cipher_len - rem_byte_len;
    uint8_t* text_ = text + cipher_len - rem_byte_len;

    if (r == 64) {
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
    } else if (r == 128) {
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
        state[1] ^= 0b0ul;
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
    if (r == 64) {
      state[0] ^= 0b1ul << 63;
    } else if (r == 128) {
      state[0] ^= 0b1ul << 63;
      state[1] ^= 0b0ul;
    }
  }
}

// Decrypts cipher text with Ascon-128 verified decryption algorithm; see
// algorithm 1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
//
// See parameters in table 1 of Ascon specification
static inline const bool
decrypt_128(const secret_key_t& k,
            const nonce_t& n,
            const uint8_t* const __restrict associated_data,
            const size_t data_len,
            const uint8_t* const __restrict cipher,
            const size_t cipher_len,
            uint8_t* const __restrict text,
            const tag_t& t)
{
  uint64_t state[5];

  initialize<ASCON_128_IV, 12>(state, k, n);

  process_associated_data<6, 64>(state, associated_data, data_len);
  process_ciphertext<6, 64>(state, cipher, cipher_len, text);

  const tag_t t_ = finalize<12, 64>(state, k);
  return (t.limbs[0] == t_.limbs[0]) && (t.limbs[1] == t_.limbs[1]);
}

// Decrypts cipher text with Ascon-128a verified decryption algorithm; see
// algorithm 1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
//
// See parameters in table 1 of Ascon specification
static inline const bool
decrypt_128a(const secret_key_t& k,
             const nonce_t& n,
             const uint8_t* const __restrict associated_data,
             const size_t data_len,
             const uint8_t* const __restrict cipher,
             const size_t cipher_len,
             uint8_t* const __restrict text,
             const tag_t& t)
{
  uint64_t state[5];

  initialize<ASCON_128a_IV, 12>(state, k, n);

  process_associated_data<8, 128>(state, associated_data, data_len);
  process_ciphertext<8, 128>(state, cipher, cipher_len, text);

  const tag_t t_ = finalize<12, 128>(state, k);
  return (t.limbs[0] == t_.limbs[0]) && (t.limbs[1] == t_.limbs[1]);
}

}
