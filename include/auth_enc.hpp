#pragma once
#include "cipher.hpp"

namespace ascon {

// Process plain text in blocks ( same as rate bits wide ) and produce cipher
// text is equal sized blocks; see section 2.4.3 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t b, const size_t r>
static inline void
process_plaintext(uint64_t* const __restrict state,
                  const uint8_t* const __restrict text,
                  const size_t text_len, // in terms of bytes
                  uint8_t* const __restrict cipher) requires(check_b(b) &&
                                                             check_r(r))
{
  const size_t tmp = (text_len << 3) % r;
  const size_t zero_pad_len = r - 1 - tmp;
  const size_t pad_byte_len = (zero_pad_len + 1) >> 3;

  const uint8_t* text_ = text + text_len - ((r >> 3) - pad_byte_len);

  if (r == 64) {
    const uint64_t last_text_blk = pad_data(text_, pad_byte_len);

    const size_t text_blk_cnt = ((text_len + pad_byte_len) << 3) >> 6;

    for (size_t i = 0; i < text_blk_cnt - 1; i++) {
      const uint64_t text_blk = ascon_utils::from_be_bytes(text + (i << 3));

      state[0] ^= text_blk;
      ascon_utils::to_be_bytes(state[0], cipher + (i << 3));

      p_b<b>(state);
    }

    state[0] ^= last_text_blk;

    const size_t remaining_len = text_len % 8;
    if (remaining_len > 0) {
      uint8_t* cipher_ = cipher + text_len - remaining_len;

      for (size_t i = 0; i < remaining_len; i++) {
        cipher_[i] = static_cast<uint8_t>((state[0] >> ((7ul - i) << 3)));
      }
    }
  } else if (r == 128) {
    uint64_t last_text_blk[2];
    pad_data(text_, pad_byte_len, last_text_blk);

    const size_t text_blk_cnt = ((text_len + pad_byte_len) << 3) >> 7;

    for (size_t i = 0; i < text_blk_cnt - 1; i++) {
      const uint64_t text_blk_0 =
        ascon_utils::from_be_bytes(text + ((i << 1) << 3));
      const uint64_t text_blk_1 =
        ascon_utils::from_be_bytes(text + (((i << 1) + 1) << 3));

      state[0] ^= text_blk_0;
      state[1] ^= text_blk_1;
      ascon_utils::to_be_bytes(state[0], cipher + ((i << 1) << 3));
      ascon_utils::to_be_bytes(state[1], cipher + (((i << 1) + 1) << 3));

      p_b<b>(state);
    }

    state[0] ^= last_text_blk[0];
    state[1] ^= last_text_blk[1];

    const size_t remaining_len = text_len % 16;
    if (remaining_len > 0) {
      uint8_t* cipher_ = cipher + text_len - remaining_len;

      for (size_t i = 0; i < remaining_len; i++) {
        if (i < 8) {
          cipher_[i] = static_cast<uint8_t>((state[0] >> ((7ul - i) << 3)));
        } else {
          cipher_[i] = static_cast<uint8_t>((state[1] >> ((15ul - i) << 3)));
        }
      }
    }
  }
}

// Encrypts plain text with Ascon-128 authenticated encryption algorithm; see
// algorithm 1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
//
// See parameters in table 1 of Ascon specification
static inline const tag_t
encrypt_128(const secret_key_t& k,
            const nonce_t& n,
            const uint8_t* const __restrict associated_data,
            const size_t data_len,
            const uint8_t* const __restrict text,
            const size_t text_len,
            uint8_t* const __restrict cipher)
{
  uint64_t state[5];

  initialize<ASCON_128_IV, 12>(state, k, n);

  process_associated_data<6, 64>(state, associated_data, data_len);
  process_plaintext<6, 64>(state, text, text_len, cipher);

  const tag_t t = finalize<12, 64>(state, k);
  return t;
}

// Encrypts plain text with Ascon-128a authenticated encryption algorithm; see
// algorithm 1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
//
// See parameters in table 1 of Ascon specification
static inline const tag_t
encrypt_128a(const secret_key_t& k,
             const nonce_t& n,
             const uint8_t* const __restrict associated_data,
             const size_t data_len,
             const uint8_t* const __restrict text,
             const size_t text_len,
             uint8_t* const __restrict cipher)
{
  uint64_t state[5];

  initialize<ASCON_128a_IV, 12>(state, k, n);

  process_associated_data<8, 128>(state, associated_data, data_len);
  process_plaintext<8, 128>(state, text, text_len, cipher);

  const tag_t t = finalize<12, 128>(state, k);
  return t;
}

}
