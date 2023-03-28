#pragma once
#include "aead_utils.hpp"
#include "consts.hpp"
#include "subtle.hpp"

// Ascon Light Weight Cryptography ( i.e. authenticated encryption, verified
// decryption and hashing ) Implementation
namespace ascon {

// Decrypts cipher text with Ascon-128 verified decryption algorithm; see
// algorithm 1 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
//
// See parameters in table 1 of Ascon specification
//
// Note, use deciphered text only when this function returns true !
static inline bool
decrypt_128(const uint8_t* const __restrict key,
            const uint8_t* const __restrict nonce,
            const uint8_t* const __restrict data,
            const size_t dlen, // bytes; can be >= 0
            const uint8_t* const __restrict cipher,
            const size_t ctlen,             // bytes; can be >= 0
            uint8_t* const __restrict text, // length same as `cipher`
            const uint8_t* const __restrict tag)
{
  uint64_t state[5]{};
  uint8_t tag_[16];

  aead_utils::initialize<aead_utils::ASCON_128_IV, 128>(state, key, nonce);
  aead_utils::process_associated_data<6, 64>(state, data, dlen);
  aead_utils::process_ciphertext<6, 64>(state, cipher, ctlen, text);
  aead_utils::finalize<12, 64, 128>(state, key, tag_);

  // constant-time equality check of `tag` and `tag_`
  uint32_t flg = -1u;
  for (size_t i = 0; i < ascon::ASCON128_TAG_LEN; i++) {
    flg &= subtle::ct_eq<uint8_t, uint32_t>(tag[i], tag_[i]);
  }
  // constant-time setting of bytes held in memory locations
  // to zero values, in case tag != tag_
  for (size_t i = 0; i < ctlen; i++) {
    text[i] = subtle::ct_select(flg, text[i], static_cast<uint8_t>(0));
  }

  return static_cast<bool>(flg);
}

// Decrypts cipher text with Ascon-128a verified decryption algorithm; see
// algorithm 1 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
//
// See parameters in table 1 of Ascon specification
//
// Note, use deciphered text only when this function returns true !
static inline bool
decrypt_128a(const uint8_t* const __restrict key,
             const uint8_t* const __restrict nonce,
             const uint8_t* const __restrict data,
             const size_t dlen, // bytes; can be >= 0
             const uint8_t* const __restrict cipher,
             const size_t ctlen,             // bytes; can be >= 0
             uint8_t* const __restrict text, // length same as `cipher`
             const uint8_t* const __restrict tag)
{
  uint64_t state[5]{};
  uint8_t tag_[16];

  aead_utils::initialize<aead_utils::ASCON_128a_IV, 128>(state, key, nonce);
  aead_utils::process_associated_data<8, 128>(state, data, dlen);
  aead_utils::process_ciphertext<8, 128>(state, cipher, ctlen, text);
  aead_utils::finalize<12, 128, 128>(state, key, tag_);

  // constant-time equality check of `tag` and `tag_`
  uint32_t flg = -1u;
  for (size_t i = 0; i < ascon::ASCON128A_TAG_LEN; i++) {
    flg &= subtle::ct_eq<uint8_t, uint32_t>(tag[i], tag_[i]);
  }
  // constant-time setting of bytes held in memory locations
  // to zero values, in case tag != tag_
  for (size_t i = 0; i < ctlen; i++) {
    text[i] = subtle::ct_select(flg, text[i], static_cast<uint8_t>(0));
  }

  return static_cast<bool>(flg);
}

// Decrypts cipher text with Ascon-80pq verified decryption algorithm; see
// algorithm 1 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
//
// See parameters in last paragraph of section 2.2 in Ascon specification
//
// Note, use deciphered text only when this function returns true !
static inline bool
decrypt_80pq(const uint8_t* const __restrict key,
             const uint8_t* const __restrict nonce,
             const uint8_t* const __restrict data,
             const size_t dlen, // bytes; can be >= 0
             const uint8_t* const __restrict cipher,
             const size_t ctlen,             // bytes; can be >= 0
             uint8_t* const __restrict text, // length same as `cipher`
             const uint8_t* const __restrict tag)
{
  uint64_t state[5]{};
  uint8_t tag_[16];

  aead_utils::initialize<aead_utils::ASCON_80pq_IV, 160>(state, key, nonce);
  aead_utils::process_associated_data<6, 64>(state, data, dlen);
  aead_utils::process_ciphertext<6, 64>(state, cipher, ctlen, text);
  aead_utils::finalize<12, 64, 160>(state, key, tag_);

  // constant-time equality check of `tag` and `tag_`
  uint32_t flg = -1u;
  for (size_t i = 0; i < ascon::ASCON80PQ_TAG_LEN; i++) {
    flg &= subtle::ct_eq<uint8_t, uint32_t>(tag[i], tag_[i]);
  }
  // constant-time setting of bytes held in memory locations
  // to zero values, in case tag != tag_
  for (size_t i = 0; i < ctlen; i++) {
    text[i] = subtle::ct_select(flg, text[i], static_cast<uint8_t>(0));
  }

  return static_cast<bool>(flg);
}

}
