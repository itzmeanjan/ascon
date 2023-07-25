#pragma once
#include "common.hpp"

// Ascon-128a Authenticated Encryption with Associated Data
namespace ascon128a_aead {

// Ascon permutation instance, that needs to be applied with p^a
constexpr size_t ROUNDS_A = 12;

// Ascon permutation instance, that needs to be applied with p^b
constexpr size_t ROUNDS_B = 8;

// Bit width of rate portion of Ascon permutation
constexpr size_t RATE = 128;

// Ascon-128a initial state value ( only first 64 -bits ); taken from
// section 2.4.1 of
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
constexpr uint64_t IV = 0x80800c0800000000ul;

// Byte length of secret key of Ascon-128a AEAD
constexpr size_t KEY_LEN = 16;

// Byte length of public message nonce of Ascon-128a AEAD
constexpr size_t NONCE_LEN = 16;

// Byte length of authentication tag of Ascon-128a AEAD
constexpr size_t TAG_LEN = 16;

// Encrypts arbitrary many plain text with Ascon-128a authenticated encryption
// algorithm, given 16 -bytes secret key, 16 -bytes public message nonce and
// arbitrary many associated data bytes; see algorithm 1 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf.
//
// Note, associated data is never encrypted, only plain text is encrypted.
// Though both associated data and cipher text are authenticated.
inline void
encrypt(const uint8_t* const __restrict key,   // 16 -bytes key
        const uint8_t* const __restrict nonce, // 16 -bytes nonce
        const uint8_t* const __restrict data,  // Associated Data
        const size_t dlen,                     // bytes; can be >= 0
        const uint8_t* const __restrict text,  // Plain text
        const size_t ctlen,                    // bytes; can be >= 0
        uint8_t* const __restrict cipher,      // Cipher text
        uint8_t* const __restrict tag          // 16 -bytes authentication tag
)
{
  ascon_perm::ascon_perm_t state;

  ascon_aead::initialize<ROUNDS_A, IV, KEY_LEN * 8>(state, key, nonce);
  ascon_aead::process_associated_data<ROUNDS_B, RATE>(state, data, dlen);
  ascon_aead::process_plaintext<ROUNDS_B, RATE>(state, text, ctlen, cipher);
  ascon_aead::finalize<ROUNDS_A, RATE, KEY_LEN * 8>(state, key, tag);
}

// Decrypts arbitrary byte length cipher text with Ascon-128a verified
// decryption algorithm, given 16 -bytes secret key, 16 -bytes public message
// nonce, 16 -bytes authentication tag and arbitrary byte length associated
// data; see algorithm 1 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf.
//
// In case authentication check ( i.e. tag verification ) fails, this function
// won't release unverified plain text bytes. Rather memory locations for
// storing plain text will explicitly be zeroed. Both tag verification and
// zeroing of memory locations are attempted to be performed in constant-time.
// This function should return truth value, if authentication check passes,
// while it will return false value, in case tag verification fails.
inline bool
decrypt(const uint8_t* const __restrict key,    // 16 -bytes key
        const uint8_t* const __restrict nonce,  // 16 -bytes nonce
        const uint8_t* const __restrict data,   // Associated Data
        const size_t dlen,                      // bytes; can be >= 0
        const uint8_t* const __restrict cipher, // Cipher text
        const size_t ctlen,                     // bytes; can be >= 0
        uint8_t* const __restrict text,         // Plain text
        const uint8_t* const __restrict tag     // 16 -bytes authentication tag
)
{
  ascon_perm::ascon_perm_t state;
  uint8_t _tag[TAG_LEN];

  ascon_aead::initialize<ROUNDS_A, IV, KEY_LEN * 8>(state, key, nonce);
  ascon_aead::process_associated_data<ROUNDS_B, RATE>(state, data, dlen);
  ascon_aead::process_ciphertext<ROUNDS_B, RATE>(state, cipher, ctlen, text);
  ascon_aead::finalize<ROUNDS_A, RATE, KEY_LEN * 8>(state, key, _tag);

  const uint32_t flg = ascon_utils::ct_eq_byte_array(tag, _tag, TAG_LEN);
  ascon_utils::ct_conditional_memset(~flg, text, 0, ctlen);

  return static_cast<bool>(flg);
}

}
