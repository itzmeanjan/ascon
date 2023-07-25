#pragma once
#include "common.hpp"

// Ascon-80pq Authenticated Encryption with Associated Data
namespace ascon80pq_aead {

// Ascon permutation instance, that needs to be applied with p^a
constexpr size_t ROUNDS_A = 12;

// Ascon permutation instance, that needs to be applied with p^b
constexpr size_t ROUNDS_B = 6;

// Bit width of rate portion of Ascon permutation
constexpr size_t RATE = 64;

// Ascon-80pq initial state value ( only first 32 -bits ); taken from
// section 2.4.1 of
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
constexpr uint64_t IV = 0xa0400c06ul;

// Byte length of secret key of Ascon-80pq AEAD
constexpr size_t KEY_LEN = 20;

// Byte length of public message nonce of Ascon-80pq AEAD
constexpr size_t NONCE_LEN = ascon_aead::NONCE_LEN;

// Byte length of authentication tag of Ascon-80pq AEAD
constexpr size_t TAG_LEN = ascon_aead::TAG_LEN;

// Encrypts arbitrary many plain text with Ascon-80pq authenticated encryption
// algorithm, given 20 -bytes secret key, 16 -bytes public message nonce and
// arbitrary many associated data bytes; see algorithm 1 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf.
//
// Note, associated data is never encrypted, only plain text is encrypted.
// Though both associated data and cipher text are authenticated.
inline void
encrypt(std::span<const uint8_t, KEY_LEN> key,     // 16 -bytes key
        std::span<const uint8_t, NONCE_LEN> nonce, // 16 -bytes nonce
        std::span<const uint8_t> data,             // Associated Data
        std::span<const uint8_t> text,             // Plain text
        std::span<uint8_t> cipher,                 // Cipher text
        std::span<uint8_t, TAG_LEN> tag            // 16 -bytes authentication tag
)
{
  ascon_perm::ascon_perm_t state;

  ascon_aead::initialize<ROUNDS_A, IV, KEY_LEN * 8>(state, key, nonce);
  ascon_aead::process_associated_data<ROUNDS_B, RATE>(state, data);
  ascon_aead::process_plaintext<ROUNDS_B, RATE>(state, text, cipher);
  ascon_aead::finalize<ROUNDS_A, RATE, KEY_LEN * 8>(state, key, tag);
}

// Decrypts arbitrary byte length cipher text with Ascon-80pq verified
// decryption algorithm, given 20 -bytes secret key, 16 -bytes public message
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
decrypt(std::span<const uint8_t, KEY_LEN> key,     // 16 -bytes key
        std::span<const uint8_t, NONCE_LEN> nonce, // 16 -bytes nonce
        std::span<const uint8_t> data,             // Associated Data
        std::span<const uint8_t> cipher,           // Cipher text
        std::span<uint8_t> text,                   // Plain text
        std::span<const uint8_t, TAG_LEN> tag      // 16 -bytes authentication tag
)
{
  ascon_perm::ascon_perm_t state;
  std::array<uint8_t, TAG_LEN> _tag{};

  ascon_aead::initialize<ROUNDS_A, IV, KEY_LEN * 8>(state, key, nonce);
  ascon_aead::process_associated_data<ROUNDS_B, RATE>(state, data);
  ascon_aead::process_ciphertext<ROUNDS_B, RATE>(state, cipher, text);
  ascon_aead::finalize<ROUNDS_A, RATE, KEY_LEN * 8>(state, key, _tag);

  const uint32_t flg = ascon_utils::ct_eq_byte_array<TAG_LEN>(tag, _tag);
  ascon_utils::ct_conditional_memset(~flg, text, 0);

  return static_cast<bool>(flg);
}

}
