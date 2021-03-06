#pragma once
#include "cipher.hpp"

// Ascon Light Weight Cryptography ( i.e. authenticated encryption, verified
// decryption and hashing ) Implementation
namespace ascon {

// Decrypts cipher text with Ascon-128 verified decryption algorithm; see
// algorithm 1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
//
// See parameters in table 1 of Ascon specification
//
// Note, use deciphered text only when this function returns true !
static inline bool
decrypt_128(const secret_key_128_t& k,
            const nonce_t& n,
            const uint8_t* const __restrict associated_data,
            const size_t data_len, // bytes; can be >= 0
            const uint8_t* const __restrict cipher,
            const size_t cipher_len,        // bytes; can be >= 0
            uint8_t* const __restrict text, // length same as `cipher`
            const tag_t& t)
{
  using namespace ascon_cipher;

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
//
// Note, use deciphered text only when this function returns true !
static inline bool
decrypt_128a(const secret_key_128_t& k,
             const nonce_t& n,
             const uint8_t* const __restrict associated_data,
             const size_t data_len, // bytes; can be >= 0
             const uint8_t* const __restrict cipher,
             const size_t cipher_len,        // bytes; can be >= 0
             uint8_t* const __restrict text, // length same as `cipher`
             const tag_t& t)
{
  using namespace ascon_cipher;

  uint64_t state[5];

  initialize<ASCON_128a_IV, 12>(state, k, n);

  process_associated_data<8, 128>(state, associated_data, data_len);
  process_ciphertext<8, 128>(state, cipher, cipher_len, text);

  const tag_t t_ = finalize<12, 128>(state, k);
  return (t.limbs[0] == t_.limbs[0]) && (t.limbs[1] == t_.limbs[1]);
}

// Decrypts cipher text with Ascon-80pq verified decryption algorithm; see
// algorithm 1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
//
// See parameters in last paragraph of section 2.2 in Ascon specification
//
// Note, use deciphered text only when this function returns true !
static inline bool
decrypt_80pq(const secret_key_160_t& k,
             const nonce_t& n,
             const uint8_t* const __restrict associated_data,
             const size_t data_len, // bytes; can be >= 0
             const uint8_t* const __restrict cipher,
             const size_t cipher_len,        // bytes; can be >= 0
             uint8_t* const __restrict text, // length same as `cipher`
             const tag_t& t)
{
  using namespace ascon_cipher;

  uint64_t state[5];

  initialize<12>(state, k, n);

  process_associated_data<6, 64>(state, associated_data, data_len);
  process_ciphertext<6, 64>(state, cipher, cipher_len, text);

  const tag_t t_ = finalize<12, 64>(state, k);
  return (t.limbs[0] == t_.limbs[0]) && (t.limbs[1] == t_.limbs[1]);
}

}
