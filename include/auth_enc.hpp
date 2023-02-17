#pragma once
#include "aead_utils.hpp"

// Ascon Light Weight Cryptography ( i.e. authenticated encryption, verified
// decryption and hashing ) Implementation
namespace ascon {

// Encrypts plain text with Ascon-128 authenticated encryption algorithm; see
// algorithm 1 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
//
// See parameters in table 1 of Ascon specification
static inline void
encrypt_128(const uint8_t* const __restrict key,
            const uint8_t* const __restrict nonce,
            const uint8_t* const __restrict data,
            const size_t dlen, // bytes; can be >= 0
            const uint8_t* const __restrict text,
            const size_t ctlen,               // bytes; can be >= 0
            uint8_t* const __restrict cipher, // length same as `text`
            uint8_t* const __restrict tag)
{
  uint64_t state[5]{};

  aead_utils::initialize<aead_utils::ASCON_128_IV, 128>(state, key, nonce);
  aead_utils::process_associated_data<6, 64>(state, data, dlen);
  aead_utils::process_plaintext<6, 64>(state, text, ctlen, cipher);
  aead_utils::finalize<12, 64, 128>(state, key, tag);
}

// Encrypts plain text with Ascon-128a authenticated encryption algorithm; see
// algorithm 1 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
//
// See parameters in table 1 of Ascon specification
static inline void
encrypt_128a(const uint8_t* const __restrict key,
             const uint8_t* const __restrict nonce,
             const uint8_t* const __restrict data,
             const size_t dlen, // bytes; can be >= 0
             const uint8_t* const __restrict text,
             const size_t ctlen,               // bytes; can be >= 0
             uint8_t* const __restrict cipher, // length same as `text`
             uint8_t* const __restrict tag)
{
  uint64_t state[5]{};

  aead_utils::initialize<aead_utils::ASCON_128a_IV, 128>(state, key, nonce);
  aead_utils::process_associated_data<8, 128>(state, data, dlen);
  aead_utils::process_plaintext<8, 128>(state, text, ctlen, cipher);
  aead_utils::finalize<12, 128, 128>(state, key, tag);
}

// Encrypts plain text with Ascon-80pq authenticated encryption algorithm; see
// algorithm 1 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
//
// See parameters in last paragraph of section 2.2 in Ascon specification
static inline void
encrypt_80pq(const uint8_t* const __restrict key,
             const uint8_t* const __restrict nonce,
             const uint8_t* const __restrict data,
             const size_t dlen, // bytes; can be >= 0
             const uint8_t* const __restrict text,
             const size_t ctlen,               // bytes; can be >= 0
             uint8_t* const __restrict cipher, // length same as `text`
             uint8_t* const __restrict tag)
{
  uint64_t state[5]{};

  aead_utils::initialize<aead_utils::ASCON_80pq_IV, 160>(state, key, nonce);
  aead_utils::process_associated_data<6, 64>(state, data, dlen);
  aead_utils::process_plaintext<6, 64>(state, text, ctlen, cipher);
  aead_utils::finalize<12, 64, 160>(state, key, tag);
}

}
