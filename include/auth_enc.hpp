#pragma once
#include "cipher.hpp"

// Ascon Light Weight Cryptography ( i.e. authenticated encryption, verified
// decryption and hashing ) Implementation
namespace ascon {

// Encrypts plain text with Ascon-128 authenticated encryption algorithm; see
// algorithm 1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
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
  using namespace ascon_cipher;

  uint64_t state[5]{};

  initialize<ASCON_128_IV, 12>(state, key, nonce);
  process_associated_data<6, 64>(state, data, dlen);
  process_plaintext<6, 64>(state, text, ctlen, cipher);
  finalize<12, 64>(state, key, tag);
}

// Encrypts plain text with Ascon-128a authenticated encryption algorithm; see
// algorithm 1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
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
  using namespace ascon_cipher;

  uint64_t state[5]{};

  initialize<ASCON_128a_IV, 12>(state, key, nonce);
  process_associated_data<8, 128>(state, data, dlen);
  process_plaintext<8, 128>(state, text, ctlen, cipher);
  finalize<12, 128>(state, key, tag);
}

// Encrypts plain text with Ascon-80pq authenticated encryption algorithm; see
// algorithm 1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
//
// See parameters in last paragraph of section 2.2 in Ascon specification
inline const tag_t
encrypt_80pq(const secret_key_160_t& k,
             const nonce_t& n,
             const uint8_t* const __restrict associated_data,
             const size_t data_len, // bytes; can be >= 0
             const uint8_t* const __restrict text,
             const size_t text_len,           // bytes; can be >= 0
             uint8_t* const __restrict cipher // length same as `text`
)
{
  using namespace ascon_cipher;

  uint64_t state[5];

  initialize<12>(state, k, n);
  process_associated_data<6, 64>(state, associated_data, data_len);
  process_plaintext<6, 64>(state, text, text_len, cipher);
  const tag_t t = finalize<12, 64>(state, k);

  return t;
}

}
