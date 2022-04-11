#pragma once
#include "utils.hpp"

// Data types along with some utility functions are written here

// Ascon Light Weight Cryptography ( i.e. authenticated encryption, verified
// decryption and hashing ) Implementation
namespace ascon {

// 128 -bit Ascon secret key, used for authenticated encryption/ decryption;
// see table 1 in section 2.2 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
struct secret_key_128_t
{
  uint64_t limbs[2];

  secret_key_128_t(const uint64_t l0, const uint64_t l1)
  {
    limbs[0] = l0;
    limbs[1] = l1;
  }

  secret_key_128_t(const uint8_t* const bytes)
  {
    limbs[0] = ascon_utils::from_be_bytes(bytes);
    limbs[1] = ascon_utils::from_be_bytes(bytes + 8u);
  }

  inline void to_bytes(uint8_t* const out)
  {
    ascon_utils::to_be_bytes(limbs[0], out);
    ascon_utils::to_be_bytes(limbs[1], out + 8u);
  }
};

// 160 -bit Ascon-80pq secret key, used for authenticated encryption/
// decryption; see last paragraph of section 2.2 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
//
// Note, last 64 -bit word's ( i.e. limbs[2] ) lower 32 -bits are of our
// interest, where last 32 -bits ( from bit index 128 to 159 ) of 160 -bit
// secret key are kept, so it's safe to discard upper 32 -bits of `limbs[2]`
struct secret_key_160_t
{
  uint64_t limbs[3];

  secret_key_160_t(const uint64_t l0, const uint64_t l1, const uint64_t l2)
  {
    limbs[0] = l0;
    limbs[1] = l1;
    limbs[2] = l2;
  }

  secret_key_160_t(const uint8_t* const bytes)
  {
    limbs[0] = ascon_utils::from_be_bytes(bytes);
    limbs[1] = ascon_utils::from_be_bytes(bytes + 8u);
    limbs[2] = static_cast<uint64_t>((static_cast<uint32_t>(bytes[16u]) << 24) |
                                     (static_cast<uint32_t>(bytes[17u]) << 16) |
                                     (static_cast<uint32_t>(bytes[18u]) << 8) |
                                     static_cast<uint32_t>(bytes[19u]));
  }

  inline void to_bytes(uint8_t* const out)
  {
    ascon_utils::to_be_bytes(limbs[0], out);
    ascon_utils::to_be_bytes(limbs[1], out + 8u);

    const uint32_t low = static_cast<uint32_t>(limbs[2]);

    out[16u] = static_cast<uint8_t>(low >> 24);
    out[17u] = static_cast<uint8_t>(low >> 16);
    out[18u] = static_cast<uint8_t>(low >> 8);
    out[19u] = static_cast<uint8_t>(low >> 0);
  }
};

// 128 -bit Ascon nonce, used for authenticated encryption/ decryption
// see table 1 in section 2.2 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
struct nonce_t
{
  uint64_t limbs[2];

  nonce_t(const uint64_t l0, const uint64_t l1)
  {
    limbs[0] = l0;
    limbs[1] = l1;
  }

  nonce_t(const uint8_t* const bytes)
  {
    limbs[0] = ascon_utils::from_be_bytes(bytes);
    limbs[1] = ascon_utils::from_be_bytes(bytes + 8u);
  }

  inline void to_bytes(uint8_t* const out)
  {
    ascon_utils::to_be_bytes(limbs[0], out);
    ascon_utils::to_be_bytes(limbs[1], out + 8u);
  }
};

// 128 -bit tag, generated in finalization step of Ascon-128/128a; see table 1
// in section 2.2 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
struct tag_t
{
  uint64_t limbs[2];

  tag_t(const uint64_t l0, const uint64_t l1)
  {
    limbs[0] = l0;
    limbs[1] = l1;
  }

  tag_t(const uint8_t* const bytes)
  {
    limbs[0] = ascon_utils::from_be_bytes(bytes);
    limbs[1] = ascon_utils::from_be_bytes(bytes + 8u);
  }

  void to_bytes(uint8_t* const out)
  {
    ascon_utils::to_be_bytes(limbs[0], out);
    ascon_utils::to_be_bytes(limbs[1], out + 8u);
  }
};

}
