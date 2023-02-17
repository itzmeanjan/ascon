#pragma once
#include <cstddef>
#include <cstdint>

// Ascon Light Weight Cryptography ( i.e. authenticated encryption, verified
// decryption and hashing ) Implementation
namespace ascon {

// Ascon-128 AEAD Key Byte Length
constexpr size_t ASCON128_KEY_LEN = 16;

// Ascon-128 AEAD Public Message Nonce Byte Length
constexpr size_t ASCON128_NONCE_LEN = 16;

// Ascon-128 AEAD Authentication Tag Byte Length
constexpr size_t ASCON128_TAG_LEN = 16;

// Ascon-128a AEAD Key Byte Length
constexpr size_t ASCON128A_KEY_LEN = 16;

// Ascon-128a AEAD Public Message Nonce Byte Length
constexpr size_t ASCON128A_NONCE_LEN = 16;

// Ascon-128a AEAD Authentication Tag Byte Length
constexpr size_t ASCON128A_TAG_LEN = 16;

// Ascon-80pq AEAD Key Byte Length
constexpr size_t ASCON80PQ_KEY_LEN = 20;

// Ascon-80pq AEAD Public Message Nonce Byte Length
constexpr size_t ASCON80PQ_NONCE_LEN = 16;

// Ascon-80pq AEAD Authentication Tag Byte Length
constexpr size_t ASCON80PQ_TAG_LEN = 16;

}
