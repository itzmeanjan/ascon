#pragma once
#include "permutation.hpp"
#include "utils.hpp"

// Common functions required for implementing Ascon-{128, 128a, 80pq}
// authenticated encryption & verified decryption
namespace ascon_aead {

// = (1 << 64) - 1; maximum number that can be represented using 64 -bits
constexpr uint64_t MAX_ULONG = -1ul;

// Initialize cipher state for Ascon{128, 128a, 80pq} authenticated encryption/
// decryption; see section 2.4.1 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
template<const size_t rounds_a, const uint64_t IV, const size_t klen>
static inline void
initialize(uint64_t* const __restrict state,     // uninitialized hash state
           const uint8_t* const __restrict key,  // {128, 160} -bit secret key
           const uint8_t* const __restrict nonce // 128 -bit nonce
)
{
  if constexpr (klen == 128) {
    // For Ascon-128{a}
    const auto key0 = ascon_utils::from_be_bytes<uint64_t>(key);
    const auto key1 = ascon_utils::from_be_bytes<uint64_t>(key + 8);

    state[0] = IV;
    state[1] = key0;
    state[2] = key1;
    state[3] = ascon_utils::from_be_bytes<uint64_t>(nonce);
    state[4] = ascon_utils::from_be_bytes<uint64_t>(nonce + 8);

    ascon_permutation::permute<rounds_a>(state);

    state[3] ^= key0;
    state[4] ^= key1;
  } else {
    // For Ascon-80pq
    static_assert(klen == 160, "Bit length of secret key must be 160.");

    const auto key0 = ascon_utils::from_be_bytes<uint64_t>(key);
    const auto key1 = ascon_utils::from_be_bytes<uint64_t>(key + 8);
    const auto key2 = ascon_utils::from_be_bytes<uint32_t>(key + 16);

    state[0] = (IV << 32) | (key0 >> 32);
    state[1] = (key0 << 32) | (key1 >> 32);
    state[2] = (key1 << 32) | static_cast<uint64_t>(key2);
    state[3] = ascon_utils::from_be_bytes<uint64_t>(nonce);
    state[4] = ascon_utils::from_be_bytes<uint64_t>(nonce + 8);

    ascon_permutation::permute<12>(state);

    state[2] ^= (key0 >> 32);
    state[3] ^= (key0 << 32) | (key1 >> 32);
    state[4] ^= (key1 << 32) | static_cast<uint64_t>(key2);
  }
}

// Process `s` -many blocks of associated data, each of with rate ( = {64, 128}
// ) -bits; see section 2.4.2 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
template<const size_t rounds_b, const size_t rate>
static inline void
process_associated_data(uint64_t* const __restrict state,
                        const uint8_t* const __restrict data, // associated data
                        const size_t dlen // in terms of bytes, can be >= 0
                        )
  requires((rate == 64) || (rate == 128))
{
  if (dlen > 0) {
    constexpr size_t rbytes = rate / 8;
    const size_t blk_cnt = (dlen + 1 + (rbytes - 1)) / rbytes;

    uint8_t chunk[rbytes];

    // Process full message blocks, expect the last one, which is padded.
    for (size_t i = 0; i < blk_cnt - 1; i++) {
      ascon_utils::get_ith_msg_blk<rbytes>(data, dlen, i, chunk);

      if constexpr (rate == 64) {
        const auto word = ascon_utils::from_be_bytes<uint64_t>(chunk);
        state[0] ^= word;
      } else {
        // force compile-time branch evaluation
        static_assert(rate == 128, "Rate must be 128 -bits");

        const auto word0 = ascon_utils::from_be_bytes<uint64_t>(chunk);
        const auto word1 = ascon_utils::from_be_bytes<uint64_t>(chunk + 8);

        state[0] ^= word0;
        state[1] ^= word1;
      }

      ascon_permutation::permute<rounds_b>(state);
    }

    // Process last message block, which is padded.
    // `read` must be < `rbytes`.

    const size_t i = blk_cnt - 1;
    size_t read = ascon_utils::get_ith_msg_blk<rbytes>(data, dlen, i, chunk);

    // Padding with 10* rule.
    std::memset(chunk + read, 0x00, rbytes - read);
    std::memset(chunk + read, 0x80, std::min(rbytes - read, 1ul));

    if constexpr (rate == 64) {
      const auto word = ascon_utils::from_be_bytes<uint64_t>(chunk);
      state[0] ^= word;
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      const auto word0 = ascon_utils::from_be_bytes<uint64_t>(chunk);
      const auto word1 = ascon_utils::from_be_bytes<uint64_t>(chunk + 8);

      state[0] ^= word0;
      state[1] ^= word1;
    }

    ascon_permutation::permute<rounds_b>(state);
  }

  // final 1 -bit domain seperator constant mixing is mandatory
  state[4] ^= 0b1ul;
}

// Process plain text in blocks ( same as rate bits wide ) and produce cipher
// text is equal sized blocks; see section 2.4.3 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
template<const size_t rounds_b, const size_t rate>
static inline void
process_plaintext(uint64_t* const __restrict state,
                  const uint8_t* const __restrict text,
                  const size_t ctlen, // in terms of bytes, can be >= 0
                  uint8_t* const __restrict cipher // has length same as `text`
                  )
  requires((rate == 64) || (rate == 128))
{
  constexpr size_t rbytes = rate / 8;
  const size_t blk_cnt = (ctlen + 1 + (rbytes - 1)) / rbytes;

  uint8_t chunk[rbytes];
  size_t off = 0;

  // Process full message blocks, expect the last one, which is padded.
  for (size_t i = 0; i < blk_cnt - 1; i++) {
    ascon_utils::get_ith_msg_blk<rbytes>(text, ctlen, i, chunk);

    if constexpr (rate == 64) {
      const uint64_t word = ascon_utils::from_be_bytes<uint64_t>(chunk);

      state[0] ^= word;
      ascon_utils::to_be_bytes(state[0], cipher + off);
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      const uint64_t word0 = ascon_utils::from_be_bytes<uint64_t>(chunk);
      const uint64_t word1 = ascon_utils::from_be_bytes<uint64_t>(chunk + 8);

      state[0] ^= word0;
      state[1] ^= word1;

      ascon_utils::to_be_bytes(state[0], cipher + off);
      ascon_utils::to_be_bytes(state[1], cipher + off + 8);
    }

    ascon_permutation::permute<rounds_b>(state);
    off += rbytes;
  }

  // Process last message block, which is padded.
  // `read` must be < `rbytes`.

  const size_t i = blk_cnt - 1;
  size_t read = ascon_utils::get_ith_msg_blk<rbytes>(text, ctlen, i, chunk);

  // Padding with 10* rule.
  std::memset(chunk + read, 0x00, rbytes - read);
  std::memset(chunk + read, 0x80, std::min(rbytes - read, 1ul));

  if constexpr (rate == 64) {
    const uint64_t word = ascon_utils::from_be_bytes<uint64_t>(chunk);

    state[0] ^= word;
    ascon_utils::to_be_bytes(state[0], chunk);
  } else {
    // force compile-time branch evaluation
    static_assert(rate == 128, "Rate must be 128 -bits");

    const uint64_t word0 = ascon_utils::from_be_bytes<uint64_t>(chunk);
    const uint64_t word1 = ascon_utils::from_be_bytes<uint64_t>(chunk + 8);

    state[0] ^= word0;
    state[1] ^= word1;

    ascon_utils::to_be_bytes(state[0], chunk);
    ascon_utils::to_be_bytes(state[1], chunk + 8);
  }

  // At this point, assert (ctlen - off) == read, must pass !
  std::memcpy(cipher + off, chunk, read);
}

// Process cipher text in blocks ( same as rate bits wide ) and keep producing
// plain text blocks is equal sized blocks; see section 2.4.3 of Ascon
// specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
template<const size_t rounds_b, const size_t rate>
static inline void
process_ciphertext(uint64_t* const __restrict state,
                   const uint8_t* const __restrict cipher,
                   const size_t ctlen, // in terms of bytes, can be >= 0
                   uint8_t* const __restrict text // has length same as `cipher`
                   )
  requires((rate == 64) || (rate == 128))
{
  constexpr size_t rbytes = rate / 8;
  const size_t blk_cnt = (ctlen + 1 + (rbytes - 1)) / rbytes;

  uint8_t chunk[rbytes];
  size_t off = 0;

  // Process full message blocks, expect the last one, which is padded.
  for (size_t i = 0; i < blk_cnt - 1; i++) {
    ascon_utils::get_ith_msg_blk<rbytes>(cipher, ctlen, i, chunk);

    if constexpr (rate == 64) {
      const uint64_t cword = ascon_utils::from_be_bytes<uint64_t>(chunk);
      const uint64_t tword = state[0] ^ cword;
      state[0] = cword;

      ascon_utils::to_be_bytes(tword, text + off);
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      const uint64_t cword0 = ascon_utils::from_be_bytes<uint64_t>(chunk);
      const uint64_t cword1 = ascon_utils::from_be_bytes<uint64_t>(chunk + 8);

      const uint64_t tword0 = state[0] ^ cword0;
      const uint64_t tword1 = state[1] ^ cword1;

      state[0] = cword0;
      state[1] = cword1;

      ascon_utils::to_be_bytes(tword0, text + off);
      ascon_utils::to_be_bytes(tword1, text + off + 8);
    }

    ascon_permutation::permute<rounds_b>(state);
    off += rbytes;
  }

  // Process last message block, which is padded.
  // `read` must be < `rbytes`.

  const size_t i = blk_cnt - 1;
  size_t read = ascon_utils::get_ith_msg_blk<rbytes>(cipher, ctlen, i, chunk);
  std::memset(chunk + read, 0x00, rbytes - read);

  if constexpr (rate == 64) {
    const uint64_t cword = ascon_utils::from_be_bytes<uint64_t>(chunk);
    const uint64_t tword = state[0] ^ cword;

    ascon_utils::to_be_bytes(tword, chunk);
    std::memcpy(text + off, chunk, read);

    // Padding with 10* rule.
    std::memset(chunk + read, 0x00, rbytes - read);
    std::memset(chunk + read, 0x80, std::min(rbytes - read, 1ul));

    const uint64_t pword = ascon_utils::from_be_bytes<uint64_t>(chunk);
    state[0] ^= pword;
  } else {
    // force compile-time branch evaluation
    static_assert(rate == 128, "Rate must be 128 -bits");

    const uint64_t cword0 = ascon_utils::from_be_bytes<uint64_t>(chunk);
    const uint64_t cword1 = ascon_utils::from_be_bytes<uint64_t>(chunk + 8);

    const uint64_t tword0 = state[0] ^ cword0;
    const uint64_t tword1 = state[1] ^ cword1;

    ascon_utils::to_be_bytes(tword0, chunk);
    ascon_utils::to_be_bytes(tword1, chunk + 8);
    std::memcpy(text + off, chunk, read);

    // Padding with 10* rule.
    std::memset(chunk + read, 0x00, rbytes - read);
    std::memset(chunk + read, 0x80, std::min(rbytes - read, 1ul));

    const uint64_t pword0 = ascon_utils::from_be_bytes<uint64_t>(chunk);
    const uint64_t pword1 = ascon_utils::from_be_bytes<uint64_t>(chunk + 8);

    state[0] ^= pword0;
    state[1] ^= pword1;
  }
}

// Ascon-{128, 128a, 80pq} finalization step, generates 128 -bit tag; taken from
// section 2.4.4 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
template<const size_t rounds_a, const size_t rate, const size_t klen>
static inline void
finalize(uint64_t* const __restrict state,
         const uint8_t* const __restrict key, // {128, 160} -bit secret key
         uint8_t* const __restrict tag        // 128 -bit tag
         )
  requires(((klen == 128) && ((rate == 64) || (rate == 128))) ||
           ((klen == 160) && (rate == 64)))
{
  if constexpr (klen == 128) {
    const auto key0 = ascon_utils::from_be_bytes<uint64_t>(key);
    const auto key1 = ascon_utils::from_be_bytes<uint64_t>(key + 8);

    if constexpr (rate == 64) {
      state[1] ^= key0;
      state[2] ^= key1;
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      state[2] ^= key0;
      state[3] ^= key1;
    }

    ascon_permutation::permute<rounds_a>(state);

    ascon_utils::to_be_bytes(state[3] ^ key0, tag);
    ascon_utils::to_be_bytes(state[4] ^ key1, tag + 8);
  } else {
    static_assert(klen == 160, "Bit length of secret key must be 160.");

    const auto key0 = ascon_utils::from_be_bytes<uint64_t>(key);
    const auto key1 = ascon_utils::from_be_bytes<uint64_t>(key + 8);
    const auto key2 = ascon_utils::from_be_bytes<uint32_t>(key + 16);

    state[1] ^= key0;
    state[2] ^= key1;
    state[3] ^= static_cast<uint64_t>(key2) << 32;

    ascon_permutation::permute<rounds_a>(state);

    const auto t0 = (key0 << 32) | (key1 >> 32);
    const auto t1 = (key1 << 32) | static_cast<uint64_t>(key2);

    ascon_utils::to_be_bytes(state[3] ^ t0, tag);
    ascon_utils::to_be_bytes(state[4] ^ t1, tag + 8);
  }
}

}
