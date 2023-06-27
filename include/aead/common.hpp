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
    const size_t dbits = dlen << 3;
    const size_t rm_bits = dbits & (rate - 1ul);
    const size_t zero_pad_bits = rate - 1ul - rm_bits;
    const size_t pad_bytes = (1ul + zero_pad_bits) >> 3;

    const size_t till = dlen - (rm_bits >> 3);
    size_t off = 0;

    // first mix all bytes which can form full words ( rate bits wide )
    while (off < till) {
      if constexpr (rate == 64) {
        // force compile-time branch evaluation
        static_assert(rate == 64, "Rate must be 64 -bits");

        const auto word = ascon_utils::from_be_bytes<uint64_t>(data + off);
        state[0] ^= word;
        ascon_permutation::permute<rounds_b>(state);

        off += 8ul;
      } else {
        // force compile-time branch evaluation
        static_assert(rate == 128, "Rate must be 128 -bits");

        const auto word0 = ascon_utils::from_be_bytes<uint64_t>(data + off);
        const auto word1 = ascon_utils::from_be_bytes<uint64_t>(data + off + 8);
        state[0] ^= word0;
        state[1] ^= word1;
        ascon_permutation::permute<rounds_b>(state);

        off += 16ul;
      }
    }

    // finally do padding and then mixing of padded word ( rate bits wide )
    if constexpr (rate == 64) {
      // force compile-time branch evaluation
      static_assert(rate == 64, "Rate must be 64 -bits");

      const auto word = ascon_utils::pad64(data + off, pad_bytes);
      state[0] ^= word;
      ascon_permutation::permute<rounds_b>(state);
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      const auto words = ascon_utils::pad128(data + off, pad_bytes);
      state[0] ^= words.first;
      state[1] ^= words.second;
      ascon_permutation::permute<rounds_b>(state);
    }
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
  const size_t tbits = ctlen << 3;
  const size_t rm_bits = tbits & (rate - 1ul);
  const size_t zero_pad_bits = rate - 1ul - rm_bits;
  const size_t pad_bytes = (1ul + zero_pad_bits) >> 3;

  const size_t till = ctlen - (rm_bits >> 3);
  size_t off = 0ul;

  // first encrypt all bytes which can be packed into rate bits wide full words
  while (off < till) {
    if constexpr (rate == 64) {
      // force compile-time branch evaluation
      static_assert(rate == 64, "Rate must be 64 -bits");

      const auto word = ascon_utils::from_be_bytes<uint64_t>(text + off);

      state[0] ^= word;
      ascon_utils::to_be_bytes(state[0], cipher + off);

      ascon_permutation::permute<rounds_b>(state);

      off += 8ul;
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      const auto word0 = ascon_utils::from_be_bytes<uint64_t>(text + off);
      const auto word1 = ascon_utils::from_be_bytes<uint64_t>(text + off + 8);

      state[0] ^= word0;
      state[1] ^= word1;

      ascon_utils::to_be_bytes(state[0], cipher + off);
      ascon_utils::to_be_bytes(state[1], cipher + off + 8ul);

      ascon_permutation::permute<rounds_b>(state);

      off += 16ul;
    }
  }

  // then encrypt remaining bytes which can't be packed into a full word i.e.
  // padding will be required
  if constexpr (rate == 64) {
    // force compile-time branch evaluation
    static_assert(rate == 64, "Rate must be 64 -bits");

    const auto word = ascon_utils::pad64(text + off, pad_bytes);
    state[0] ^= word;

    const size_t rm_bytes = rm_bits >> 3;

    if constexpr (std::endian::native == std::endian::little) {
      const auto swapped = ascon_utils::bswap(state[0]);
      std::memcpy(cipher + off, &swapped, rm_bytes);
    } else {
      std::memcpy(cipher + off, &state[0], rm_bytes);
    }
  } else {
    // force compile-time branch evaluation
    static_assert(rate == 128, "Rate must be 128 -bits");

    const auto words = ascon_utils::pad128(text + off, pad_bytes);
    state[0] ^= words.first;
    state[1] ^= words.second;

    const size_t rm_bytes = rm_bits >> 3;
    const size_t fbytes = std::min(rm_bytes, 8ul);
    const size_t lbytes = std::min(rm_bytes - fbytes, 8ul);

    if constexpr (std::endian::native == std::endian::little) {
      const auto word0 = ascon_utils::bswap(state[0]);
      const auto word1 = ascon_utils::bswap(state[1]);

      std::memcpy(cipher + off, &word0, fbytes);
      std::memcpy(cipher + off + fbytes, &word1, lbytes);
    } else {
      std::memcpy(cipher + off, &state[0], fbytes);
      std::memcpy(cipher + off + fbytes, &state[1], lbytes);
    }
  }
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
  const size_t ctbits = ctlen << 3;
  const size_t rm_bits = ctbits & (rate - 1ul);
  const size_t rm_bytes = rm_bits >> 3;

  const size_t till = ctlen - rm_bytes;
  size_t off = 0ul;

  // first decrypt all bytes which can be packed into rate bits wide full words
  while (off < till) {
    if constexpr (rate == 64) {
      // force compile-time branch evaluation
      static_assert(rate == 64, "Rate must be 64 -bits");

      const auto worda = ascon_utils::from_be_bytes<uint64_t>(cipher + off);
      const auto wordb = state[0] ^ worda;
      ascon_utils::to_be_bytes(wordb, text + off);

      state[0] = worda;
      ascon_permutation::permute<rounds_b>(state);

      off += 8ul;
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      const auto word0a = ascon_utils::from_be_bytes<uint64_t>(cipher + off);
      const auto word1a =
        ascon_utils::from_be_bytes<uint64_t>(cipher + off + 8);

      const auto word0b = state[0] ^ word0a;
      const auto word1b = state[1] ^ word1a;

      ascon_utils::to_be_bytes(word0b, text + off);
      ascon_utils::to_be_bytes(word1b, text + off + 8ul);

      state[0] = word0a;
      state[1] = word1a;

      ascon_permutation::permute<rounds_b>(state);

      off += 16ul;
    }
  }

  // then decrypt remaining bytes which can't be packed into a full word i.e.
  // padding was required during encryption
  if constexpr (rate == 64) {
    // force compile-time branch evaluation
    static_assert(rate == 64, "Rate must be 64 -bits");

    uint64_t worda = 0ul;
    std::memcpy(&worda, cipher + off, rm_bytes);

    if constexpr (std::endian::native == std::endian::little) {
      worda = ascon_utils::bswap(worda);
    }

    const auto wordb = state[0] ^ worda;

    if constexpr (std::endian::native == std::endian::little) {
      const auto swapped = ascon_utils::bswap(wordb);
      std::memcpy(text + off, &swapped, rm_bytes);
    } else {
      std::memcpy(text + off, &wordb, rm_bytes);
    }

    const bool flg = rm_bytes > 0;
    const uint64_t mask = flg * (MAX_ULONG << ((8ul - rm_bytes) * 8));
    const uint64_t selected = wordb & mask;
    const uint64_t padding0 = 1ul << (((8ul - rm_bytes) * 8) - 1ul);

    state[0] ^= selected | padding0;
  } else {
    // force compile-time branch evaluation
    static_assert(rate == 128, "Rate must be 128 -bits");

    const size_t fbytes = std::min(rm_bytes, 8ul);
    const size_t lbytes = std::min(rm_bytes - fbytes, 8ul);

    uint64_t word0a = 0ul;
    uint64_t word1a = 0ul;

    std::memcpy(&word0a, cipher + off, fbytes);
    std::memcpy(&word1a, cipher + off + fbytes, lbytes);

    if constexpr (std::endian::native == std::endian::little) {
      word0a = ascon_utils::bswap(word0a);
      word1a = ascon_utils::bswap(word1a);
    }

    const auto word0b = state[0] ^ word0a;
    const auto word1b = state[1] ^ word1a;

    if constexpr (std::endian::native == std::endian::little) {
      const auto swapped0 = ascon_utils::bswap(word0b);
      const auto swapped1 = ascon_utils::bswap(word1b);

      std::memcpy(text + off, &swapped0, fbytes);
      std::memcpy(text + off + fbytes, &swapped1, lbytes);
    } else {
      std::memcpy(text + off, &word0b, fbytes);
      std::memcpy(text + off + fbytes, &word1b, lbytes);
    }

    const bool flg0 = fbytes > 0;
    const uint64_t mask0 = flg0 * (MAX_ULONG << ((8ul - fbytes) * 8));
    const uint64_t selected0 = word0b & mask0;
    const bool flg1 = fbytes != 8ul;
    const uint64_t padding0 = flg1 * (1ul << (((8ul - fbytes) * 8) - 1ul));

    state[0] ^= selected0 | padding0;

    const bool flg2 = lbytes > 0;
    const uint64_t mask1 = flg2 * (MAX_ULONG << ((8ul - lbytes) * 8));
    const uint64_t selected1 = word1b & mask1;
    const bool flg3 = fbytes < 8ul;
    const uint64_t padding1 = 1ul << (((8ul - lbytes) * 8) - 1ul);

    state[1] ^= !flg3 * (selected1 | padding1);
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
      // force compile-time branch evaluation
      static_assert(rate == 64, "Rate must be 64 -bits");

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
