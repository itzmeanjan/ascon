#pragma once
#include "ascon_perm.hpp"
#include "utils.hpp"
#include <array>

// Common functions required for implementing Ascon-{128, 128a, 80pq}
// authenticated encryption & verified decryption.
namespace ascon_aead {

// Byte length of public message nonce for all AEAD schemes.
constexpr size_t NONCE_LEN = 16;

// Byte length of authentication tag for all AEAD schemes.
constexpr size_t TAG_LEN = 16;

// Initialize cipher state for Ascon{128, 128a, 80pq} authenticated encryption/
// decryption; see section 2.4.1 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
template<const size_t rounds_a, const uint64_t IV, const size_t klen>
static inline void
initialize(ascon_perm::ascon_perm_t& state,
           std::span<const uint8_t, klen / 8> key,
           std::span<const uint8_t, NONCE_LEN> nonce)
{
  if constexpr (klen == 128) {
    // For Ascon-128{a}
    const auto _key0 = key.template subspan<0, 8>();
    const auto _key1 = key.template subspan<8, 8>();

    const auto _nonce0 = nonce.subspan<0, 8>();
    const auto _nonce1 = nonce.subspan<8, 8>();

    const auto key0 = ascon_utils::from_be_bytes<uint64_t>(_key0);
    const auto key1 = ascon_utils::from_be_bytes<uint64_t>(_key1);

    const auto nonce0 = ascon_utils::from_be_bytes<uint64_t>(_nonce0);
    const auto nonce1 = ascon_utils::from_be_bytes<uint64_t>(_nonce1);

    state[0] = IV;
    state[1] = key0;
    state[2] = key1;
    state[3] = nonce0;
    state[4] = nonce1;

    state.permute<rounds_a>();

    state[3] ^= key0;
    state[4] ^= key1;
  } else {
    // For Ascon-80pq
    static_assert(klen == 160, "Bit length of secret key must be 160.");

    const auto _key0 = key.template subspan<0, 8>();
    const auto _key1 = key.template subspan<8, 8>();
    const auto _key2 = key.template subspan<16, 4>();

    const auto _nonce0 = nonce.subspan<0, 8>();
    const auto _nonce1 = nonce.subspan<8, 8>();

    const auto key0 = ascon_utils::from_be_bytes<uint64_t>(_key0);
    const auto key1 = ascon_utils::from_be_bytes<uint64_t>(_key1);
    const auto key2 = ascon_utils::from_be_bytes<uint32_t>(_key2);

    const auto nonce0 = ascon_utils::from_be_bytes<uint64_t>(_nonce0);
    const auto nonce1 = ascon_utils::from_be_bytes<uint64_t>(_nonce1);

    state[0] = (IV << 32) | (key0 >> 32);
    state[1] = (key0 << 32) | (key1 >> 32);
    state[2] = (key1 << 32) | static_cast<uint64_t>(key2);
    state[3] = nonce0;
    state[4] = nonce1;

    state.permute<ascon_perm::MAX_ROUNDS>();

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
process_associated_data(ascon_perm::ascon_perm_t& state, std::span<const uint8_t> data)
  requires((rate == 64) || (rate == 128))
{
  const size_t dlen = data.size();

  if (dlen > 0) {
    constexpr size_t rbytes = rate / 8;
    const size_t blk_cnt = (dlen + 1 + (rbytes - 1)) / rbytes;

    std::array<uint8_t, rbytes> chunk{};
    auto _chunk = std::span(chunk);

    // Process full message blocks, expect the last one, which is padded.
    for (size_t i = 0; i < blk_cnt - 1; i++) {
      ascon_utils::get_ith_msg_blk(data, i, _chunk);

      if constexpr (rate == 64) {
        const auto word = ascon_utils::from_be_bytes<uint64_t>(_chunk);
        state[0] ^= word;
      } else {
        // force compile-time branch evaluation
        static_assert(rate == 128, "Rate must be 128 -bits");

        const auto _chunk0 = _chunk.template subspan<0, 8>();
        const auto _chunk1 = _chunk.template subspan<8, 8>();

        const auto word0 = ascon_utils::from_be_bytes<uint64_t>(_chunk0);
        const auto word1 = ascon_utils::from_be_bytes<uint64_t>(_chunk1);

        state[0] ^= word0;
        state[1] ^= word1;
      }

      state.permute<rounds_b>();
    }

    // Process last message block, which is padded.
    // `read` must be < `rbytes`.

    const size_t i = blk_cnt - 1;
    const size_t read = ascon_utils::get_ith_msg_blk(data, i, _chunk);
    ascon_utils::pad_msg_blk(_chunk, read);

    if constexpr (rate == 64) {
      const auto word = ascon_utils::from_be_bytes<uint64_t>(_chunk);
      state[0] ^= word;
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      const auto _chunk0 = _chunk.template subspan<0, 8>();
      const auto _chunk1 = _chunk.template subspan<8, 8>();

      const auto word0 = ascon_utils::from_be_bytes<uint64_t>(_chunk0);
      const auto word1 = ascon_utils::from_be_bytes<uint64_t>(_chunk1);

      state[0] ^= word0;
      state[1] ^= word1;
    }

    state.permute<rounds_b>();
  }

  // final 1 -bit domain seperator constant mixing is mandatory
  state[4] ^= 0b1ul;
}

// Process plain text in blocks ( same as rate bits wide ) and produce cipher
// text is equal sized blocks; see section 2.4.3 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
template<const size_t rounds_b, const size_t rate>
static inline void
process_plaintext(ascon_perm::ascon_perm_t& state,
                  std::span<const uint8_t> text,
                  std::span<uint8_t> cipher)
  requires((rate == 64) || (rate == 128))
{
  const size_t ctlen = text.size();
  constexpr size_t rbytes = rate / 8;
  const size_t blk_cnt = (ctlen + 1 + (rbytes - 1)) / rbytes;

  std::array<uint8_t, rbytes> chunk{};
  auto _chunk = std::span(chunk);

  size_t off = 0;

  // Process full message blocks, expect the last one, which is padded.
  for (size_t i = 0; i < blk_cnt - 1; i++) {
    if constexpr (rate == 64) {
      const auto _text = text.subspan(off, 8);
      const uint64_t word = ascon_utils::from_be_bytes<uint64_t>(_text);

      state[0] ^= word;

      auto _cipher = cipher.subspan(off, 8);
      ascon_utils::to_be_bytes(state[0], _cipher);
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      ascon_utils::get_ith_msg_blk(text, i, _chunk);

      const auto _chunk0 = _chunk.template subspan<0, 8>();
      const auto _chunk1 = _chunk.template subspan<8, 8>();

      const uint64_t word0 = ascon_utils::from_be_bytes<uint64_t>(_chunk0);
      const uint64_t word1 = ascon_utils::from_be_bytes<uint64_t>(_chunk1);

      state[0] ^= word0;
      state[1] ^= word1;

      auto _cipher0 = cipher.subspan(off, 8);
      auto _cipher1 = cipher.subspan(off + 8, 8);

      ascon_utils::to_be_bytes(state[0], _cipher0);
      ascon_utils::to_be_bytes(state[1], _cipher1);
    }

    state.permute<rounds_b>();
    off += rbytes;
  }

  // Process last message block, which is padded.
  // `read` must be < `rbytes`.

  const size_t i = blk_cnt - 1;
  const size_t read = ascon_utils::get_ith_msg_blk(text, i, _chunk);
  ascon_utils::pad_msg_blk(_chunk, read);

  if constexpr (rate == 64) {
    const uint64_t word = ascon_utils::from_be_bytes<uint64_t>(_chunk);
    state[0] ^= word;
    ascon_utils::to_be_bytes(state[0], _chunk);
  } else {
    // force compile-time branch evaluation
    static_assert(rate == 128, "Rate must be 128 -bits");

    auto _chunk0 = chunk.template subspan<0, 8>();
    auto _chunk1 = chunk.template subspan<8, 8>();

    const uint64_t word0 = ascon_utils::from_be_bytes<uint64_t>(_chunk0);
    const uint64_t word1 = ascon_utils::from_be_bytes<uint64_t>(_chunk1);

    state[0] ^= word0;
    state[1] ^= word1;

    ascon_utils::to_be_bytes(state[0], _chunk0);
    ascon_utils::to_be_bytes(state[1], _chunk1);
  }

  // At this point, assert (ctlen - off) == read, must pass !
  std::memcpy(cipher.subspan(off).data(), _chunk.data(), read);
}

// Process cipher text in blocks ( same as rate bits wide ) and keep producing
// plain text blocks is equal sized blocks; see section 2.4.3 of Ascon
// specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
template<const size_t rounds_b, const size_t rate>
static inline void
process_ciphertext(ascon_perm::ascon_perm_t& state,
                   std::span<const uint8_t> cipher,
                   std::span<uint8_t> text)
  requires((rate == 64) || (rate == 128))
{
  const size_t ctlen = cipher.size();
  constexpr size_t rbytes = rate / 8;
  const size_t blk_cnt = (ctlen + 1 + (rbytes - 1)) / rbytes;

  std::array<uint8_t, rbytes> chunk{};
  auto _chunk = std::span(chunk);

  size_t off = 0;

  // Process full message blocks, expect the last one, which is padded.
  for (size_t i = 0; i < blk_cnt - 1; i++) {
    if constexpr (rate == 64) {
      const auto _cipher = cipher.subspan(off, 8);
      const uint64_t cword = ascon_utils::from_be_bytes<uint64_t>(_cipher);

      const uint64_t tword = state[0] ^ cword;
      state[0] = cword;

      auto _text = text.subspan(off, 8);
      ascon_utils::to_be_bytes(tword, _text);
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      ascon_utils::get_ith_msg_blk(cipher, i, chunk);

      const auto _chunk0 = chunk.template subspan<0, 8>();
      const auto _chunk1 = chunk.template subspan<8, 8>();

      const uint64_t cword0 = ascon_utils::from_be_bytes<uint64_t>(_chunk0);
      const uint64_t cword1 = ascon_utils::from_be_bytes<uint64_t>(_chunk1);

      const uint64_t tword0 = state[0] ^ cword0;
      const uint64_t tword1 = state[1] ^ cword1;

      state[0] = cword0;
      state[1] = cword1;

      auto _text0 = text.subspan(off, 8);
      auto _text1 = text.subspan(off + 8, 8);

      ascon_utils::to_be_bytes(tword0, _text0);
      ascon_utils::to_be_bytes(tword1, _text1);
    }

    state.permute<rounds_b>();
    off += rbytes;
  }

  // Process last message block, which is padded.
  // `read` must be < `rbytes`.

  const size_t i = blk_cnt - 1;
  const size_t read = ascon_utils::get_ith_msg_blk(cipher, i, _chunk);
  std::memset(_chunk.data() + read, 0x00, rbytes - read);

  if constexpr (rate == 64) {
    const uint64_t cword = ascon_utils::from_be_bytes<uint64_t>(_chunk);
    const uint64_t tword = state[0] ^ cword;

    ascon_utils::to_be_bytes(tword, _chunk);
    std::memcpy(text.subspan(off).data(), _chunk.data(), read);

    ascon_utils::pad_msg_blk(_chunk, read);

    const uint64_t pword = ascon_utils::from_be_bytes<uint64_t>(_chunk);
    state[0] ^= pword;
  } else {
    // force compile-time branch evaluation
    static_assert(rate == 128, "Rate must be 128 -bits");

    auto _chunk0 = _chunk.template subspan<0, 8>();
    auto _chunk1 = _chunk.template subspan<8, 8>();

    const uint64_t cword0 = ascon_utils::from_be_bytes<uint64_t>(_chunk0);
    const uint64_t cword1 = ascon_utils::from_be_bytes<uint64_t>(_chunk1);

    const uint64_t tword0 = state[0] ^ cword0;
    const uint64_t tword1 = state[1] ^ cword1;

    ascon_utils::to_be_bytes(tword0, _chunk0);
    ascon_utils::to_be_bytes(tword1, _chunk1);
    std::memcpy(text.subspan(off).data(), _chunk.data(), read);

    ascon_utils::pad_msg_blk(_chunk, read);

    const uint64_t pword0 = ascon_utils::from_be_bytes<uint64_t>(_chunk0);
    const uint64_t pword1 = ascon_utils::from_be_bytes<uint64_t>(_chunk1);

    state[0] ^= pword0;
    state[1] ^= pword1;
  }
}

// Ascon-{128, 128a, 80pq} finalization step, generates 128 -bit tag; taken from
// section 2.4.4 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
template<const size_t rounds_a, const size_t rate, const size_t klen>
static inline void
finalize(ascon_perm::ascon_perm_t& state,
         std::span<const uint8_t, klen / 8> key,
         std::span<uint8_t, TAG_LEN> tag)
  requires(((klen == 128) && ((rate == 64) || (rate == 128))) ||
           ((klen == 160) && (rate == 64)))
{
  if constexpr (klen == 128) {
    const auto _key0 = key.template subspan<0, 8>();
    const auto _key1 = key.template subspan<8, 8>();

    const auto key0 = ascon_utils::from_be_bytes<uint64_t>(_key0);
    const auto key1 = ascon_utils::from_be_bytes<uint64_t>(_key1);

    if constexpr (rate == 64) {
      state[1] ^= key0;
      state[2] ^= key1;
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      state[2] ^= key0;
      state[3] ^= key1;
    }

    state.permute<rounds_a>();

    auto _tag0 = tag.subspan<0, 8>();
    auto _tag1 = tag.subspan<8, 8>();

    ascon_utils::to_be_bytes(state[3] ^ key0, _tag0);
    ascon_utils::to_be_bytes(state[4] ^ key1, _tag1);
  } else {
    static_assert(klen == 160, "Bit length of secret key must be 160.");

    const auto _key0 = key.template subspan<0, 8>();
    const auto _key1 = key.template subspan<8, 8>();
    const auto _key2 = key.template subspan<16, 4>();

    const auto key0 = ascon_utils::from_be_bytes<uint64_t>(_key0);
    const auto key1 = ascon_utils::from_be_bytes<uint64_t>(_key1);
    const auto key2 = ascon_utils::from_be_bytes<uint32_t>(_key2);

    state[1] ^= key0;
    state[2] ^= key1;
    state[3] ^= static_cast<uint64_t>(key2) << 32;

    state.permute<rounds_a>();

    const auto t0 = (key0 << 32) | (key1 >> 32);
    const auto t1 = (key1 << 32) | static_cast<uint64_t>(key2);

    auto _tag0 = tag.subspan<0, 8>();
    auto _tag1 = tag.subspan<8, 8>();

    ascon_utils::to_be_bytes(state[3] ^ t0, _tag0);
    ascon_utils::to_be_bytes(state[4] ^ t1, _tag1);
  }
}

}
