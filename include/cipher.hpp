#pragma once
#include "permutation.hpp"
#include "types.hpp"
#include "utils.hpp"
#include <cstring>

// Utility functions for implementing Ascon-{128, 128a, 80pq} authenticated
// encryption & verified decryption
namespace ascon_cipher {

// Ascon-128 initial state value ( only first 64 -bits ); taken from
// section 2.4.1 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint64_t ASCON_128_IV = 0X80400c0600000000ul;

// Ascon-128a initial state value ( only first 64 -bits ); taken from
// section 2.4.1 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint64_t ASCON_128a_IV = 0x80800c0800000000ul;

// Ascon-80pq initial state value ( only first 32 -bits );
// taken from section 2.4.1 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint32_t ASCON_80pq_IV = 0xa0400c06ul;

// = (1 << 64) - 1; maximum number that can be represented using 64 -bits
constexpr uint64_t MAX_ULONG = 0xfffffffffffffffful;

// Compile-time check that correct initial state is used for either Ascon-128 or
// Ascon-128a
consteval bool
check_iv(const uint64_t iv)
{
  return !static_cast<bool>(iv ^ ASCON_128_IV) |
         !static_cast<bool>(iv ^ ASCON_128a_IV);
}

// Initialize cipher state for Ascon authenticated encryption/ decryption;
// see section 2.4.1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
//
// # -of rounds `a` should be 12 for both Ascon-128 & Ascon-128a, though still
// it's parameterized
template<const uint64_t IV, const size_t a>
static inline void
initialize(uint64_t* const __restrict state,     // uninitialized hash state
           const uint8_t* const __restrict key,  // 128 -bit secret key
           const uint8_t* const __restrict nonce // 128 -bit nonce
           )
  requires(check_iv(IV))
{
  const auto key0 = ascon_utils::from_be_bytes(key);
  const auto key1 = ascon_utils::from_be_bytes(key + 8);

  state[0] = IV;
  state[1] = key0;
  state[2] = key1;
  state[3] = ascon_utils::from_be_bytes(nonce);
  state[4] = ascon_utils::from_be_bytes(nonce + 8);

  ascon_perm::permute<a>(state);

  state[3] ^= key0;
  state[4] ^= key1;
}

// Initialize cipher state for Ascon-80pq authenticated cipher;
// see section 2.4.1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
//
// # -of rounds `a` should be 12 for Ascon-80pq, though still it's parameterized
template<const size_t a>
static inline void
initialize(uint64_t* const state,            // uninitialized hash state
           const ascon::secret_key_160_t& k, // 160 -bit secret key
           const ascon::nonce_t& n           // 128 -bit nonce
)
{
  state[0] = (static_cast<uint64_t>(ASCON_80pq_IV) << 32) | (k.limbs[0] >> 32);
  state[1] = ((k.limbs[0] & 0xfffffffful) << 32) | (k.limbs[1] >> 32);
  state[2] = ((k.limbs[1] & 0xfffffffful) << 32) | (k.limbs[2] & 0xfffffffful);
  state[3] = n.limbs[0];
  state[4] = n.limbs[1];

  ascon_perm::permute<a>(state);

  const uint64_t l_u32 = k.limbs[2] & 0xfffffffful;

  state[2] ^= (k.limbs[0] >> 32);
  state[3] ^= (((k.limbs[0] & 0xfffffffful) << 32) | (k.limbs[1] >> 32));
  state[4] ^= (((k.limbs[1] & 0xfffffffful) << 32) | l_u32);
}

// Process `s` -many blocks of associated data, each of with rate ( = {64, 128}
// ) -bits; see section 2.4.2 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t b, const size_t rate>
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

        const auto word = ascon_utils::from_be_bytes(data + off);
        state[0] ^= word;
        ascon_perm::permute<b>(state);

        off += 8ul;
      } else {
        // force compile-time branch evaluation
        static_assert(rate == 128, "Rate must be 128 -bits");

        const auto word0 = ascon_utils::from_be_bytes(data + off);
        const auto word1 = ascon_utils::from_be_bytes(data + off + 8ul);
        state[0] ^= word0;
        state[1] ^= word1;
        ascon_perm::permute<b>(state);

        off += 16ul;
      }
    }

    // finally do padding and then mixing of padded word ( rate bits wide )
    if constexpr (rate == 64) {
      // force compile-time branch evaluation
      static_assert(rate == 64, "Rate must be 64 -bits");

      const auto word = ascon_utils::pad_data(data + off, pad_bytes);
      state[0] ^= word;
      ascon_perm::permute<b>(state);
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      uint64_t buf[2];
      ascon_utils::pad_data(data + off, pad_bytes, buf);
      state[0] ^= buf[0];
      state[1] ^= buf[1];
      ascon_perm::permute<b>(state);
    }
  }

  // final 1 -bit domain seperator constant mixing is mandatory
  state[4] ^= 0b1ul;
}

// Process plain text in blocks ( same as rate bits wide ) and produce cipher
// text is equal sized blocks; see section 2.4.3 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t b, const size_t rate>
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

      const auto word = ascon_utils::from_be_bytes(text + off);

      state[0] ^= word;
      ascon_utils::to_be_bytes(state[0], cipher + off);

      ascon_perm::permute<b>(state);

      off += 8ul;
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      const auto word0 = ascon_utils::from_be_bytes(text + off);
      const auto word1 = ascon_utils::from_be_bytes(text + off + 8ul);

      state[0] ^= word0;
      state[1] ^= word1;

      ascon_utils::to_be_bytes(state[0], cipher + off);
      ascon_utils::to_be_bytes(state[1], cipher + off + 8ul);

      ascon_perm::permute<b>(state);

      off += 16ul;
    }
  }

  // then encrypt remaining bytes which can't be packed into a full word i.e.
  // padding will be required
  if constexpr (rate == 64) {
    // force compile-time branch evaluation
    static_assert(rate == 64, "Rate must be 64 -bits");

    const auto word = ascon_utils::pad_data(text + off, pad_bytes);
    state[0] ^= word;

    const size_t rm_bytes = rm_bits >> 3;

    if constexpr (std::endian::native == std::endian::little) {
      const auto swapped = ascon_utils::bswap64(state[0]);
      std::memcpy(cipher + off, &swapped, rm_bytes);
    } else {
      std::memcpy(cipher + off, &state[0], rm_bytes);
    }
  } else {
    // force compile-time branch evaluation
    static_assert(rate == 128, "Rate must be 128 -bits");

    uint64_t buf[2];
    ascon_utils::pad_data(text + off, pad_bytes, buf);

    state[0] ^= buf[0];
    state[1] ^= buf[1];

    const size_t rm_bytes = rm_bits >> 3;
    const size_t fbytes = std::min(rm_bytes, 8ul);
    const size_t lbytes = std::min(rm_bytes - fbytes, 8ul);

    if constexpr (std::endian::native == std::endian::little) {
      const auto word0 = ascon_utils::bswap64(state[0]);
      const auto word1 = ascon_utils::bswap64(state[1]);

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
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t b, const size_t rate>
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

      const auto worda = ascon_utils::from_be_bytes(cipher + off);
      const auto wordb = state[0] ^ worda;
      ascon_utils::to_be_bytes(wordb, text + off);

      state[0] = worda;
      ascon_perm::permute<b>(state);

      off += 8ul;
    } else {
      // force compile-time branch evaluation
      static_assert(rate == 128, "Rate must be 128 -bits");

      const auto word0a = ascon_utils::from_be_bytes(cipher + off);
      const auto word1a = ascon_utils::from_be_bytes(cipher + off + 8ul);

      const auto word0b = state[0] ^ word0a;
      const auto word1b = state[1] ^ word1a;

      ascon_utils::to_be_bytes(word0b, text + off);
      ascon_utils::to_be_bytes(word1b, text + off + 8ul);

      state[0] = word0a;
      state[1] = word1a;

      ascon_perm::permute<b>(state);

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
      worda = ascon_utils::bswap64(worda);
    }

    const auto wordb = state[0] ^ worda;

    if constexpr (std::endian::native == std::endian::little) {
      const auto swapped = ascon_utils::bswap64(wordb);
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
      word0a = ascon_utils::bswap64(word0a);
      word1a = ascon_utils::bswap64(word1a);
    }

    const auto word0b = state[0] ^ word0a;
    const auto word1b = state[1] ^ word1a;

    if constexpr (std::endian::native == std::endian::little) {
      const auto swapped0 = ascon_utils::bswap64(word0b);
      const auto swapped1 = ascon_utils::bswap64(word1b);

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

// Ascon-128/128a finalization step, generates 128 -bit tag; taken from
// section 2.4.4 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t a, const size_t rate>
static inline void
finalize(uint64_t* const __restrict state,
         const uint8_t* const __restrict key, // 128 -bit secret key
         uint8_t* const __restrict tag        // 128 -bit tag
         )
  requires((rate == 64) || (rate == 128))
{
  const auto key0 = ascon_utils::from_be_bytes(key);
  const auto key1 = ascon_utils::from_be_bytes(key + 8);

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

  ascon_perm::permute<a>(state);

  ascon_utils::to_be_bytes(state[3] ^ key0, tag);
  ascon_utils::to_be_bytes(state[4] ^ key1, tag + 8);
}

// Ascon-80pq finalization step, generates 128 -bit tag; taken from
// section 2.4.4 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t a, const size_t rate>
static inline const ascon::tag_t
finalize(uint64_t* const state,
         const ascon::secret_key_160_t& k // 160 -bit secret key
         )
  requires(rate == 64)
{
  state[1] ^= k.limbs[0];
  state[2] ^= k.limbs[1];
  state[3] ^= k.limbs[2] << 32;

  ascon_perm::permute<a>(state);

  // keeps 32 to 63 -bits of 160 -bit secret key, on upper 32 -bits of
  // 64 -bit unsigned integer
  const uint64_t tmp0 = (k.limbs[0] & 0xfffffffful) << 32;
  // keeps 64 to 95 -bits of 160 -bit secret key, on lower 32 -bits of
  // 64 -bit unsigned integer
  const uint64_t tmp1 = k.limbs[1] >> 32;

  // keeps 96 to 127 -bits of 160 -bit secret key, on upper 32 -bits of
  // 64 -bit unsigned integer
  const uint64_t tmp2 = (k.limbs[1] & 0xfffffffful) << 32;
  // secret key's last 32 -bits ( i.e. from bit 128 to 159 ) are placed on lower
  // 32 -bits of 64 -bit unsigned integer
  const uint64_t tmp3 = k.limbs[2] & 0xfffffffful;

  // last 128 -bits of secret key, as two 64 -bit words
  const uint64_t k_64_a = tmp0 | tmp1;
  const uint64_t k_64_b = tmp2 | tmp3;

  return { state[3] ^ k_64_a, state[4] ^ k_64_b };
}

}
