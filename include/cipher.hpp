#pragma once
#include "permutation.hpp"
#include "utils.hpp"

namespace ascon {

// Ascon-128 initial state value ( only first 64 -bits ); taken from
// section 2.4.1 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint64_t ASCON_128_IV = 0X80400c0600000000ul;

// Ascon-128a initial state value ( only first 64 -bits ); taken from
// section 2.4.1 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint64_t ASCON_128a_IV = 0x80800c0800000000ul;

// = (1 << 64) - 1; maximum number that can be represented using 64 -bits
constexpr uint64_t MAX_ULONG = 0xfffffffffffffffful;

// 128 -bit Ascon secret key, used for authenticated encryption/ decryption;
// see table 1 in section 2.2 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
struct secret_key_t
{
  uint64_t limbs[2];
};

// 128 -bit Ascon nonce, used for authenticated encryption/ decryption
// see table 1 in section 2.2 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
struct nonce_t
{
  uint64_t limbs[2];
};

// 128 -bit tag, generated in finalization step of Ascon-128/128a; see table 1
// in section 2.2 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
struct tag_t
{
  uint64_t limbs[2];
};

// Initialize cipher state for Ascon authenticated encryption/ decryption;
// see section 2.4.1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
//
// # -of rounds `a` should be 12 for both Ascon-128 & Ascon-128a, though still
// it's parameterized
template<const uint64_t IV, const size_t a>
static inline void
initialize(uint64_t* const state, // uninitialized hash state
           const secret_key_t& k, // 128 -bit secret key
           const nonce_t& n       // 128 -bit nonce
           ) requires(check_a(a))
{
  state[0] = IV;
  state[1] = k.limbs[0];
  state[2] = k.limbs[1];
  state[3] = n.limbs[0];
  state[4] = n.limbs[1];

  p_a<a>(state);

  state[3] ^= k.limbs[0];
  state[4] ^= k.limbs[1];
}

// Pad associated data/ plain text, when rate = 64, such that padded data/ plain
// text (bit-) length is evenly divisible by rate ( = 64 ).
//
// See Ascon-128 padding rule in section 2.4.{2,3} of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline const uint64_t
pad_data(const uint8_t* const data, const size_t pad_byte_len)
{
  uint64_t data_blk;

  switch (pad_byte_len) {
    case 8:
      data_blk = 0b1ul << 63 /* padding: '1' ++ '0' <63 bits> */;
      break;
    case 7:
      data_blk = (static_cast<uint64_t>(data[0]) << 56) |
                 (0b1ul << 55) /* padding: '1' ++ '0' <55 bits> */;
      break;
    case 6:
      data_blk = (static_cast<uint64_t>(data[0]) << 56) |
                 (static_cast<uint64_t>(data[1]) << 48) |
                 (0b1ul << 47) /* padding: '1' ++ '0' <47 bits> */;
      break;
    case 5:
      data_blk = (static_cast<uint64_t>(data[0]) << 56) |
                 (static_cast<uint64_t>(data[1]) << 48) |
                 (static_cast<uint64_t>(data[2]) << 40) |
                 (0b1ul << 39) /* padding: '1' ++ '0' <39 bits> */;
      break;
    case 4:
      data_blk = (static_cast<uint64_t>(data[0]) << 56) |
                 (static_cast<uint64_t>(data[1]) << 48) |
                 (static_cast<uint64_t>(data[2]) << 40) |
                 (static_cast<uint64_t>(data[3]) << 32) |
                 (0b1ul << 31) /* padding: '1' ++ '0' <31 bits> */;
      break;
    case 3:
      data_blk = (static_cast<uint64_t>(data[0]) << 56) |
                 (static_cast<uint64_t>(data[1]) << 48) |
                 (static_cast<uint64_t>(data[2]) << 40) |
                 (static_cast<uint64_t>(data[3]) << 32) |
                 (static_cast<uint64_t>(data[4]) << 24) |
                 (0b1ul << 23) /* padding: '1' ++ '0' <23 bits> */;
      break;
    case 2:
      data_blk = (static_cast<uint64_t>(data[0]) << 56) |
                 (static_cast<uint64_t>(data[1]) << 48) |
                 (static_cast<uint64_t>(data[2]) << 40) |
                 (static_cast<uint64_t>(data[3]) << 32) |
                 (static_cast<uint64_t>(data[4]) << 24) |
                 (static_cast<uint64_t>(data[5]) << 16) |
                 (0b1ul << 15) /* padding: '1' ++ '0' <15 bits> */;
      break;
    case 1:
      data_blk = (static_cast<uint64_t>(data[0]) << 56) |
                 (static_cast<uint64_t>(data[1]) << 48) |
                 (static_cast<uint64_t>(data[2]) << 40) |
                 (static_cast<uint64_t>(data[3]) << 32) |
                 (static_cast<uint64_t>(data[4]) << 24) |
                 (static_cast<uint64_t>(data[5]) << 16) |
                 (static_cast<uint64_t>(data[6]) << 8) |
                 (0b1ul << 7) /* padding: '1' ++ '0' <7 bits> */;
      break;
  }

  return data_blk;
}

// Pad associated data/ plain text, when rate = 128, such that padded data/
// plain text (bit-) length is evenly divisible by rate ( = 128 ).
//
// See Ascon-128a padding rule in section 2.4.{2,3} of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline void
pad_data(const uint8_t* const data,
         const size_t pad_byte_len,
         uint64_t* const data_blk)
{
  switch (pad_byte_len) {
    case 16:
      data_blk[0] = 0b1ul << 63 /* padding: '1' ++ '0' <63 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 15:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (0b1ul << 55) /* padding: '1' ++ '0' <55 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 14:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (0b1ul << 47) /* padding: '1' ++ '0' <47 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 13:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (0b1ul << 39) /* padding: '1' ++ '0' <39 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 12:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (0b1ul << 31) /* padding: '1' ++ '0' <31 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 11:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (0b1ul << 23) /* padding: '1' ++ '0' <23 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 10:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (0b1ul << 15) /* padding: '1' ++ '0' <15 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 9:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    (0b1ul << 7) /* padding: '1' ++ '0' <7 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 8:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = 0b1ul << 63 /* padding: '1' ++ '0' <63 bits> */;
      break;
    case 7:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = (static_cast<uint64_t>(data[8]) << 56) |
                    (0b1ul << 55) /* padding: '1' ++ '0' <55 bits> */;
      break;
    case 6:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = (static_cast<uint64_t>(data[8]) << 56) |
                    (static_cast<uint64_t>(data[9]) << 48) |
                    (0b1ul << 47) /* padding: '1' ++ '0' <47 bits> */;
      break;
    case 5:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = (static_cast<uint64_t>(data[8]) << 56) |
                    (static_cast<uint64_t>(data[9]) << 48) |
                    (static_cast<uint64_t>(data[10]) << 40) |
                    (0b1ul << 39) /* padding: '1' ++ '0' <39 bits> */;
      break;
    case 4:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = (static_cast<uint64_t>(data[8]) << 56) |
                    (static_cast<uint64_t>(data[9]) << 48) |
                    (static_cast<uint64_t>(data[10]) << 40) |
                    (static_cast<uint64_t>(data[11]) << 32) |
                    (0b1ul << 31) /* padding: '1' ++ '0' <31 bits> */;
      break;
    case 3:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = (static_cast<uint64_t>(data[8]) << 56) |
                    (static_cast<uint64_t>(data[9]) << 48) |
                    (static_cast<uint64_t>(data[10]) << 40) |
                    (static_cast<uint64_t>(data[11]) << 32) |
                    (static_cast<uint64_t>(data[12]) << 24) |
                    (0b1ul << 23) /* padding: '1' ++ '0' <23 bits> */;
      break;
    case 2:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = (static_cast<uint64_t>(data[8]) << 56) |
                    (static_cast<uint64_t>(data[9]) << 48) |
                    (static_cast<uint64_t>(data[10]) << 40) |
                    (static_cast<uint64_t>(data[11]) << 32) |
                    (static_cast<uint64_t>(data[12]) << 24) |
                    (static_cast<uint64_t>(data[13]) << 16) |
                    (0b1ul << 15) /* padding: '1' ++ '0' <15 bits> */;
      break;
    case 1:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = (static_cast<uint64_t>(data[8]) << 56) |
                    (static_cast<uint64_t>(data[9]) << 48) |
                    (static_cast<uint64_t>(data[10]) << 40) |
                    (static_cast<uint64_t>(data[11]) << 32) |
                    (static_cast<uint64_t>(data[12]) << 24) |
                    (static_cast<uint64_t>(data[13]) << 16) |
                    (static_cast<uint64_t>(data[14]) << 8) |
                    (0b1ul << 7) /* padding: '1' ++ '0' <7 bits> */;
      break;
  }
}

// Compile-time check rate bit length for Ascon-128 & Ascon-128a; see table 1 of
// Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline constexpr bool
check_r(const size_t r)
{
  return r == 64 || r == 128;
}

// Process `s` -many blocks of associated data, each of with rate ( = {64, 128}
// ) -bits; see section 2.4.2 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t b, const size_t r>
static inline void
process_associated_data(uint64_t* const __restrict state,
                        const uint8_t* const __restrict data, // associated data
                        const size_t data_len // in terms of bytes
                        ) requires(check_b(b) && check_r(r))
{
  // only when associated data is non-empty; do padding and then mixing
  if (data_len > 0) {
    const size_t tmp = (data_len << 3) % r;
    const size_t zero_pad_len = r - 1 - tmp;
    const size_t pad_byte_len = (zero_pad_len + 1) >> 3;

    const uint8_t* data_ = data + data_len - ((r >> 3) - pad_byte_len);

    if (r == 64) {
      const uint64_t last_data_blk = pad_data(data_, pad_byte_len);

      const size_t data_blk_cnt = ((data_len + pad_byte_len) << 3) >> 6;

      for (size_t i = 0; i < data_blk_cnt - 1; i++) {
        const uint64_t data_blk = ascon_utils::from_be_bytes(data + (i << 3));

        state[0] ^= data_blk;
        p_b<b>(state);
      }

      state[0] ^= last_data_blk;
      p_b<b>(state);

    } else if (r == 128) {
      uint64_t last_data_blk[2];
      pad_data(data_, pad_byte_len, last_data_blk);

      const size_t data_blk_cnt = ((data_len + pad_byte_len) << 3) >> 7;

      for (size_t i = 0; i < data_blk_cnt - 1; i++) {
        const uint64_t data_blk_0 =
          ascon_utils::from_be_bytes(data + ((i << 1) << 3));
        const uint64_t data_blk_1 =
          ascon_utils::from_be_bytes(data + (((i << 1) + 1) << 3));

        state[0] ^= data_blk_0;
        state[1] ^= data_blk_1;
        p_b<b>(state);
      }

      state[0] ^= last_data_blk[0];
      state[1] ^= last_data_blk[1];
      p_b<b>(state);
    }
  }

  // final 1 -bit domain seperator constant mixing is mandatory
  state[4] ^= 0b1ul;
}

// Ascon-128/128a finalization step, generates 128 -bit tag; taken from
// section 2.4.4 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t a, const size_t r>
static inline const tag_t
finalize(uint64_t* const state,
         const secret_key_t& k // 128 -bit secret key
         ) requires(check_a(a) && check_r(r))
{
  if (r == 64) {
    state[1] ^= k.limbs[0];
    state[2] ^= k.limbs[1];
  } else if (r == 128) {
    state[2] ^= k.limbs[0];
    state[3] ^= k.limbs[1];
  }

  p_a<a>(state);

  // 128 -bit tag
  tag_t t;

  t.limbs[0] = state[3] ^ k.limbs[0];
  t.limbs[1] = state[4] ^ k.limbs[1];

  return t;
}

}
