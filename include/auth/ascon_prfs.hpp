#pragma once
#include "ascon_perm.hpp"
#include "utils.hpp"

// Ascon-PRFShort
namespace ascon_prfs {

// Ascon permutation instance that needs to be applied.
constexpr size_t ROUNDS_A = 12;

// Maximum byte length of message, that can be absorbed into Ascon-PRFShort.
constexpr size_t MAX_MSG_LEN = 16;

// Maximum byte length of tag, that can be squeezed from Ascon-PRFShort.
constexpr size_t MAX_TAG_LEN = 16;

// Bit width of RATE portion of Ascon permutation, when absorbing.
constexpr size_t IN_RATE = MAX_MSG_LEN * 8;

// Bit width of RATE portion of Ascon permutation, when squeezing.
constexpr size_t OUT_RATE = MAX_TAG_LEN * 8;

// Byte length of Ascon-PRFShort secret key.
constexpr size_t KEY_LEN = 16;

// Compile-time compute initialization value for Ascon-PRFShort, following
// section 2.6 ( page 7 ) of spec. https://eprint.iacr.org/2021/1574.pdf.
constexpr uint64_t IV =
  ((KEY_LEN * 8) << 56) |           // 8 -bit wide, bit length of secret key
  (0b00000000ul << 48) |            // 8 -bit wide, message bit length, not yet filled
  (((1ul << 6) ^ ROUNDS_A) << 40) | // 8 -bit wide, round number as 2^6 ⊕ a
  (OUT_RATE << 32)                  // 8 -bit wide, bit width of output block
  // 32 zero bits
  ;

// Short-input pseudo-random function, which can be used for computing a <=16
// -bytes authentication tag, for an input message of length at max 16 -bytes,
// given a 16 -bytes secret key.
//
// This routine is an implementation of algorithm 3 of spec.
// https://eprint.iacr.org/2021/1574.pdf.
inline void
prf_short(std::span<const uint8_t, KEY_LEN> key, // 16 -bytes secret key
          std::span<const uint8_t> msg,          // Input message
          std::span<uint8_t> tag                 // <=16 -bytes Authentication tag
)
{
  std::array<uint8_t, IN_RATE / 8> rate{};
  auto _rate = std::span(rate);

  const size_t mlen = msg.size();
  const size_t tlen = tag.size();

  std::memcpy(_rate.data(), msg.data(), mlen);
  std::memset(_rate.subspan(mlen).data(), 0x00, _rate.size() - mlen);

  const uint64_t key0 = ascon_utils::from_be_bytes<uint64_t>(key.subspan<0, 8>());
  const uint64_t key1 = ascon_utils::from_be_bytes<uint64_t>(key.subspan<8, 8>());

  ascon_perm::ascon_perm_t state;

  state[0] = IV ^ ((mlen * 8) << 48);
  state[1] = key0;
  state[2] = key1;
  state[3] = ascon_utils::from_be_bytes<uint64_t>(_rate.subspan<0, 8>());
  state[4] = ascon_utils::from_be_bytes<uint64_t>(_rate.subspan<8, 8>());

  state.permute<ROUNDS_A>();

  state[3] ^= key0;
  state[4] ^= key1;

  ascon_utils::to_be_bytes(state[3], _rate.subspan<0, 8>());
  ascon_utils::to_be_bytes(state[4], _rate.subspan<8, 8>());

  const size_t off = MAX_TAG_LEN - tlen;
  std::memcpy(tag.data(), _rate.subspan(off).data(), tlen);
}

// Authenticates at max 16 -bytes input message, by absorbing it into RATE
// portion of Ascon permutation state, while computing a 16 -bytes
// authentication tag, when a 16 -bytes secret key is provided as input.
inline void
prfs_authenticate(std::span<const uint8_t, KEY_LEN> key, // 16 -bytes key
                  std::span<const uint8_t> msg, // Input message, to be authenticated
                  std::span<uint8_t, MAX_TAG_LEN> tag // 16 -bytes tag, to be computed
)
{
  prf_short(key, msg, tag);
}

// Verifies 16 -bytes authentication tag, for a message of byte length at max
// 16, by (constant-time) comparing received tag with (function) locally
// computed tag, given 16 -bytes secret key. Returns boolean truth value,
// denoting successful tag comparison, while false value is returned, otherwise.
inline bool
prfs_verify(std::span<const uint8_t, KEY_LEN> key, // 16 -bytes key
            std::span<const uint8_t> msg,          // Input message, to be authenticated
            std::span<const uint8_t, MAX_TAG_LEN> tag // 16 -bytes tag, to be verified
)
{
  std::array<uint8_t, MAX_TAG_LEN> computed_tag{};
  auto _computed_tag = std::span(computed_tag);

  prf_short(key, msg, _computed_tag);

  auto _const_computed_tag = std::span<const uint8_t, MAX_TAG_LEN>(_computed_tag);
  return ascon_utils::ct_eq_byte_array(tag, _const_computed_tag);
}

}
