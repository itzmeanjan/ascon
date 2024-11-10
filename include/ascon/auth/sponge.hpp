#pragma once
#include "ascon/ascon_perm.hpp"
#include "ascon/utils.hpp"
#include <array>
#include <span>

// Common functions used for implementing Ascon based authentication schemes
// such as PRF and MAC.
namespace ascon_auth {

// 320 -bit Ascon permutation state is initialized by applying a 12 -rounds
// Ascon permutation on compile-time computed 64 -bit initialization value and
// 128 -bit ( i.e. 16 -bytes ) secret key, following section 2.4.1 of spec.
// https://eprint.iacr.org/2021/1574.pdf. Initialized permutation state can be
// used for Ascon based authentication scheme.
template<const size_t rounds_a,     // a -rounds permutation p^a | a <= 12
         const size_t in_rate,      // in bits
         const size_t out_rate,     // in bits
         const size_t klen,         // key length, in bits
         const uint32_t max_out_len // max. output length, in bits
         >
static inline constexpr void
initialize(ascon_perm::ascon_perm_t& state, std::span<const uint8_t, klen / 8> key)
  requires((klen == 128) && (rounds_a == ascon_perm::ASCON_PERMUTATION_MAX_ROUNDS))
{
  // Compile-time compute initialization value
  constexpr uint64_t iv = (klen << 56) |                    // 8 -bit wide bit length of secret key
                          (out_rate << 48) |                // 8 -bit wide bit length of output rate
                          (((1ul << 7) ^ rounds_a) << 40) | // 8 -bit wide, 2^7 ⊕ a
                          (0b00000000ull << 32) |           // 8 zero bits
                          max_out_len                       // 32 -bit wide max. output bit length
    ;

  state[0] = iv;
  state[1] = ascon_utils::from_be_bytes<uint64_t>(key.template subspan<0, 8>());
  state[2] = ascon_utils::from_be_bytes<uint64_t>(key.template subspan<8, 8>());
  state[3] = 0;
  state[4] = 0;

  state.permute<rounds_a>();
}

// Absorbs arbitrary many message bytes into RATE portion of Ascon permutation
// state s.t. `offset` many bytes can already be absorbed into it. `offset` can
// have value from [0, rbytes). This routine is an implementation following
// section 2.4.2 of spec. https://eprint.iacr.org/2021/1574.pdf.
//
// One can invoke absorb routine arbitrary many times for absorbing arbitrary
// many message bytes, until the state is finalized.
template<const size_t rounds_a, // a -rounds permutation p^a | a <= 12
         const size_t rate      // in bits
         >
static inline void
absorb(ascon_perm::ascon_perm_t& state,
       size_t& offset, // ∈ [0, rbytes)
       std::span<const uint8_t> msg)
  requires((rounds_a == ascon_perm::ASCON_PERMUTATION_MAX_ROUNDS) && (rate == 256))
{
  constexpr size_t rbytes = rate / 8;
  const size_t mlen = msg.size();
  const size_t blk_cnt = (offset + mlen) / rbytes;

  std::array<uint8_t, rbytes> chunk{};
  auto _chunk = std::span(chunk);

  size_t moff = 0;

  for (size_t i = 0; i < blk_cnt; i++) {
    const size_t readable = rbytes - offset;

    std::memset(_chunk.data(), 0x00, offset);
    std::memcpy(_chunk.subspan(offset).data(), msg.subspan(moff).data(), readable);

    auto _chunk0 = _chunk.template subspan<0, 8>();
    auto _chunk1 = _chunk.template subspan<8, 8>();
    auto _chunk2 = _chunk.template subspan<16, 8>();
    auto _chunk3 = _chunk.template subspan<24, 8>();

    const auto word0 = ascon_utils::from_be_bytes<uint64_t>(_chunk0);
    const auto word1 = ascon_utils::from_be_bytes<uint64_t>(_chunk1);
    const auto word2 = ascon_utils::from_be_bytes<uint64_t>(_chunk2);
    const auto word3 = ascon_utils::from_be_bytes<uint64_t>(_chunk3);

    state[0] ^= word0;
    state[1] ^= word1;
    state[2] ^= word2;
    state[3] ^= word3;

    moff += (rbytes - offset);

    state.permute<rounds_a>();
    offset = 0;
  }

  const size_t rm_bytes = mlen - moff;

  std::memset(_chunk.data(), 0x00, rbytes);
  std::memcpy(_chunk.subspan(offset).data(), msg.subspan(moff).data(), rm_bytes);

  auto _chunk0 = _chunk.template subspan<0, 8>();
  auto _chunk1 = _chunk.template subspan<8, 8>();
  auto _chunk2 = _chunk.template subspan<16, 8>();
  auto _chunk3 = _chunk.template subspan<24, 8>();

  const auto word0 = ascon_utils::from_be_bytes<uint64_t>(_chunk0);
  const auto word1 = ascon_utils::from_be_bytes<uint64_t>(_chunk1);
  const auto word2 = ascon_utils::from_be_bytes<uint64_t>(_chunk2);
  const auto word3 = ascon_utils::from_be_bytes<uint64_t>(_chunk3);

  state[0] ^= word0;
  state[1] ^= word1;
  state[2] ^= word2;
  state[3] ^= word3;

  offset += rm_bytes;
}

// Given that arbitrary many message bytes are already absorbed into RATE
// portion of Ascon permutation state, this function can be used for finalizing
// it so that it becomes ready for squeezing. This is an implementation,
// following section 2.4.2 and (last message block absorption step of) algorithm
// 1 of spec. https://eprint.iacr.org/2021/1574.pdf.
template<const size_t rounds_a, // a -rounds permutation p^a | a <= 12
         const size_t rate      // in bits
         >
static inline void
finalize(ascon_perm::ascon_perm_t& state,
         size_t& offset // ∈ [0, rbytes)
         )
  requires((rounds_a == ascon_perm::ASCON_PERMUTATION_MAX_ROUNDS) && (rate == 256))
{
  constexpr size_t rbytes = rate / 8;

  std::array<uint8_t, rbytes> chunk{};
  auto _chunk = std::span(chunk);

  std::memset(_chunk.data(), 0x00, rbytes);
  std::memset(_chunk.subspan(offset).data(), 0x80, 1);

  auto _chunk0 = _chunk.template subspan<0, 8>();
  auto _chunk1 = _chunk.template subspan<8, 8>();
  auto _chunk2 = _chunk.template subspan<16, 8>();
  auto _chunk3 = _chunk.template subspan<24, 8>();

  state[0] ^= ascon_utils::from_be_bytes<uint64_t>(_chunk0);
  state[1] ^= ascon_utils::from_be_bytes<uint64_t>(_chunk1);
  state[2] ^= ascon_utils::from_be_bytes<uint64_t>(_chunk2);
  state[3] ^= ascon_utils::from_be_bytes<uint64_t>(_chunk3);
  state[4] ^= 1;

  state.permute<rounds_a>();
  offset = 0;
}

// Given that message bytes are already absorbed into Ascon permutation state,
// which is also finalized, this routine can be used for squeezing arbitrary
// many mesasge bytes ( i.e. authentication tag ), from RATE portion of Ascon
// permutation. This is an implementation, following section 2.4.3 of spec.
// https://eprint.iacr.org/2021/1574.pdf.
template<const size_t rounds_a, // a -rounds permutation p^a | a <= 12
         const size_t rate      // in bits
         >
static inline void
squeeze(ascon_perm::ascon_perm_t& state,
        size_t& readable, // ∈ [0, rbytes)
        std::span<uint8_t> out)
  requires((rounds_a == ascon_perm::ASCON_PERMUTATION_MAX_ROUNDS) && (rate == 128))
{
  constexpr size_t rbytes = rate / 8;

  std::array<uint8_t, rbytes> chunk{};
  auto _chunk = std::span(chunk);

  const size_t olen = out.size();
  size_t ooff = 0;

  while (ooff < olen) {
    const size_t elen = std::min(readable, olen - ooff);
    const size_t soff = rbytes - readable;

    ascon_utils::to_be_bytes(state[0], _chunk.template subspan<0, 8>());
    ascon_utils::to_be_bytes(state[1], _chunk.template subspan<8, 8>());

    std::memcpy(out.subspan(ooff).data(), _chunk.subspan(soff).data(), elen);

    readable -= elen;
    ooff += elen;

    if (readable == 0) {
      state.permute<rounds_a>();
      readable = rbytes;
    }
  }
}

}
