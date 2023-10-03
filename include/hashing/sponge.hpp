#pragma once
#include "ascon_perm.hpp"
#include "utils.hpp"
#include <algorithm>
#include <array>
#include <cstdint>

// Common functions required for implementing sponge-based hash functions.
namespace sponge {

// Common bit width for RATE portion of sponge.
constexpr size_t RATE_BITS = 64;

// Compile-time compute initial 320 -bit Ascon permutation state, used for Ascon based
// hashing schemes, following description in section 2.5.1 of Ascon v1.2 spec.
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf.
constexpr ascon_perm::ascon_perm_t
compute_init_state(const uint64_t iv)
{
  ascon_perm::ascon_perm_t state({ iv, 0, 0, 0, 0 });
  state.permute<ascon_perm::MAX_ROUNDS>();
  return state;
}

// Given `mlen` (>=0) -bytes message, this routine consumes it into RATE portion
// of Ascon permutation state, s.t. `offset` ( second parameter ) denotes how
// many bytes are already consumed into RATE portion of the state.
//
// - `rate` portion of sponge will have bitwidth = 64.
// - `offset` must ∈ [0, `rbytes`).
//
// One may invoke this function arbitrary many times, for absorbing arbitrary
// many message bytes, until permutation state is finalized.
template<const size_t rounds_b, const size_t rate>
static inline constexpr void
absorb(ascon_perm::ascon_perm_t& state, size_t& offset, std::span<const uint8_t> msg)
  requires(rate == RATE_BITS)
{
  constexpr size_t rbytes = rate / 8;
  const size_t mlen = msg.size();

  std::array<uint8_t, rbytes> block{};
  auto _block = std::span(block);

  const size_t blk_cnt = (offset + mlen) / rbytes;
  size_t moff = 0;

  for (size_t i = 0; i < blk_cnt; i++) {
    const size_t readable = rbytes - offset;

    auto __block = _block.subspan(0, offset);
    std::fill(__block.begin(), __block.end(), 0x00);

    auto _msg = msg.subspan(moff, readable);
    std::copy(_msg.begin(), _msg.end(), _block.subspan(offset, readable).begin());

    const auto word = ascon_utils::from_be_bytes<uint64_t>(_block);
    state[0] ^= word;

    moff += readable;

    state.permute<rounds_b>();
    offset = 0;
  }

  const size_t rm_bytes = mlen - moff;
  auto _msg = msg.subspan(moff, rm_bytes);

  std::fill(_block.begin(), _block.end(), 0x00);
  std::copy(_msg.begin(), _msg.end(), _block.subspan(offset, rm_bytes).begin());

  const auto word = ascon_utils::from_be_bytes<uint64_t>(_block);
  state[0] ^= word;

  offset += rm_bytes;
}

// Given arbitrary many message bytes are already absorbed into RATE portion of
// Ascon permutation state, this routine finalizes sponge state and makes it
// ready for squeezing.
//
// - `rate` portion of sponge will have bitwidth = 64.
// - `offset` must ∈ [0, `rbytes`).
//
// Once Ascon permutation state is finalized, it can't absorb any more message
// bytes, though you can squeeze output bytes from it.
template<const size_t rounds_a, const size_t rate>
static inline constexpr void
finalize(ascon_perm::ascon_perm_t& state, size_t& offset)
  requires(rate == RATE_BITS)
{
  constexpr size_t rbytes = rate / 8;

  const size_t pad_bytes = rbytes - offset;
  const size_t pad_bits = pad_bytes * 8;
  const uint64_t pad_mask = 1ull << (pad_bits - 1);

  state[0] ^= pad_mask;
  state.permute<rounds_a>();

  offset = 0;
}

// Given that sponge state is already finalized, this routine can be invoked for
// squeezing `olen` -bytes out of rate portion of the Ascon permutation state.
//
// - `rate` portion of sponge will have bitwidth = 64.
// - `readable` denotes how many bytes can be squeezed without permutating the
// sponge state.
// - When `readable` becomes 0, sponge state needs to be permutated again, after
// which `rbytes` can again be squeezed from rate portion of the state.
template<const size_t rounds_b, const size_t rate>
static inline constexpr void
squeeze(ascon_perm::ascon_perm_t& state, size_t& readable, std::span<uint8_t> out)
  requires(rate == RATE_BITS)
{
  constexpr size_t rbytes = rate / 8;

  std::array<uint8_t, rbytes> block{};
  auto _block = std::span(block);

  const size_t olen = out.size();

  size_t ooff = 0;
  while (ooff < olen) {
    const size_t elen = std::min(readable, olen - ooff);
    const size_t soff = rbytes - readable;

    ascon_utils::to_be_bytes(state[0], _block);

    auto _out = out.subspan(ooff, elen);
    auto __block = _block.subspan(soff, elen);
    std::copy(__block.begin(), __block.end(), _out.begin());

    readable -= elen;
    ooff += elen;

    if (readable == 0) {
      state.permute<rounds_b>();
      readable = rbytes;
    }
  }
}

}
