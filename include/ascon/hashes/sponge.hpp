#pragma once
#include "ascon/permutation/ascon.hpp"
#include "ascon/utils/common.hpp"
#include "ascon/utils/force_inline.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>

namespace ascon_sponge_mode {

static constexpr size_t RATE_BITS = 64;
static constexpr size_t RATE_BYTES = RATE_BITS / std::numeric_limits<uint8_t>::digits;
static constexpr size_t ASCON_PERM_NUM_ROUNDS = 12;

// Compile-time compute initial 320 -bit Ascon permutation state, used for Ascon -based hashing schemes.
consteval ascon_perm::ascon_perm_t
compute_init_state(const uint64_t iv)
{
  ascon_perm::ascon_perm_t state({ iv, 0, 0, 0, 0 });
  state.permute<12>();
  return state;
}

// Absorbs an arbitrary-length message into the permutation state. Can be called multiple times before finalization.
forceinline constexpr void
absorb(ascon_perm::ascon_perm_t& state,
       size_t& block_offset, // Denotes how many bytes were already absorbed into the RATE portion of state, without permuting it.
       std::span<const uint8_t> msg)
{
  const size_t mlen = msg.size();

  std::array<uint8_t, RATE_BYTES> block{};
  auto block_span = std::span(block);

  const size_t total_num_blocks = (block_offset + mlen) / RATE_BYTES;
  size_t msg_offset = 0;

  for (size_t block_index = 0; block_index < total_num_blocks; block_index++) {
    const size_t readable = RATE_BYTES - block_offset;

    std::copy_n(msg.subspan(msg_offset).begin(), readable, block_span.subspan(block_offset).begin());
    state[0] ^= ascon_common_utils::from_le_bytes(block_span);

    state.permute<ASCON_PERM_NUM_ROUNDS>();

    msg_offset += readable;
    block_offset = 0;
  }

  const size_t remaining_num_bytes = mlen - msg_offset;

  std::fill(block_span.begin(), block_span.end(), 0x00);
  std::copy_n(msg.subspan(msg_offset).begin(), remaining_num_bytes, block_span.subspan(block_offset).begin());

  state[0] ^= ascon_common_utils::from_le_bytes(block_span);
  block_offset += remaining_num_bytes;
}

// Finalizes the internal state after absorbing all input messages, preparing it for squeezing.
forceinline constexpr void
finalize(ascon_perm::ascon_perm_t& state, size_t& block_offset)
{
  const size_t pad_bytes = RATE_BYTES - block_offset;
  const size_t pad_bits = pad_bytes * std::numeric_limits<uint8_t>::digits;
  const uint64_t pad_mask = 1ul << (pad_bits - 1ul);

  state[0] ^= pad_mask;
  state.permute<ASCON_PERM_NUM_ROUNDS>();

  block_offset = 0;
}

// Extracts an arbitrary-length output from the finalized permutation state. Multiple calls are permitted.
forceinline constexpr void
squeeze(ascon_perm::ascon_perm_t& state, size_t& num_squeezable_bytes, std::span<uint8_t> out)
{
  const size_t olen = out.size();

  std::array<uint8_t, RATE_BYTES> block{};
  auto block_span = std::span(block);

  size_t out_offset = 0;
  while (out_offset < olen) {
    const size_t to_be_squeezed_num_bytes = std::min(num_squeezable_bytes, olen - out_offset);
    const size_t block_offset = RATE_BYTES - num_squeezable_bytes;

    ascon_common_utils::to_le_bytes(state[0], block_span);
    std::copy_n(block_span.subspan(block_offset).begin(), to_be_squeezed_num_bytes, out.subspan(out_offset).begin());

    num_squeezable_bytes -= to_be_squeezed_num_bytes;
    out_offset += to_be_squeezed_num_bytes;

    if (num_squeezable_bytes == 0) {
      state.permute<ASCON_PERM_NUM_ROUNDS>();
      num_squeezable_bytes = RATE_BYTES;
    }
  }
}

}
