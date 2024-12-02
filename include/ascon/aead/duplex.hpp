#pragma once
#include "ascon/permutation/ascon.hpp"
#include "ascon/utils/common.hpp"
#include "ascon/utils/force_inline.hpp"
#include <algorithm>
#include <array>
#include <limits>

namespace ascon_duplex_mode {

// See table 12 of Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
static constexpr uint8_t UNIQUE_ALGORITHM_ID = 1;

static constexpr size_t ASCON_PERM_NUM_ROUNDS_A = 12;
static constexpr size_t ASCON_PERM_NUM_ROUNDS_B = 8;

static constexpr size_t BIT_SECURITY_LEVEL = 128;
static constexpr size_t RATE_BITS = BIT_SECURITY_LEVEL;
static constexpr size_t RATE_BYTES = RATE_BITS / std::numeric_limits<uint8_t>::digits;

static constexpr size_t KEY_BYTE_LEN = BIT_SECURITY_LEVEL / std::numeric_limits<uint8_t>::digits;
static constexpr size_t NONCE_BYTE_LEN = BIT_SECURITY_LEVEL / std::numeric_limits<uint8_t>::digits;
static constexpr size_t TAG_BYTE_LEN = BIT_SECURITY_LEVEL / std::numeric_limits<uint8_t>::digits;

// Initialize Ascon permutation state with 16 -bytes key and nonce.
// See point 1 of section 4.1.1 in Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
forceinline constexpr void
initialize(ascon_perm::ascon_perm_t& state, std::span<const uint8_t, KEY_BYTE_LEN> key, std::span<const uint8_t, NONCE_BYTE_LEN> nonce)
{
  const auto key_first = ascon_common_utils::from_le_bytes(key.first<8>());
  const auto key_last = ascon_common_utils::from_le_bytes(key.last<8>());

  state[0] = ascon_common_utils::compute_iv(UNIQUE_ALGORITHM_ID, ASCON_PERM_NUM_ROUNDS_A, ASCON_PERM_NUM_ROUNDS_B, TAG_BYTE_LEN * 8, RATE_BYTES);
  state[1] = key_first;
  state[2] = key_last;
  state[3] = ascon_common_utils::from_le_bytes(nonce.first<8>());
  state[4] = ascon_common_utils::from_le_bytes(nonce.last<8>());

  state.permute<ASCON_PERM_NUM_ROUNDS_A>();

  state[3] ^= key_first;
  state[4] ^= key_last;
}

// Absorbs arbitrary length associated data into Ascon permutation state; also adds the domain separation bit.
// See point 2 of section 4.1.1 in Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
forceinline constexpr void
process_associated_data(ascon_perm::ascon_perm_t& state, std::span<const uint8_t> data)
{
  const size_t dlen = data.size();

  if (dlen > 0) {
    const size_t total_num_blocks = (dlen + 1 + (RATE_BYTES - 1)) / RATE_BYTES;

    std::array<uint8_t, RATE_BYTES> chunk{};
    auto chunk_span = std::span(chunk);

    // Process full message blocks, expect the last one, which is padded.
    for (size_t block_index = 0; block_index < total_num_blocks - 1; block_index++) {
      (void)ascon_common_utils::get_ith_msg_blk(data, block_index, chunk_span);

      state[0] ^= ascon_common_utils::from_le_bytes(chunk_span.first<8>());
      state[1] ^= ascon_common_utils::from_le_bytes(chunk_span.last<8>());

      state.permute<ASCON_PERM_NUM_ROUNDS_B>();
    }

    // Process last message block, which is padded.
    const size_t final_block_index = total_num_blocks - 1;

    const size_t read = ascon_common_utils::get_ith_msg_blk(data, final_block_index, chunk_span);
    ascon_common_utils::pad_msg_blk(chunk_span, read);

    state[0] ^= ascon_common_utils::from_le_bytes(chunk_span.first<8>());
    state[1] ^= ascon_common_utils::from_le_bytes(chunk_span.last<8>());

    state.permute<ASCON_PERM_NUM_ROUNDS_B>();
  }

  // final 1 -bit domain seperator constant mixing is mandatory
  state[4] ^= 0b1ul;
}

// Encrypts arbitrary length plain text, producing equal length cipher text.
// See point 3 of section 4.1.1 in Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
forceinline constexpr void
process_plaintext(ascon_perm::ascon_perm_t& state, std::span<const uint8_t> text, std::span<uint8_t> cipher)
{
  const size_t ctlen = text.size();
  const size_t total_num_blocks = (ctlen + 1 + (RATE_BYTES - 1)) / RATE_BYTES;

  std::array<uint8_t, RATE_BYTES> chunk{};
  auto chunk_span = std::span(chunk);

  using span_8bytes_t = std::span<uint8_t, 8>;
  size_t off = 0;

  // Process full message blocks, expect the last one, which is padded.
  for (size_t block_index = 0; block_index < total_num_blocks - 1; block_index++) {
    (void)ascon_common_utils::get_ith_msg_blk(text, block_index, chunk_span);

    state[0] ^= ascon_common_utils::from_le_bytes(chunk_span.first<8>());
    state[1] ^= ascon_common_utils::from_le_bytes(chunk_span.last<8>());

    ascon_common_utils::to_le_bytes(state[0], span_8bytes_t(cipher.subspan(off, 8)));
    ascon_common_utils::to_le_bytes(state[1], span_8bytes_t(cipher.subspan(off + 8, 8)));

    state.permute<ASCON_PERM_NUM_ROUNDS_B>();
    off += RATE_BYTES;
  }

  // Process last message block, which is padded.
  const size_t final_block_index = total_num_blocks - 1;

  const size_t read = ascon_common_utils::get_ith_msg_blk(text, final_block_index, chunk_span);
  ascon_common_utils::pad_msg_blk(chunk_span, read);

  state[0] ^= ascon_common_utils::from_le_bytes(chunk_span.first<8>());
  state[1] ^= ascon_common_utils::from_le_bytes(chunk_span.last<8>());

  ascon_common_utils::to_le_bytes(state[0], chunk_span.first<8>());
  ascon_common_utils::to_le_bytes(state[1], chunk_span.last<8>());

  std::copy_n(chunk_span.begin(), read, cipher.subspan(off).begin());
}

// Decrypts arbitrary length cipher text, producing equal length plain text.
// See point 3 of section 4.1.2 in Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
forceinline constexpr void
process_ciphertext(ascon_perm::ascon_perm_t& state, std::span<const uint8_t> cipher, std::span<uint8_t> text)
{
  const size_t ctlen = cipher.size();
  const size_t total_num_blocks = (ctlen + 1 + (RATE_BYTES - 1)) / RATE_BYTES;

  std::array<uint8_t, RATE_BYTES> chunk{};
  auto chunk_span = std::span(chunk);

  using span_8bytes_t = std::span<uint8_t, 8>;
  size_t off = 0;

  // Process full message blocks, expect the last one, which is padded.
  for (size_t block_index = 0; block_index < total_num_blocks - 1; block_index++) {
    (void)ascon_common_utils::get_ith_msg_blk(cipher, block_index, chunk_span);

    const auto ct_first_word = ascon_common_utils::from_le_bytes(chunk_span.first<8>());
    const auto ct_last_word = ascon_common_utils::from_le_bytes(chunk_span.last<8>());

    const uint64_t pt_first_word = state[0] ^ ct_first_word;
    const uint64_t pt_last_word = state[1] ^ ct_last_word;

    state[0] = ct_first_word;
    state[1] = ct_last_word;

    ascon_common_utils::to_le_bytes(pt_first_word, span_8bytes_t(text.subspan(off, 8)));
    ascon_common_utils::to_le_bytes(pt_last_word, span_8bytes_t(text.subspan(off + 8, 8)));

    state.permute<ASCON_PERM_NUM_ROUNDS_B>();
    off += RATE_BYTES;
  }

  // Process last message block, which is padded.
  const size_t final_block_index = total_num_blocks - 1;

  const size_t read = ascon_common_utils::get_ith_msg_blk(cipher, final_block_index, chunk_span);
  std::fill_n(chunk_span.subspan(read).begin(), RATE_BYTES - read, 0);

  const uint64_t ct_first_word = ascon_common_utils::from_le_bytes(chunk_span.first<8>());
  const uint64_t ct_last_word = ascon_common_utils::from_le_bytes(chunk_span.last<8>());

  const uint64_t pt_first_word = state[0] ^ ct_first_word;
  const uint64_t pt_last_word = state[1] ^ ct_last_word;

  ascon_common_utils::to_le_bytes(pt_first_word, chunk_span.first<8>());
  ascon_common_utils::to_le_bytes(pt_last_word, chunk_span.last<8>());
  std::copy_n(chunk_span.begin(), read, text.subspan(off).begin());

  ascon_common_utils::pad_msg_blk(chunk_span, read);

  state[0] ^= ascon_common_utils::from_le_bytes(chunk_span.first<8>());
  state[1] ^= ascon_common_utils::from_le_bytes(chunk_span.last<8>());
}

// Finalizes the Ascon permutation state, producing 16 -bytes authentication tag.
// See point 4 of section 4.1.1 in Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
forceinline constexpr void
finalize(ascon_perm::ascon_perm_t& state, std::span<const uint8_t, KEY_BYTE_LEN> key, std::span<uint8_t, TAG_BYTE_LEN> tag)
{
  const auto key_first = ascon_common_utils::from_le_bytes(key.first<8>());
  const auto key_last = ascon_common_utils::from_le_bytes(key.last<8>());

  state[2] ^= key_first;
  state[3] ^= key_last;

  state.permute<ASCON_PERM_NUM_ROUNDS_A>();

  ascon_common_utils::to_le_bytes(state[3] ^ key_first, tag.first<8>());
  ascon_common_utils::to_le_bytes(state[4] ^ key_last, tag.last<8>());
}

}
