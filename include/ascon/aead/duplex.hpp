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

/**
 * @brief Initializes the Ascon permutation state with the given key and nonce.
 * See point 1 of section 4.1.1 in Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
 *
 * @param state Ascon permutation state.
 * @param key Encryption key.
 * @param nonce Nonce - don't repeat it, for the same key !
 */
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

/**
 * @brief Absorbs arbitrary-length associated data into the Ascon permutation state.
 * This function can be called multiple times with different spans of associated data before calling `finalize_associated_data`.
 * See point 2 of section 4.1.1 in Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
 *
 * @param state Ascon permutation state.
 * @param block_offset Offset within the current block, must be <= `RATE_BYTES`.
 * @param data Associated data to be absorbed.
 */
forceinline constexpr void
absorb_associated_data(ascon_perm::ascon_perm_t& state, size_t& block_offset, std::span<const uint8_t> data)
{
  std::array<uint8_t, RATE_BYTES> block{};
  auto block_span = std::span(block);

  const size_t dlen = data.size();
  size_t data_offset = 0;

  while (data_offset < dlen) {
    const size_t absorbable_num_bytes = RATE_BYTES - block_offset;
    const size_t available_num_bytes = dlen - data_offset;
    const size_t to_be_absorbed_num_bytes = std::min(absorbable_num_bytes, available_num_bytes);

    std::copy_n(data.subspan(data_offset).begin(), to_be_absorbed_num_bytes, block_span.subspan(block_offset).begin());
    std::fill_n(block_span.subspan(block_offset + to_be_absorbed_num_bytes).begin(), block_span.size() - (block_offset + to_be_absorbed_num_bytes), 0);

    state[0] ^= ascon_common_utils::from_le_bytes(block_span.first<8>());
    state[1] ^= ascon_common_utils::from_le_bytes(block_span.last<8>());

    data_offset += to_be_absorbed_num_bytes;
    block_offset += to_be_absorbed_num_bytes;

    if (block_offset == RATE_BYTES) {
      state.permute<ASCON_PERM_NUM_ROUNDS_B>();
      block_offset = 0;
    }
  }
}

/**
 * @brief Finalizes the associated data absorption process by adding a 1-bit domain separator.
 * No more associated data can be absorbed after calling this function.
 * See point 2 of section 4.1.1 in Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
 *
 * @param state Ascon permutation state.
 * @param block_offset Offset within the current block, must be <= `RATE_BYTES`.
 * @param absorbed_data_byte_len The total number of bytes of associated data absorbed.
 */
forceinline constexpr void
finalize_associated_data(ascon_perm::ascon_perm_t& state, size_t& block_offset, const size_t absorbed_data_byte_len)
{
  if (absorbed_data_byte_len > 0) {
    std::array<uint8_t, RATE_BYTES> block{};
    auto block_span = std::span(block);

    block_span[block_offset] = 0x01;

    state[0] ^= ascon_common_utils::from_le_bytes(block_span.first<8>());
    state[1] ^= ascon_common_utils::from_le_bytes(block_span.last<8>());

    state.permute<ASCON_PERM_NUM_ROUNDS_B>();
    block_offset = 0;
  }

  // Final 1 -bit domain separator constant mixing is mandatory
  state[4] ^= (0b1ul << 63u);
}

/**
 * @brief Absorbs arbitrary-length plaintext into the Ascon permutation state and produces ciphertext.
 * This function can be called multiple times with different spans of plaintext before calling `finalize_ciphering`.
 * See point 3 of section 4.1.1 in Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
 *
 * @param state Ascon permutation state.
 * @param block_offset Offset within the current block, must be <= `RATE_BYTES`.
 * @param plaintext Plaintext to be absorbed.
 * @param ciphertext Ciphertext produced.
 */
forceinline constexpr void
encrypt_plaintext(ascon_perm::ascon_perm_t& state, size_t& block_offset, std::span<const uint8_t> plaintext, std::span<uint8_t> ciphertext)
{
  std::array<uint8_t, RATE_BYTES> block{};
  auto block_span = std::span(block);

  const size_t ptlen = plaintext.size();
  size_t pt_offset = 0;

  while (pt_offset < ptlen) {
    const size_t absorbable_num_bytes = RATE_BYTES - block_offset;
    const size_t remaining_num_bytes = ptlen - pt_offset;
    const size_t to_be_absorbed_num_bytes = std::min(absorbable_num_bytes, remaining_num_bytes);

    std::copy_n(plaintext.subspan(pt_offset).begin(), to_be_absorbed_num_bytes, block_span.subspan(block_offset).begin());
    std::fill_n(block_span.subspan(block_offset + to_be_absorbed_num_bytes).begin(), block_span.size() - (block_offset + to_be_absorbed_num_bytes), 0);

    state[0] ^= ascon_common_utils::from_le_bytes(block_span.first<8>());
    state[1] ^= ascon_common_utils::from_le_bytes(block_span.last<8>());

    ascon_common_utils::to_le_bytes(state[0], block_span.first<8>());
    ascon_common_utils::to_le_bytes(state[1], block_span.last<8>());

    std::copy_n(block_span.subspan(block_offset).begin(), to_be_absorbed_num_bytes, ciphertext.subspan(pt_offset).begin());

    pt_offset += to_be_absorbed_num_bytes;
    block_offset += to_be_absorbed_num_bytes;

    if (block_offset == RATE_BYTES) {
      state.permute<ASCON_PERM_NUM_ROUNDS_B>();
      block_offset = 0;
    }
  }
}

/**
 * @brief Absorbs arbitrary-length ciphertext into the Ascon permutation state and produces decrypted plaintext.
 * This function can be called multiple times with different spans of ciphertext before calling `finalize_ciphering`.
 * See point 3 of section 4.1.2 in Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
 *
 * @param state Ascon permutation state.
 * @param block_offset Offset within the current block, must be <= `RATE_BYTES`.
 * @param ciphertext Ciphertext to be decrypted.
 * @param plaintext Plaintext produced.
 */
forceinline constexpr void
decrypt_ciphertext(ascon_perm::ascon_perm_t& state, size_t& block_offset, std::span<const uint8_t> ciphertext, std::span<uint8_t> plaintext)
{
  std::array<uint8_t, RATE_BYTES> block{};
  auto block_span = std::span(block);

  const size_t ctlen = ciphertext.size();
  size_t ct_offset = 0;

  while (ct_offset < ctlen) {
    const size_t absorbable_num_bytes = RATE_BYTES - block_offset;
    const size_t remaining_num_bytes = ctlen - ct_offset;
    const size_t to_be_absorbed_num_bytes = std::min(absorbable_num_bytes, remaining_num_bytes);

    std::copy_n(ciphertext.subspan(ct_offset).begin(), to_be_absorbed_num_bytes, block_span.subspan(block_offset).begin());
    std::fill_n(block_span.subspan(block_offset + to_be_absorbed_num_bytes).begin(), block_span.size() - (block_offset + to_be_absorbed_num_bytes), 0);

    ascon_common_utils::to_le_bytes(state[0] ^ ascon_common_utils::from_le_bytes(block_span.first<8>()), block_span.first<8>());
    ascon_common_utils::to_le_bytes(state[1] ^ ascon_common_utils::from_le_bytes(block_span.last<8>()), block_span.last<8>());

    std::copy_n(block_span.subspan(block_offset).begin(), to_be_absorbed_num_bytes, plaintext.subspan(ct_offset).begin());
    std::fill_n(block_span.begin(), block_offset, 0);
    std::fill_n(block_span.subspan(block_offset + to_be_absorbed_num_bytes).begin(), block_span.size() - (block_offset + to_be_absorbed_num_bytes), 0);

    state[0] ^= ascon_common_utils::from_le_bytes(block_span.first<8>());
    state[1] ^= ascon_common_utils::from_le_bytes(block_span.last<8>());

    ct_offset += to_be_absorbed_num_bytes;
    block_offset += to_be_absorbed_num_bytes;

    if (block_offset == RATE_BYTES) {
      state.permute<ASCON_PERM_NUM_ROUNDS_B>();
      block_offset = 0;
    }
  }
}

/**
 * @brief Finalizes the plaintext/ciphertext absorption process by adding a 1-bit domain separator to be permutation state.
 * No more plaintext/ciphertext can be encrypted/decrypted after calling this function.
 * See point 3 of section 4.1.1 in Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
 *
 * @param state Ascon permutation state.
 * @param block_offset Offset within the current block, must be <= `RATE_BYTES`.
 */
forceinline constexpr void
finalize_ciphering(ascon_perm::ascon_perm_t& state, size_t& block_offset)
{
  std::array<uint8_t, RATE_BYTES> block{};
  auto block_span = std::span(block);

  block_span[block_offset] = 0x01;

  state[0] ^= ascon_common_utils::from_le_bytes(block_span.first<8>());
  state[1] ^= ascon_common_utils::from_le_bytes(block_span.last<8>());

  block_offset = 0;
}

/**
 * @brief Finalizes the Ascon permutation state and produces a tag.
 * See point 4 of section 4.1.1 in Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
 *
 * @param state Ascon permutation state.
 * @param key Key used for encryption/decryption.
 * @param tag Authentication tag produced.
 */
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
