#pragma once
#include "ascon/aead/duplex.hpp"
#include "ascon/permutation/ascon.hpp"
#include "ascon/utils/common.hpp"
#include "ascon/utils/force_inline.hpp"
#include <array>
#include <cstdint>

namespace ascon_aead128 {

static constexpr size_t KEY_BYTE_LEN = ascon_duplex_mode::KEY_BYTE_LEN;
static constexpr size_t NONCE_BYTE_LEN = ascon_duplex_mode::NONCE_BYTE_LEN;
static constexpr size_t TAG_BYTE_LEN = ascon_duplex_mode::TAG_BYTE_LEN;

struct ascon_aead128_t
{
private:
  std::array<uint8_t, KEY_BYTE_LEN> key{};
  std::array<uint8_t, NONCE_BYTE_LEN> nonce{};

  ascon_perm::ascon_perm_t state{};
  size_t offset = 0;
  size_t total_absorbed_data_byte_len = 0;

  alignas(4) bool finished_absorbing_data = false;
  alignas(4) bool finished_ciphering = false;
  alignas(4) bool finished_squeezing_tag = false;

public:
  forceinline constexpr ascon_aead128_t(std::span<const uint8_t, KEY_BYTE_LEN> key, std::span<const uint8_t, NONCE_BYTE_LEN> nonce)
  {
    ascon_duplex_mode::initialize(state, key, nonce);
  }
  forceinline constexpr ~ascon_aead128_t() { this->reset(); }

  [[nodiscard]]
  forceinline constexpr bool absorb_data(std::span<const uint8_t> data)
  {
    if (finished_absorbing_data) {
      return false;
    }

    ascon_duplex_mode::absorb_associated_data(state, offset, data);
    total_absorbed_data_byte_len += data.size();

    return true;
  }

  [[nodiscard]]
  forceinline constexpr bool finalize_data()
  {
    if (finished_absorbing_data) {
      return false;
    }

    ascon_duplex_mode::finalize_associated_data(state, offset, total_absorbed_data_byte_len);
    finished_absorbing_data = true;

    return true;
  }

  [[nodiscard]]
  forceinline constexpr bool encrypt_plaintext(std::span<const uint8_t> plaintext, std::span<uint8_t> ciphertext)
  {
    if (!finished_absorbing_data || finished_ciphering) {
      return false;
    }

    ascon_duplex_mode::encrypt_plaintext(state, offset, plaintext, ciphertext);
    return true;
  }

  [[nodiscard]]
  forceinline constexpr bool decrypt_plaintext(std::span<const uint8_t> ciphertext, std::span<uint8_t> plaintext)
  {
    if (!finished_absorbing_data || finished_ciphering) {
      return false;
    }

    ascon_duplex_mode::decrypt_ciphertext(state, offset, ciphertext, plaintext);
    return true;
  }

  [[nodiscard]]
  forceinline constexpr bool finalize_ciphering()
  {
    if (!finished_absorbing_data || finished_ciphering) {
      return false;
    }

    ascon_duplex_mode::finalize_ciphering(state, offset);
    finished_ciphering = true;

    return true;
  }

  [[nodiscard]]
  forceinline constexpr bool squeeze_tag(std::span<uint8_t, TAG_BYTE_LEN> tag)
  {
    if (!finished_absorbing_data || !finished_ciphering || finished_squeezing_tag) {
      return false;
    }

    ascon_duplex_mode::finalize(state, key, tag);
    finished_squeezing_tag = true;

    return true;
  }

  forceinline constexpr void reset()
  {
    this->key.fill(0);
    this->nonce.fill(0);
    this->state.reset();
    this->offset = 0;
    this->total_absorbed_data_byte_len = 0;
    this->finished_absorbing_data = false;
    this->finished_ciphering = false;
    this->finished_squeezing_tag = false;
  }
};

/**
 * @brief Encrypts plaintext using the Ascon-AEAD128 algorithm.
 *
 * @param key The 128-bit encryption key.
 * @param nonce The 128-bit nonce (must be unique for each encryption with the same key).
 * @param associated_data Arbitrary-length associated data to be authenticated (but not encrypted).
 * @param plaintext The plaintext to be encrypted.
 * @param ciphertext Output buffer for the ciphertext (must be the same length as plaintext).
 * @param tag Output buffer for the 128-bit authentication tag.
 *
 * This function encrypts the plaintext, producing ciphertext of the same length.
 * It also generates a 128-bit authentication tag that authenticates both the associated data and the ciphertext.
 * The associated data is authenticated but not encrypted.
 */
forceinline constexpr void
encrypt(std::span<const uint8_t, KEY_BYTE_LEN> key,
        std::span<const uint8_t, NONCE_BYTE_LEN> nonce,
        std::span<const uint8_t> associated_data,
        std::span<const uint8_t> plaintext,
        std::span<uint8_t> ciphertext,
        std::span<uint8_t, TAG_BYTE_LEN> tag)
{
  ascon_perm::ascon_perm_t state{};

  ascon_duplex_mode::initialize(state, key, nonce);

  size_t block_offset = 0;
  ascon_duplex_mode::absorb_associated_data(state, block_offset, associated_data);
  ascon_duplex_mode::finalize_associated_data(state, block_offset, associated_data.size());

  ascon_duplex_mode::encrypt_plaintext(state, block_offset, plaintext, ciphertext);
  ascon_duplex_mode::finalize_ciphering(state, block_offset);

  ascon_duplex_mode::finalize(state, key, tag);
}

/**
 * @brief Decrypts ciphertext using the Ascon-AEAD128 algorithm and verifies its authenticity.
 *
 * @param key The 128-bit encryption key.
 * @param nonce The 128-bit nonce used during encryption.
 * @param associated_data Arbitrary-length associated data used during encryption.
 * @param cipher The ciphertext to be decrypted.
 * @param text Output buffer for the plaintext (must be the same length as cipher).  Will be zeroed if authentication fails.
 * @param tag The 128-bit authentication tag generated during encryption.
 * @return True if the authentication tag is valid and decryption was successful; False otherwise.  If false, the output text will be zeroed.
 *
 * This function decrypts the ciphertext, producing plaintext of the same length.  It also verifies the authenticity of both the ciphertext and associated data
 * using the provided authentication tag. If authentication fails, the function returns false and the plaintext buffer is zeroed.
 */
[[nodiscard]]
forceinline constexpr bool
decrypt(std::span<const uint8_t, KEY_BYTE_LEN> key,
        std::span<const uint8_t, NONCE_BYTE_LEN> nonce,
        std::span<const uint8_t> associated_data,
        std::span<const uint8_t> ciphertext,
        std::span<uint8_t> plaintext,
        std::span<const uint8_t, TAG_BYTE_LEN> tag)
{
  ascon_perm::ascon_perm_t state{};
  std::array<uint8_t, TAG_BYTE_LEN> computed_tag{};

  ascon_duplex_mode::initialize(state, key, nonce);

  size_t block_offset = 0;
  ascon_duplex_mode::absorb_associated_data(state, block_offset, associated_data);
  ascon_duplex_mode::finalize_associated_data(state, block_offset, associated_data.size());

  ascon_duplex_mode::decrypt_ciphertext(state, block_offset, ciphertext, plaintext);
  ascon_duplex_mode::finalize_ciphering(state, block_offset);

  ascon_duplex_mode::finalize(state, key, computed_tag);

  const uint32_t flg = ascon_common_utils::ct_eq_byte_array<TAG_BYTE_LEN>(tag, computed_tag);
  ascon_common_utils::ct_conditional_memset(~flg, plaintext, 0);

  return static_cast<bool>(flg);
}

}
