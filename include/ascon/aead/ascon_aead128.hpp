#pragma once
#include "ascon/aead/duplex.hpp"

namespace ascon_aead128 {

static constexpr size_t KEY_BYTE_LEN = ascon_duplex_mode::KEY_BYTE_LEN;
static constexpr size_t NONCE_BYTE_LEN = ascon_duplex_mode::NONCE_BYTE_LEN;
static constexpr size_t TAG_BYTE_LEN = ascon_duplex_mode::TAG_BYTE_LEN;

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
forceinline void
encrypt(std::span<const uint8_t, KEY_BYTE_LEN> key,
        std::span<const uint8_t, NONCE_BYTE_LEN> nonce,
        std::span<const uint8_t> associated_data,
        std::span<const uint8_t> plaintext,
        std::span<uint8_t> ciphertext,
        std::span<uint8_t, TAG_BYTE_LEN> tag)
{
  ascon_perm::ascon_perm_t state{};

  ascon_duplex_mode::initialize(state, key, nonce);
  ascon_duplex_mode::process_associated_data(state, associated_data);
  ascon_duplex_mode::process_plaintext(state, plaintext, ciphertext);
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
forceinline bool
decrypt(std::span<const uint8_t, KEY_BYTE_LEN> key,
        std::span<const uint8_t, NONCE_BYTE_LEN> nonce,
        std::span<const uint8_t> associated_data,
        std::span<const uint8_t> cipher,
        std::span<uint8_t> text,
        std::span<const uint8_t, TAG_BYTE_LEN> tag)
{
  ascon_perm::ascon_perm_t state{};
  std::array<uint8_t, TAG_BYTE_LEN> computed_tag{};

  ascon_duplex_mode::initialize(state, key, nonce);
  ascon_duplex_mode::process_associated_data(state, associated_data);
  ascon_duplex_mode::process_ciphertext(state, cipher, text);
  ascon_duplex_mode::finalize(state, key, computed_tag);

  const uint32_t flg = ascon_common_utils::ct_eq_byte_array<TAG_BYTE_LEN>(tag, computed_tag);
  ascon_common_utils::ct_conditional_memset(~flg, text, 0);

  return static_cast<bool>(flg);
}

}
