#pragma once
#include "ascon/hashes/sponge.hpp"

namespace ascon_hash256 {

static constexpr size_t DIGEST_BYTE_LEN = (ascon_perm::PERMUTATION_STATE_BITWIDTH - ascon_sponge_mode::RATE_BITS) / std::numeric_limits<uint8_t>::digits;

// See table 12 of Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
static constexpr uint8_t UNIQUE_ALGORITHM_ID = 2;
static constexpr auto INITIAL_PERMUTATION_STATE = ascon_sponge_mode::compute_init_state(ascon_common_utils::compute_iv(UNIQUE_ALGORITHM_ID,
                                                                                                                       ascon_sponge_mode::ASCON_PERM_NUM_ROUNDS,
                                                                                                                       ascon_sponge_mode::ASCON_PERM_NUM_ROUNDS,
                                                                                                                       DIGEST_BYTE_LEN * 8,
                                                                                                                       ascon_sponge_mode::RATE_BYTES));

/**
 * @brief Represents the Ascon-Hash256 hashing algorithm.
 *
 * This struct encapsulates the state and methods for computing the Ascon-Hash256 hash of a message. It uses the Ascon permutation and a sponge construction.
 * The hash function produces a 32-byte digest. The object can be reused after calling the `reset()` method.
 */
struct ascon_hash256_t
{
private:
  ascon_perm::ascon_perm_t state = INITIAL_PERMUTATION_STATE;
  size_t offset = 0;
  alignas(4) bool finished_absorbing = false;
  alignas(4) bool finished_squeezing = false;

public:
  // Constructor(s)/ Destructor(s)
  forceinline constexpr ascon_hash256_t() = default;
  forceinline constexpr ~ascon_hash256_t()
  {
    state.reset();
    offset = 0;
    finished_absorbing = false;
    finished_squeezing = false;
  }

  forceinline constexpr ascon_hash256_t(const ascon_hash256_t&) = default;
  forceinline constexpr ascon_hash256_t(ascon_hash256_t&&) = default;
  forceinline constexpr ascon_hash256_t& operator=(const ascon_hash256_t&) = default;
  forceinline constexpr ascon_hash256_t& operator=(ascon_hash256_t&&) = default;

  /**
   * @brief Absorbs data into the hash state.
   *
   * This function absorbs the provided data into the internal state of the Ascon-Hash256 function. It uses the underlying Ascon sponge construction's absorb
   * function. This function can be called multiple times to absorb data in chunks; only after calling `finalize()` will further calls to `absorb` be ignored.
   *
   * @param msg A span of bytes representing the data to absorb.
   * @return `true` if the data was successfully absorbed, `false` if the hash state has already been finalized.
   */
  forceinline constexpr bool absorb(std::span<const uint8_t> msg)
  {
    if (!finished_absorbing) [[likely]] {
      ascon_sponge_mode::absorb(state, offset, msg);
      return true;
    }

    return false;
  }

  /**
   * @brief Finalizes the hash computation.
   *
   * This function finalizes the hash computation by padding the message and performing the necessary final transformations within the Ascon sponge
   * construction.  It must be called before calling `digest()` to obtain the final hash value.  Calling this function multiple times has no effect.
   * Subsequent calls to `absorb` after calling `finalize` will be ignored.
   *
   * @return `true` if the function successfully finalized the hash computation (meaning it was called before and not after `digest`), `false` otherwise.
   */
  forceinline bool constexpr finalize()
  {
    if (!finished_absorbing) [[likely]] {
      ascon_sponge_mode::finalize(state, offset);
      finished_absorbing = true;

      return true;
    }

    return false;
  }

  /**
   * @brief Extracts the hash digest.
   *
   * This function extracts the computed hash digest from the internal state.  It must be called after `finalize()`. Only the first call after `finalize()` will
   * successfully extract and return the digest; subsequent calls will only return `false`.
   *
   * @param out A span of bytes where the resulting digest will be written.  The span must be large enough to hold a digest of `DIGEST_BYTE_LEN` bytes.
   * @return `true` if the digest was successfully extracted (this is the first call after `finalize()`), `false` otherwise.
   */
  forceinline bool constexpr digest(std::span<uint8_t, DIGEST_BYTE_LEN> out)
  {
    if (finished_absorbing && !finished_squeezing) [[likely]] {
      size_t readable = ascon_sponge_mode::RATE_BYTES;
      ascon_sponge_mode::squeeze(state, readable, out);

      finished_squeezing = true;
      return true;
    }

    return false;
  }

  /**
   * @brief Resets the hash state to its initial values.
   *
   * This function resets the internal state of the Ascon-Hash256 object, allowing it to be reused for hashing a new message.  After calling `reset()`, the
   * object is in the same state as a newly constructed object.
   */
  forceinline void constexpr reset()
  {
    this->state = INITIAL_PERMUTATION_STATE;
    this->offset = 0;
    this->finished_absorbing = false;
    this->finished_squeezing = false;
  }
};

}
