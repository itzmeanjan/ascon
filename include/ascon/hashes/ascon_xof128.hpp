#pragma once
#include "ascon/hashes/sponge.hpp"

namespace ascon_xof128 {

// See table 12 of Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
static constexpr uint8_t UNIQUE_ALGORITHM_ID = 3;
static constexpr auto INITIAL_PERMUTATION_STATE = ascon_sponge_mode::compute_init_state(ascon_common_utils::compute_iv(UNIQUE_ALGORITHM_ID,
                                                                                                                       ascon_sponge_mode::ASCON_PERM_NUM_ROUNDS,
                                                                                                                       ascon_sponge_mode::ASCON_PERM_NUM_ROUNDS,
                                                                                                                       0,
                                                                                                                       ascon_sponge_mode::RATE_BYTES));

/**
 * @brief Ascon-based extendable-output function (XOF) offering 128-bit security. Provides methods for absorbing arbitrary long data, finalizing the internal
 * state, and squeezing arbitrarily long output sequences.
 */
struct ascon_xof128_t
{
private:
  ascon_perm::ascon_perm_t state = INITIAL_PERMUTATION_STATE;
  size_t offset = 0;
  size_t readable = 0;
  alignas(4) bool finished_absorbing = false;

public:
  // Constructor(s)/ Destructor(s)
  forceinline constexpr ascon_xof128_t() = default;
  forceinline constexpr ~ascon_xof128_t()
  {
    state.reset();
    offset = 0;
    readable = 0;
    finished_absorbing = false;
  }

  forceinline constexpr ascon_xof128_t(const ascon_xof128_t&) = default;
  forceinline constexpr ascon_xof128_t(ascon_xof128_t&&) = default;
  forceinline constexpr ascon_xof128_t& operator=(const ascon_xof128_t&) = default;
  forceinline constexpr ascon_xof128_t& operator=(ascon_xof128_t&&) = default;

  /**
   * @brief Absorbs input data into the XOF's internal state. This function can be called repeatedly to absorb data in chunks before calling `finalize()`.
   * @param msg The data to absorb.
   * @return True if the data was successfully absorbed (the XOF has not been finalized), false otherwise.
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
   * @brief Completes the absorption phase of the XOF. This function must be called after all data has been absorbed using the `absorb` method. It prepares the
   * internal state for the squeezing operation.
   * @return True if the XOF was successfully finalized, false if it was already finalized.
   */
  forceinline constexpr bool finalize()
  {
    if (!finished_absorbing) [[likely]] {
      ascon_sponge_mode::finalize(state, offset);

      finished_absorbing = true;
      readable = ascon_sponge_mode::RATE_BYTES;

      return true;
    }

    return false;
  }

  /**
   * @brief Extracts output data from the finalized XOF. This function can be called multiple times to generate an arbitrary amount of output data.
   * The `finalize` method must be called before the first call to this function.
   * @param out The buffer to write the squeezed data to.
   * @return True if output was successfully squeezed (XOF is finalized), false otherwise.
   */
  forceinline constexpr bool squeeze(std::span<uint8_t> out)
  {
    if (!finished_absorbing) [[unlikely]] {
      return false;
    }

    ascon_sponge_mode::squeeze(state, readable, out);
    return true;
  }
};

}
