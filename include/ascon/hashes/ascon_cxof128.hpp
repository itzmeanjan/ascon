#pragma once
#include "ascon/hashes/sponge.hpp"

namespace ascon_cxof128 {

// See table 12 of Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
static constexpr uint8_t UNIQUE_ALGORITHM_ID = 4;
static constexpr auto INITIAL_PERMUTATION_STATE = ascon_sponge_mode::compute_init_state(ascon_common_utils::compute_iv(UNIQUE_ALGORITHM_ID,
                                                                                                                       ascon_sponge_mode::ASCON_PERM_NUM_ROUNDS,
                                                                                                                       ascon_sponge_mode::ASCON_PERM_NUM_ROUNDS,
                                                                                                                       0,
                                                                                                                       ascon_sponge_mode::RATE_BYTES));

static constexpr size_t CUSTOMIZATION_STRING_MAX_BYTE_LEN = 256;

/**
 * @brief Represents an Ascon CXOF-128 instance offering 128-bit security.
 *
 * This struct encapsulates the state of an Ascon customizable extendable output function (CXOF), providing 128-bit security. It offers
 * methods for customization, data absorption, finalization, and output squeezing.
 */
struct ascon_cxof128_t
{
private:
  ascon_perm::ascon_perm_t state = INITIAL_PERMUTATION_STATE;
  size_t offset = 0;
  size_t readable = 0;
  alignas(4) bool has_customized = false;
  alignas(4) bool finished_absorbing = false;

public:
  // Constructor(s)/ Destructor(s)
  forceinline constexpr ascon_cxof128_t() = default;
  forceinline constexpr ~ascon_cxof128_t()
  {
    state.reset();
    offset = 0;
    readable = 0;
    has_customized = false;
    finished_absorbing = false;
  }

  /**
   * @brief Customizes the CXOF with a given customization string.
   *
   * This function allows you to provide a customization string to the CXOF. The string length is limited to `CUSTOMIZATION_STRING_MAX_BYTE_LEN`.
   * The customization string is absorbed into the internal state of the CXOF. This function must be called before calling `absorb`.
   *
   * @param cust_str The customization string.
   * @return True if customization was successful, false otherwise (e.g., if already customized or string too long).
   */
  [[nodiscard]]
  forceinline constexpr bool customize(std::span<const uint8_t> cust_str)
  {
    if (!has_customized && (cust_str.size() <= CUSTOMIZATION_STRING_MAX_BYTE_LEN)) [[likely]] {
      std::array<uint8_t, ascon_sponge_mode::RATE_BYTES> cust_str_len_as_bytes{};
      ascon_common_utils::to_le_bytes(cust_str.size(), cust_str_len_as_bytes);

      ascon_sponge_mode::absorb(state, offset, cust_str_len_as_bytes);
      ascon_sponge_mode::absorb(state, offset, cust_str);
      ascon_sponge_mode::finalize(state, offset);

      has_customized = true;
      return true;
    }

    return false;
  }

  /**
   * @brief Absorbs data into the CXOF.
   *
   * This function absorbs input data into the internal state of the CXOF. The `customize` function must be called before calling this function. This function
   * can be called multiple times before calling `finalize`.
   *
   * @param msg The data to absorb.
   * @return True if absorption was successful, false otherwise (e.g., if not yet customized or already finalized).
   */
  [[nodiscard]]
  forceinline constexpr bool absorb(std::span<const uint8_t> msg)
  {
    if (has_customized && !finished_absorbing) [[likely]] {
      ascon_sponge_mode::absorb(state, offset, msg);
      return true;
    }

    return false;
  }

  /**
   * @brief Finalizes the absorption phase of the CXOF, preparing for squeezing.
   *
   * This function marks the end of the data absorption phase. It must be called after all data has been absorbed using the `absorb` function and before any
   * calls to `squeeze`. Calling this function multiple times has no effect. Calling `finalize` before `customize` is a no-op and returns `false`.
   *
   * @return True if finalization was successful (and it was not already finalized), false otherwise.
   */
  [[nodiscard]]
  forceinline constexpr bool finalize()
  {
    if (has_customized && !finished_absorbing) [[likely]] {
      ascon_sponge_mode::finalize(state, offset);

      finished_absorbing = true;
      readable = ascon_sponge_mode::RATE_BYTES;

      return true;
    }

    return false;
  }

  /**
   * @brief Squeezes output data from the CXOF.
   *
   * This function extracts output data from the CXOF. The `finalize` function must be called before calling this function. This function can be called multiple
   * times to retrieve any number of bytes of output data.
   *
   * @param out The buffer to write the squeezed output to.
   * @return True if squeezing was successful, false otherwise (e.g., if `finalize` has not been called).
   */
  [[nodiscard]]
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
