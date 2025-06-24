#include "ascon/hashes/ascon_cxof128.hpp"
#include "test_helper.hpp"
#include <array>
#include <cassert>
#include <gtest/gtest.h>

// Given a statically known input message, computes olen -bytes Ascon-CXOF128 digest on it, returning hex-encoded character array as output,
// during program compilation time.
template<size_t olen = 32>
constexpr std::array<char, 2 * olen>
eval_ascon_cxof128()
{
  // Statically defined input.
  // Message = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  std::array<uint8_t, 32> data{};
  std::iota(data.begin(), data.end(), 0);

  std::array<uint8_t, 8> cust_str{};
  std::iota(cust_str.begin(), cust_str.end(), 0xde);

  // To be computed digest.
  std::array<uint8_t, olen> md{};

  ascon_cxof128::ascon_cxof128_t hasher;
  assert(hasher.customize(cust_str) == ascon_cxof128::ascon_cxof128_status_t::customized);
  assert(hasher.absorb(data) == ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  assert(hasher.finalize() == ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  assert(hasher.squeeze(md) == ascon_cxof128::ascon_cxof128_status_t::squeezed_output);

  // Returns hex-encoded digest.
  return bytes_to_hex(md);
}

TEST(AsconCXOF128, CompileTimeComputeCXOFOutput)
{
  constexpr auto expected_output =
    std::array<char, 64>{ 'E', '0', '9', '8', 'F', '0', '4', '7', 'A', '8', 'A', 'C', 'A', '0', '3', '1', '7', '0', '7', '6', 'E', '4',
                          '8', '2', 'E', '2', '8', '4', 'F', '5', '7', '9', 'B', 'E', '1', '7', '3', 'A', '2', 'F', '0', 'B', 'D', '5',
                          '6', '8', 'D', '3', '3', '1', '9', '8', '3', '1', 'B', 'A', '3', '5', '2', '8', 'C', '4', '4', 'D' };

  // AsconCXOF128("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") = "E098F047A8ACA0317076E482E284F579BE173A2F0BD568D3319831BA3528C44D"
  constexpr auto md = eval_ascon_cxof128();
  constexpr auto is_matching = md == expected_output;

  static_assert(is_matching, "Must be able to evaluate Ascon-CXOF128 during program compilation time itself !");
  EXPECT_TRUE(is_matching);
}

TEST(AsconCXOF128, ForSameMessageOneshotHashingAndIncrementalHashingProducesSameOutput)
{
  for (size_t cust_str_byte_len = MIN_CUST_STR_LEN; cust_str_byte_len <= MAX_CUST_STR_LEN; cust_str_byte_len++) {
    for (size_t msg_byte_len = MIN_MSG_LEN; msg_byte_len <= MAX_MSG_LEN; msg_byte_len++) {
      for (size_t output_byte_len = MIN_OUT_LEN; output_byte_len <= MAX_OUT_LEN; output_byte_len++) {
        std::vector<uint8_t> cust_str(cust_str_byte_len);
        std::vector<uint8_t> msg(msg_byte_len);

        std::vector<uint8_t> digest_oneshot(output_byte_len, 0x5f);
        std::vector<uint8_t> digest_multishot(output_byte_len, 0x3f);

        auto msg_span = std::span(msg);
        auto digest_oneshot_span = std::span(digest_oneshot);
        auto digest_multishot_span = std::span(digest_multishot);

        generate_random_data(msg_span);

        // Oneshot hashing
        {
          ascon_cxof128::ascon_cxof128_t hasher;

          EXPECT_EQ(hasher.customize(cust_str), ascon_cxof128::ascon_cxof128_status_t::customized);
          EXPECT_EQ(hasher.absorb(msg_span), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
          EXPECT_EQ(hasher.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
          EXPECT_EQ(hasher.squeeze(digest_oneshot_span), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
        }

        // Incremental hashing
        {
          ascon_cxof128::ascon_cxof128_t hasher;

          EXPECT_EQ(hasher.customize(cust_str), ascon_cxof128::ascon_cxof128_status_t::customized);

          size_t msg_offset = 0;
          while (msg_offset < msg_byte_len) {
            // Because we don't want to be stuck in an infinite loop if msg[off] = 0
            const auto elen = std::min<size_t>(std::max<uint8_t>(msg_span[msg_offset], 1), msg_byte_len - msg_offset);

            EXPECT_EQ(hasher.absorb(msg_span.subspan(msg_offset, elen)), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
            msg_offset += elen;
          }

          EXPECT_EQ(hasher.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);

          // Squeeze message bytes in many iterations
          size_t output_offset = 0;
          while (output_offset < output_byte_len) {
            EXPECT_EQ(hasher.squeeze(digest_multishot_span.subspan(output_offset, 1)), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);

            auto elen = std::min<size_t>(digest_multishot_span[output_offset], output_byte_len - (output_offset + 1));

            output_offset += 1;
            EXPECT_EQ(hasher.squeeze(digest_multishot_span.subspan(output_offset, elen)), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
            output_offset += elen;
          }
        }

        EXPECT_EQ(digest_oneshot, digest_multishot);
      }
    }
  }
}

TEST(AsconCXOF128, ValidCXOFSequence)
{
  std::array<uint8_t, 8> cstr{};
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, 32> output{};

  ascon_cxof128::ascon_cxof128_t cxof;
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::customized);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
}

TEST(AsconCXOF128, MultipleCustomizeCalls)
{
  std::array<uint8_t, 8> cstr{};
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, 32> output{};

  ascon_cxof128::ascon_cxof128_t cxof;
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::customized);
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::already_customized);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
}

TEST(AsconCXOF128, MultipleAbsorbCalls)
{
  std::array<uint8_t, 8> cstr{};
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, 32> output{};

  ascon_cxof128::ascon_cxof128_t cxof;
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::customized);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
}

TEST(AsconCXOF128, MultipleFinalizeCalls)
{
  std::array<uint8_t, 8> cstr{};
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, 32> output{};

  ascon_cxof128::ascon_cxof128_t cxof;
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::customized);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::data_absorption_phase_already_finalized);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
}

TEST(AsconCXOF128, MultipleSqueezeCalls)
{
  std::array<uint8_t, 8> cstr{};
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, 32> output{};

  ascon_cxof128::ascon_cxof128_t cxof;
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::customized);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
}

TEST(AsconCXOF128, CustomizeDuringAbsorption)
{
  std::array<uint8_t, 8> cstr{};
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, 32> output{};

  ascon_cxof128::ascon_cxof128_t cxof;
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::customized);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::already_customized);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
}

TEST(AsconCXOF128, CustomizeAfterFinalization)
{
  std::array<uint8_t, 8> cstr{};
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, 32> output{};

  ascon_cxof128::ascon_cxof128_t cxof;
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::customized);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::already_customized);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
}

TEST(AsconCXOF128, CustomizeDuringSqueezing)
{
  std::array<uint8_t, 8> cstr{};
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, 32> output{};

  ascon_cxof128::ascon_cxof128_t cxof;
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::customized);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::already_customized);
}

TEST(AsconCXOF128, AbsorbMessageAfterFinalization)
{
  std::array<uint8_t, 8> cstr{};
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, 32> output{};

  ascon_cxof128::ascon_cxof128_t cxof;
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::customized);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::data_absorption_phase_already_finalized);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
}

TEST(AsconCXOF128, AbsorbMessageDuringSqueezing)
{
  std::array<uint8_t, 8> cstr{};
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, 32> output{};

  ascon_cxof128::ascon_cxof128_t cxof;
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::customized);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::data_absorption_phase_already_finalized);
}

TEST(AsconCXOF128, FinalizeDuringSqueezing)
{
  std::array<uint8_t, 8> cstr{};
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, 32> output{};

  ascon_cxof128::ascon_cxof128_t cxof;
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::customized);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::data_absorption_phase_already_finalized);
}

TEST(AsconCXOF128, AbsorbWithoutCustomize)
{
  std::array<uint8_t, 8> cstr{};
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, 32> output{};

  ascon_cxof128::ascon_cxof128_t cxof;
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::not_yet_customized);
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::customized);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
}

TEST(AsconCXOF128, FinalizeWithoutAbsorb)
{
  std::array<uint8_t, 8> cstr{};
  std::array<uint8_t, 32> output{};

  ascon_cxof128::ascon_cxof128_t cxof;
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::customized);
  EXPECT_EQ(cxof.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);
}

TEST(AsconCXOF128, SqueezeWithoutFinalize)
{
  std::array<uint8_t, 8> cstr{};
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, 32> output{};

  ascon_cxof128::ascon_cxof128_t cxof;
  EXPECT_EQ(cxof.customize(cstr), ascon_cxof128::ascon_cxof128_status_t::customized);
  EXPECT_EQ(cxof.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  EXPECT_EQ(cxof.squeeze(output), ascon_cxof128::ascon_cxof128_status_t::still_in_data_absorption_phase);
}
