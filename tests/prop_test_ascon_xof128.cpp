#include "ascon/hashes/ascon_xof128.hpp"
#include "test_helper.hpp"
#include <cassert>
#include <gtest/gtest.h>

// Given a statically known input message, computes olen -bytes Ascon-Xof128 digest on it, returning hex-encoded character array as output,
// during program compilation time.
template<size_t olen = 32>
constexpr std::array<char, 2 * olen>
eval_ascon_xof128()
{
  // Statically defined input.
  // Message = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
  std::array<uint8_t, 32> data{};
  std::iota(data.begin(), data.end(), 0);

  // To be computed digest.
  std::array<uint8_t, olen> md{};

  ascon_xof128::ascon_xof128_t hasher;
  assert(hasher.absorb(data));
  assert(hasher.finalize());
  assert(hasher.squeeze(md));

  // Returns hex-encoded digest.
  return bytes_to_hex(md);
}

TEST(AsconXof128, CompileTimeComputeXofOutput)
{
  constexpr auto expected_output = std::array<char, 64>{
    '2', 'E', '5', 'F', '3', '4', '0', '3', 'F', '4', '1', '7', '1', '4', '7', '1', 'C', 'C', '7', '9', '3', '4',
    'B', '5', '1', '9', '8', '2', 'C', 'E', 'C', 'E', '8', 'D', '6', '6', '2', '8', '4', '3', '5', 'D', 'B', '7',
    '0', 'E', '8', '9', '8', '8', '0', 'F', '3', 'B', 'E', '4', 'E', '0', 'B', '7', 'B', '0', '5', '2',
  };

  // AsconXof128("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F") = "2E5F3403F4171471CC7934B51982CECE8D6628435DB70E89880F3BE4E0B7B052"
  constexpr auto output = eval_ascon_xof128();
  constexpr auto is_matching = output == expected_output;

  static_assert(is_matching, "Must be able to evaluate Ascon-Xof128 during program compilation time itself !");
  EXPECT_TRUE(is_matching);
}

TEST(AsconXof128, ForSameMessageOneshotHashingAndIncrementalHashingProducesSameOutput)
{
  for (size_t msg_byte_len = MIN_MSG_LEN; msg_byte_len <= MAX_MSG_LEN; msg_byte_len++) {
    for (size_t output_byte_len = MIN_OUT_LEN; output_byte_len <= MAX_OUT_LEN; output_byte_len++) {
      std::vector<uint8_t> msg(msg_byte_len);
      std::vector<uint8_t> digest_oneshot(output_byte_len, 0x5f);
      std::vector<uint8_t> digest_multishot(output_byte_len, 0x3f);

      auto msg_span = std::span(msg);
      auto digest_oneshot_span = std::span(digest_oneshot);
      auto digest_multishot_span = std::span(digest_multishot);

      generate_random_data(msg_span);

      // Oneshot hashing
      {
        ascon_xof128::ascon_xof128_t hasher;

        EXPECT_TRUE(hasher.absorb(msg_span));
        EXPECT_TRUE(hasher.finalize());
        EXPECT_TRUE(hasher.squeeze(digest_oneshot_span));
      }

      // Incremental hashing
      {
        ascon_xof128::ascon_xof128_t hasher;

        size_t msg_offset = 0;
        while (msg_offset < msg_byte_len) {
          // Because we don't want to be stuck in an infinite loop if msg[off] = 0
          const auto elen = std::min<size_t>(std::max<uint8_t>(msg_span[msg_offset], 1), msg_byte_len - msg_offset);

          EXPECT_TRUE(hasher.absorb(msg_span.subspan(msg_offset, elen)));
          msg_offset += elen;
        }

        EXPECT_TRUE(hasher.finalize());

        // Squeeze message bytes in many iterations
        size_t output_offset = 0;
        while (output_offset < output_byte_len) {
          EXPECT_TRUE(hasher.squeeze(digest_multishot_span.subspan(output_offset, 1)));

          auto elen = std::min<size_t>(digest_multishot_span[output_offset], output_byte_len - (output_offset + 1));

          output_offset += 1;
          EXPECT_TRUE(hasher.squeeze(digest_multishot_span.subspan(output_offset, elen)));
          output_offset += elen;
        }
      }

      EXPECT_EQ(digest_oneshot, digest_multishot);
    }
  }
}
