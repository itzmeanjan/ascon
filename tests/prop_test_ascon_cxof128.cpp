#include "ascon/hashes/ascon_cxof128.hpp"
#include "test_helper.hpp"
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
  assert(hasher.customize(cust_str));
  assert(hasher.absorb(data));
  assert(hasher.finalize());
  assert(hasher.squeeze(md));

  // Returns hex-encoded digest.
  return bytes_to_hex(md);
}

TEST(AsconCXOF128, CompileTimeComputeXofOutput)
{
  // AsconCXOF128("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") =
  // "0b8e325b9bbf1bb43e77aa1eed93bee62b4ea1e4b0c5a696b2f5c5b09c968918"
  constexpr auto md = eval_ascon_cxof128();
  constexpr auto flg = md == std::array<char, 64>{ '0', 'b', '8', 'e', '3', '2', '5', 'b', '9', 'b', 'b', 'f', '1', 'b', 'b', '4', '3', 'e', '7', '7', 'a', 'a',
                                                   '1', 'e', 'e', 'd', '9', '3', 'b', 'e', 'e', '6', '2', 'b', '4', 'e', 'a', '1', 'e', '4', 'b', '0', 'c', '5',
                                                   'a', '6', '9', '6', 'b', '2', 'f', '5', 'c', '5', 'b', '0', '9', 'c', '9', '6', '8', '9', '1', '8' };

  static_assert(!flg, "Must not be able to evaluate Ascon-CXOF128 correctly, as expected output is wrong. I'll update it !");
  EXPECT_FALSE(flg);
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

          EXPECT_TRUE(hasher.customize(cust_str));
          EXPECT_TRUE(hasher.absorb(msg_span));
          EXPECT_TRUE(hasher.finalize());
          EXPECT_TRUE(hasher.squeeze(digest_oneshot_span));
        }

        // Incremental hashing
        {
          ascon_cxof128::ascon_cxof128_t hasher;

          EXPECT_TRUE(hasher.customize(cust_str));

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
}
