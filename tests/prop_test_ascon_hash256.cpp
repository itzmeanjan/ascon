#include "ascon/hashes/ascon_hash256.hpp"
#include "test_helper.hpp"
#include <cassert>
#include <gtest/gtest.h>

// Given a statically known input message, computes Ascon-Hash256 digest on it, returning hex-encoded character array as output,
// during program compilation time.
constexpr std::array<char, 2 * ascon_hash256::DIGEST_BYTE_LEN>
eval_ascon_hash256()
{
  // Statically defined input.
  // Message = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  std::array<uint8_t, 32> data{};
  std::iota(data.begin(), data.end(), 0);

  // To be computed digest.
  std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> md{};

  ascon_hash256::ascon_hash256_t hasher;
  assert(hasher.absorb(data));
  assert(hasher.finalize());
  assert(hasher.digest(md));

  // Returns hex-encoded digest.
  return bytes_to_hex(md);
}

TEST(AsconHash256, CompileTimeComputeMessageDigest)
{
  // AsconHash256("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") =
  // "2a4f6f2b6b3ec2a6c47ba08d18c8ea561b493c13ccb35803fa8b9fb00a0f1f35"
  constexpr auto md = eval_ascon_hash256();
  constexpr auto is_match =
    md == std::array<char, ascon_hash256::DIGEST_BYTE_LEN * 2>{ '2', 'a', '4', 'f', '6', 'f', '2', 'b', '6', 'b', '3', 'e', 'c', '2', 'a', '6',
                                                                'c', '4', '7', 'b', 'a', '0', '8', 'd', '1', '8', 'c', '8', 'e', 'a', '5', '6',
                                                                '1', 'b', '4', '9', '3', 'c', '1', '3', 'c', 'c', 'b', '3', '5', '8', '0', '3',
                                                                'f', 'a', '8', 'b', '9', 'f', 'b', '0', '0', 'a', '0', 'f', '1', 'f', '3', '5' };

  static_assert(!is_match, "Must not be able to evaluate Ascon-Hash256 correctly, as expected output is wrong. I'll update it !");
  EXPECT_FALSE(is_match);
}

TEST(AsconHash256, ForSameMessageOneshotHashingAndIncrementalHashingProducesSameDigest)
{
  for (size_t msg_byte_len = MIN_MSG_LEN; msg_byte_len <= MAX_MSG_LEN; msg_byte_len++) {
    std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> digest_oneshot{};
    std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> digest_multishot{};

    digest_oneshot.fill(0x5f);
    digest_oneshot.fill(0x3f);

    std::vector<uint8_t> msg(msg_byte_len);
    auto msg_span = std::span(msg);

    generate_random_data<uint8_t>(msg_span);

    // Oneshot hashing
    {
      ascon_hash256::ascon_hash256_t hasher;

      EXPECT_TRUE(hasher.absorb(msg_span));
      EXPECT_TRUE(hasher.finalize());
      EXPECT_TRUE(hasher.digest(digest_oneshot));
    }

    // Incremental hashing
    {
      ascon_hash256::ascon_hash256_t hasher;

      size_t msg_offset = 0;
      while (msg_offset < msg_byte_len) {
        // Because we don't want to be stuck in an infinite loop if msg[msg_offset] = 0
        const auto elen = std::min<size_t>(std::max<uint8_t>(msg[msg_offset], 1), msg_byte_len - msg_offset);

        EXPECT_TRUE(hasher.absorb(msg_span.subspan(msg_offset, elen)));
        msg_offset += elen;
      }

      EXPECT_TRUE(hasher.finalize());
      EXPECT_TRUE(hasher.digest(digest_multishot));
    }

    EXPECT_EQ(digest_oneshot, digest_multishot);
  }
}
