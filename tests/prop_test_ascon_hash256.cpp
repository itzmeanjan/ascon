#include "ascon/hashes/ascon_hash256.hpp"
#include "test_helper.hpp"
#include <array>
#include <cassert>
#include <gtest/gtest.h>

// Given a statically known input message, computes Ascon-Hash256 digest on it, returning hex-encoded character array as output,
// during program compilation time.
constexpr std::array<char, 2 * ascon_hash256::DIGEST_BYTE_LEN>
eval_ascon_hash256()
{
  // Statically defined input.
  // Message = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
  std::array<uint8_t, 32> data{};
  std::iota(data.begin(), data.end(), 0);

  // To be computed digest.
  std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> md{};

  ascon_hash256::ascon_hash256_t hasher;
  assert(hasher.absorb(data) == ascon_hash256::ascon_hash256_status_t::absorbed_data);
  assert(hasher.finalize() == ascon_hash256::ascon_hash256_status_t::finalized_data_absorption_phase);
  assert(hasher.digest(md) == ascon_hash256::ascon_hash256_status_t::message_digest_produced);

  // Returns hex-encoded digest.
  return bytes_to_hex(md);
}

TEST(AsconHash256, CompileTimeComputeMessageDigest)
{
  constexpr auto expected_md = std::array<char, ascon_hash256::DIGEST_BYTE_LEN * 2>{
    'B', 'D', '9', 'D', '3', 'D', '6', '0', 'A', '6', '6', 'B', '5', '3', '8', '6', '8', 'E', 'A', 'B', '2', 'A',
    '5', 'C', '7', '4', '5', '3', '9', 'A', '5', '1', '8', 'A', '1', 'F', '6', '0', 'F', '0', '1', 'E', 'B', '1',
    '7', '6', 'C', '6', '0', 'E', '4', '3', 'D', 'E', 'E', '8', '1', '6', '8', '0', 'B', '3', '3', 'E',
  };

  // AsconHash256("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F") = "BD9D3D60A66B53868EAB2A5C74539A518A1F60F01EB176C60E43DEE81680B33E"
  constexpr auto md = eval_ascon_hash256();
  constexpr auto is_matching = md == expected_md;

  static_assert(is_matching, "Must be able to evaluate Ascon-Hash256 during program compilation time itself !");
  EXPECT_TRUE(is_matching);
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

      EXPECT_EQ(hasher.absorb(msg_span), ascon_hash256::ascon_hash256_status_t::absorbed_data);
      EXPECT_EQ(hasher.finalize(), ascon_hash256::ascon_hash256_status_t::finalized_data_absorption_phase);
      EXPECT_EQ(hasher.digest(digest_oneshot), ascon_hash256::ascon_hash256_status_t::message_digest_produced);
    }

    // Incremental hashing
    {
      ascon_hash256::ascon_hash256_t hasher;

      size_t msg_offset = 0;
      while (msg_offset < msg_byte_len) {
        // Because we don't want to be stuck in an infinite loop if msg[msg_offset] = 0
        const auto elen = std::min<size_t>(std::max<uint8_t>(msg[msg_offset], 1), msg_byte_len - msg_offset);

        EXPECT_EQ(hasher.absorb(msg_span.subspan(msg_offset, elen)), ascon_hash256::ascon_hash256_status_t::absorbed_data);
        msg_offset += elen;
      }

      EXPECT_EQ(hasher.finalize(), ascon_hash256::ascon_hash256_status_t::finalized_data_absorption_phase);
      EXPECT_EQ(hasher.digest(digest_multishot), ascon_hash256::ascon_hash256_status_t::message_digest_produced);
    }

    EXPECT_EQ(digest_oneshot, digest_multishot);
  }
}

TEST(AsconHash256, ValidHashingSequence)
{
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> digest{};

  ascon_hash256::ascon_hash256_t hasher;
  EXPECT_EQ(hasher.absorb(msg), ascon_hash256::ascon_hash256_status_t::absorbed_data);
  EXPECT_EQ(hasher.finalize(), ascon_hash256::ascon_hash256_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(hasher.digest(digest), ascon_hash256::ascon_hash256_status_t::message_digest_produced);
}

TEST(AsconHash256, MultipleAbsorbCalls)
{
  std::array<uint8_t, 8> msg1{};
  std::array<uint8_t, 8> msg2{};
  std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> digest{};

  ascon_hash256::ascon_hash256_t hasher;
  EXPECT_EQ(hasher.absorb(msg1), ascon_hash256::ascon_hash256_status_t::absorbed_data);
  EXPECT_EQ(hasher.absorb(msg2), ascon_hash256::ascon_hash256_status_t::absorbed_data);
  EXPECT_EQ(hasher.finalize(), ascon_hash256::ascon_hash256_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(hasher.digest(digest), ascon_hash256::ascon_hash256_status_t::message_digest_produced);
}

TEST(AsconHash256, MultipleFinalizeCalls)
{
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> digest{};

  ascon_hash256::ascon_hash256_t hasher;
  EXPECT_EQ(hasher.absorb(msg), ascon_hash256::ascon_hash256_status_t::absorbed_data);
  EXPECT_EQ(hasher.finalize(), ascon_hash256::ascon_hash256_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(hasher.finalize(), ascon_hash256::ascon_hash256_status_t::data_absorption_phase_already_finalized);
  EXPECT_EQ(hasher.digest(digest), ascon_hash256::ascon_hash256_status_t::message_digest_produced);
}

TEST(AsconHash256, MultipleProduceDigestCalls)
{
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> digest1{};
  std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> digest2{};

  ascon_hash256::ascon_hash256_t hasher;
  EXPECT_EQ(hasher.absorb(msg), ascon_hash256::ascon_hash256_status_t::absorbed_data);
  EXPECT_EQ(hasher.finalize(), ascon_hash256::ascon_hash256_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(hasher.digest(digest1), ascon_hash256::ascon_hash256_status_t::message_digest_produced);
  EXPECT_EQ(hasher.digest(digest2), ascon_hash256::ascon_hash256_status_t::message_digest_already_produced);
}

TEST(AsconHash256, AbsorbMessageAfterFinalize)
{
  std::array<uint8_t, 8> msg1{};
  std::array<uint8_t, 8> msg2{};
  std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> digest{};

  ascon_hash256::ascon_hash256_t hasher;
  EXPECT_EQ(hasher.absorb(msg1), ascon_hash256::ascon_hash256_status_t::absorbed_data);
  EXPECT_EQ(hasher.finalize(), ascon_hash256::ascon_hash256_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(hasher.absorb(msg2), ascon_hash256::ascon_hash256_status_t::data_absorption_phase_already_finalized);
  EXPECT_EQ(hasher.digest(digest), ascon_hash256::ascon_hash256_status_t::message_digest_produced);
}

TEST(AsconHash256, AbsorbMessageAfterDigestIsProduced)
{
  std::array<uint8_t, 8> msg1{};
  std::array<uint8_t, 8> msg2{};
  std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> digest{};

  ascon_hash256::ascon_hash256_t hasher;
  EXPECT_EQ(hasher.absorb(msg1), ascon_hash256::ascon_hash256_status_t::absorbed_data);
  EXPECT_EQ(hasher.finalize(), ascon_hash256::ascon_hash256_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(hasher.digest(digest), ascon_hash256::ascon_hash256_status_t::message_digest_produced);
  EXPECT_EQ(hasher.absorb(msg2), ascon_hash256::ascon_hash256_status_t::data_absorption_phase_already_finalized);
}

TEST(AsconHash256, FinalizeAfterDigestIsProduced)
{
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> digest{};

  ascon_hash256::ascon_hash256_t hasher;
  EXPECT_EQ(hasher.absorb(msg), ascon_hash256::ascon_hash256_status_t::absorbed_data);
  EXPECT_EQ(hasher.finalize(), ascon_hash256::ascon_hash256_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(hasher.digest(digest), ascon_hash256::ascon_hash256_status_t::message_digest_produced);
  EXPECT_EQ(hasher.finalize(), ascon_hash256::ascon_hash256_status_t::data_absorption_phase_already_finalized);
}

TEST(AsconHash256, FinalizeWithoutAbsorption)
{
  std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> digest{};

  ascon_hash256::ascon_hash256_t hasher;
  EXPECT_EQ(hasher.finalize(), ascon_hash256::ascon_hash256_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(hasher.digest(digest), ascon_hash256::ascon_hash256_status_t::message_digest_produced);
}

TEST(AsconHash256, DigestWithoutFinalize)
{
  std::array<uint8_t, 16> msg{};
  std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> digest{};

  ascon_hash256::ascon_hash256_t hasher;
  EXPECT_EQ(hasher.absorb(msg), ascon_hash256::ascon_hash256_status_t::absorbed_data);
  EXPECT_EQ(hasher.digest(digest), ascon_hash256::ascon_hash256_status_t::still_in_data_absorption_phase);
}
