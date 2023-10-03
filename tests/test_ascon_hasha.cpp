#include "hashing/ascon_hasha.hpp"
#include "test_common.hpp"
#include <array>
#include <fstream>
#include <gtest/gtest.h>
#include <span>

// Given a statically known input message, computes Ascon-HashA digest on it, returning
// hex-encoded character array as output, during program compilation time.
constexpr std::array<char, 2 * ascon_hasha::DIGEST_LEN>
eval_ascon_hasha()
{
  // Statically defined input.
  // Message = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  std::array<uint8_t, 32> data{};
  std::iota(data.begin(), data.end(), 0);

  // To be computed digest.
  std::array<uint8_t, ascon_hasha::DIGEST_LEN> md{};

  ascon_hasha::ascon_hasha_t hasher;
  hasher.absorb(data);
  hasher.finalize();
  hasher.digest(md);

  // Returns hex-encoded digest.
  return bytes_to_hex(md);
}

TEST(AsconHashing, CompileTimeEvalAsconHashA)
{
  // AsconHashA("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") =
  // "3237cbcc617a2550583a50e8bad3dacda82562e06220150448c109008fa054a2"
  constexpr auto md = eval_ascon_hasha();
  constexpr auto flg = md == std::array<char, ascon_hasha::DIGEST_LEN * 2>{
    '3', '2', '3', '7', 'c', 'b', 'c', 'c', '6', '1', '7', 'a', '2', '5', '5', '0',
    '5', '8', '3', 'a', '5', '0', 'e', '8', 'b', 'a', 'd', '3', 'd', 'a', 'c', 'd',
    'a', '8', '2', '5', '6', '2', 'e', '0', '6', '2', '2', '0', '1', '5', '0', '4',
    '4', '8', 'c', '1', '0', '9', '0', '0', '8', 'f', 'a', '0', '5', '4', 'a', '2'
  };

  static_assert(
    flg,
    "Must be able to evaluate Ascon-HashA during program compilation time itself !");
  EXPECT_TRUE(flg);
}

// Ensure that both oneshot and incremental way of absorbing same message produces same
// digest for Ascon-HashA.
inline void
test_ascon_hasha(const size_t mlen)
{
  using namespace std::literals;

  std::vector<uint8_t> dig_oneshot(ascon_hasha::DIGEST_LEN);
  std::vector<uint8_t> dig_incremental(ascon_hasha::DIGEST_LEN);
  std::vector<uint8_t> msg(mlen);

  auto _dig_oneshot = std::span<uint8_t, ascon_hasha::DIGEST_LEN>(dig_oneshot);
  auto _dig_incremental = std::span<uint8_t, ascon_hasha::DIGEST_LEN>(dig_incremental);
  auto _msg = std::span(msg);

  ascon_utils::random_data(_msg);

  // oneshot hashing
  {
    ascon_hasha::ascon_hasha_t hasher;

    hasher.absorb(_msg);
    hasher.finalize();
    hasher.digest(_dig_oneshot);
  }

  // incremental hashing
  {
    ascon_hasha::ascon_hasha_t hasher;

    size_t off = 0;
    while (off < mlen) {
      // because we don't want to be stuck in an infinite loop if msg[off] = 0
      auto elen = std::min<size_t>(std::max<uint8_t>(msg[off], 1), mlen - off);

      hasher.absorb(_msg.subspan(off, elen));
      off += elen;
    }

    hasher.finalize();
    hasher.digest(_dig_incremental);
  }

  EXPECT_EQ(dig_oneshot, dig_incremental);
}

TEST(AsconHashing, IncrementalMessageAbsorptionAsconHashA)
{
  for (size_t mlen = MIN_MSG_LEN; mlen <= MAX_MSG_LEN; mlen++) {
    test_ascon_hasha(mlen);
  }
}

// Ensure that this Ascon-HashA implementation is conformant to the specification, using
// known answer tests.
inline void
kat_ascon_hasha()
{
  using namespace std::literals;

  const std::string kat_file = "./kats/ascon_hasha.kat";
  std::fstream file(kat_file);

  while (true) {
    std::string count0;

    if (!std::getline(file, count0).eof()) {
      std::string msg0;
      std::string md0;

      std::getline(file, msg0);
      std::getline(file, md0);

      auto msg1 = std::string_view(msg0);
      auto md1 = std::string_view(md0);

      auto msg2 = msg1.substr(msg1.find("="sv) + 2, msg1.size());
      auto md2 = md1.substr(md1.find("="sv) + 2, md1.size());

      auto msg = ascon_utils::from_hex(msg2);
      auto md = ascon_utils::from_hex(md2);

      std::vector<uint8_t> digest(ascon_hasha::DIGEST_LEN);

      auto _msg = std::span(msg);
      auto _digest = std::span<uint8_t, ascon_hasha::DIGEST_LEN>(digest);

      ascon_hasha::ascon_hasha_t hasher;
      hasher.absorb(_msg);
      hasher.finalize();
      hasher.digest(_digest);

      EXPECT_EQ(digest, md);

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

TEST(AsconHashing, KnownAnswerTestsAsconHashA)
{
  kat_ascon_hasha();
}
