#include "hashing/ascon_hasha.hpp"
#include "test_aead_common.hpp"
#include <fstream>
#include <gtest/gtest.h>
#include <span>

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
    ascon_hasha::ascon_hasha hasher;

    hasher.absorb(_msg);
    hasher.finalize();
    hasher.digest(_dig_oneshot);
  }

  // incremental hashing
  {
    ascon_hasha::ascon_hasha hasher;

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

  ASSERT_EQ(dig_oneshot, dig_incremental);
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

      ascon_hasha::ascon_hasha hasher;
      hasher.absorb(_msg);
      hasher.finalize();
      hasher.digest(_digest);

      ASSERT_EQ(digest, md);

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
