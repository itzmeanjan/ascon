#include "hashing/ascon_xof.hpp"
#include "test_common.hpp"
#include <fstream>
#include <gtest/gtest.h>
#include <span>

// Ensure that both oneshot and incremental way of absorbing same message and squeezing
// same length output, produces same digest for Ascon-Xof.
inline void
test_ascon_xof(const size_t mlen, const size_t dlen)
{
  using namespace std::literals;

  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> dig_oneshot(dlen);
  std::vector<uint8_t> dig_incremental(dlen);

  auto _dig_oneshot = std::span(dig_oneshot);
  auto _dig_incremental = std::span(dig_incremental);
  auto _msg = std::span(msg);

  ascon_utils::random_data(_msg);

  // oneshot hashing
  {
    ascon_xof::ascon_xof_t hasher;

    hasher.absorb(_msg);
    hasher.finalize();
    hasher.squeeze(_dig_oneshot);
  }

  // incremental hashing
  {
    ascon_xof::ascon_xof_t hasher;

    size_t off = 0;
    while (off < mlen) {
      // because we don't want to be stuck in an infinite loop if msg[off] = 0
      auto elen = std::min<size_t>(std::max<uint8_t>(_msg[off], 1), mlen - off);

      hasher.absorb(_msg.subspan(off, elen));
      off += elen;
    }

    hasher.finalize();

    // squeeze message bytes in many iterations
    off = 0;
    while (off < dlen) {
      hasher.squeeze(_dig_incremental.subspan(off, 1));

      auto elen = std::min<size_t>(_dig_incremental[off], dlen - (off + 1));

      off += 1;
      hasher.squeeze(_dig_incremental.subspan(off, elen));
      off += elen;
    }
  }

  ASSERT_EQ(dig_oneshot, dig_incremental);
}

TEST(AsconHashing, IncrementalMessageAbsorptionSqueezingAsconXof)
{
  for (size_t mlen = MIN_MSG_LEN; mlen <= MAX_MSG_LEN; mlen++) {
    for (size_t olen = MIN_OUT_LEN; olen <= MAX_OUT_LEN; olen++) {
      test_ascon_xof(mlen, olen);
    }
  }
}

// Ensure that this Ascon-Xof implementation is conformant to the specification, using
// known answer tests.
inline void
kat_ascon_xof()
{
  using namespace std::literals;

  const std::string kat_file = "./kats/ascon_xof.kat";
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

      std::vector<uint8_t> digest(md.size());

      auto _msg = std::span(msg);
      auto _digest = std::span(digest);

      ascon_xof::ascon_xof_t hasher;
      hasher.absorb(_msg);
      hasher.finalize();
      hasher.squeeze(_digest);

      ASSERT_EQ(digest, md);

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

TEST(AsconHashing, KnownAnswerTestsAsconXof)
{
  kat_ascon_xof();
}
