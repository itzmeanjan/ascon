#include "ascon/hashing/ascon_xofa.hpp"
#include "test_common.hpp"
#include <fstream>
#include <gtest/gtest.h>
#include <span>

// Given a statically known input message, computes olen -bytes Ascon-XofA digest on it,
// returning hex-encoded character array as output, during program compilation time.
template<size_t olen = 32>
constexpr std::array<char, 2 * olen>
eval_ascon_xofa()
{
  // Statically defined input.
  // Message = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  std::array<uint8_t, 32> data{};
  std::iota(data.begin(), data.end(), 0);

  // To be computed digest.
  std::array<uint8_t, olen> md{};

  ascon_xofa::ascon_xofa_t hasher;
  hasher.absorb(data);
  hasher.finalize();
  hasher.squeeze(md);

  // Returns hex-encoded digest.
  return bytes_to_hex(md);
}

TEST(AsconHashing, CompileTimeEvalAsconXofA)
{
  // AsconXofA("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") =
  // "42047aea031115f8465cbfac356ac23c4d71f84bd661c8aa7971f37118e520e6"
  constexpr auto md = eval_ascon_xofa();
  constexpr auto flg = md == std::array<char, 64>{ '4', '2', '0', '4', '7', 'a', 'e', 'a', '0', '3', '1', '1', '1', '5', 'f', '8', '4', '6', '5', 'c', 'b', 'f',
                                                   'a', 'c', '3', '5', '6', 'a', 'c', '2', '3', 'c', '4', 'd', '7', '1', 'f', '8', '4', 'b', 'd', '6', '6', '1',
                                                   'c', '8', 'a', 'a', '7', '9', '7', '1', 'f', '3', '7', '1', '1', '8', 'e', '5', '2', '0', 'e', '6' };

  static_assert(flg, "Must be able to evaluate Ascon-XofA during program compilation time itself !");
  EXPECT_TRUE(flg);
}

// Ensure that both oneshot and incremental way of absorbing same message and squeezing
// same length output, produces same digest for Ascon-XofA.
inline void
test_ascon_xofa(const size_t mlen, const size_t dlen)
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
    ascon_xofa::ascon_xofa_t hasher;

    hasher.absorb(_msg);
    hasher.finalize();
    hasher.squeeze(_dig_oneshot);
  }

  // incremental hashing
  {
    ascon_xofa::ascon_xofa_t hasher;

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

  EXPECT_EQ(dig_oneshot, dig_incremental);
}

TEST(AsconHashing, IncrementalMessageAbsorptionSqueezingAsconXofA)
{
  for (size_t mlen = MIN_MSG_LEN; mlen <= MAX_MSG_LEN; mlen++) {
    for (size_t olen = MIN_OUT_LEN; olen <= MAX_OUT_LEN; olen++) {
      test_ascon_xofa(mlen, olen);
    }
  }
}

// Ensure that this Ascon-XofA implementation is conformant to the specification, using
// known answer tests.
inline void
kat_ascon_xofa()
{
  using namespace std::literals;

  const std::string kat_file = "./kats/ascon_xofa.kat";
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

      ascon_xofa::ascon_xofa_t hasher;
      hasher.absorb(_msg);
      hasher.finalize();
      hasher.squeeze(_digest);

      EXPECT_EQ(digest, md);

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

TEST(AsconHashing, KnownAnswerTestsAsconXofA)
{
  kat_ascon_xofa();
}
