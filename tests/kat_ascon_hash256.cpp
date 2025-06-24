#include "ascon/hashes/ascon_hash256.hpp"
#include "test_helper.hpp"
#include <algorithm>
#include <fstream>
#include <gtest/gtest.h>

static void
ascon_hash256_KAT_runner(const std::string file_name)
{
  using namespace std::literals;
  std::fstream file(file_name);

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

      auto msg = hex_to_bytes(msg2);
      auto md = hex_to_bytes(md2);

      std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> computed_md{};

      ascon_hash256::ascon_hash256_t hasher;
      EXPECT_EQ(hasher.absorb(msg), ascon_hash256::ascon_hash256_status_t::absorbed_data);
      EXPECT_EQ(hasher.finalize(), ascon_hash256::ascon_hash256_status_t::finalized_data_absorption_phase);
      EXPECT_EQ(hasher.digest(computed_md), ascon_hash256::ascon_hash256_status_t::message_digest_produced);

      EXPECT_TRUE(std::ranges::equal(computed_md, md));

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

TEST(AsconHash256, KnownAnswerTests)
{
  ascon_hash256_KAT_runner("./kats/ascon_hash256.kat");
}

TEST(AsconHash256, ACVPKnownAnswerTests)
{
  ascon_hash256_KAT_runner("./kats/ascon_hash256.acvp.kat");
}
