#include "ascon/hashes/ascon_xof128.hpp"
#include "test_helper.hpp"
#include <fstream>
#include <gtest/gtest.h>

static void
ascon_xof128_KAT_runner(const std::string file_name)
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

      std::vector<uint8_t> computed_md(md.size());

      ascon_xof128::ascon_xof128_t hasher;
      EXPECT_EQ(hasher.absorb(msg), ascon_xof128::ascon_xof128_status_t::absorbed_data);
      EXPECT_EQ(hasher.finalize(), ascon_xof128::ascon_xof128_status_t::finalized_data_absorption_phase);
      EXPECT_EQ(hasher.squeeze(computed_md), ascon_xof128::ascon_xof128_status_t::squeezed_output);

      EXPECT_EQ(computed_md, md);

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

TEST(AsconXof128, KnownAnswerTests)
{
  ascon_xof128_KAT_runner("./kats/ascon_xof128.kat");
}

TEST(AsconXof128, ACVPKnownAnswerTests)
{
  ascon_xof128_KAT_runner("./kats/ascon_xof128.acvp.kat");
}
