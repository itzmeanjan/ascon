#include "ascon/hashes/ascon_cxof128.hpp"
#include "test_helper.hpp"
#include <fstream>
#include <gtest/gtest.h>

static void
ascon_cxof128_KAT_runner(const std::string file_name)
{
  using namespace std::literals;
  std::fstream file(file_name);

  while (true) {
    std::string count0;

    if (!std::getline(file, count0).eof()) {
      std::string msg0;
      std::string customization_str0;
      std::string md0;

      std::getline(file, msg0);
      std::getline(file, customization_str0);
      std::getline(file, md0);

      auto msg1 = std::string_view(msg0);
      auto customization_str1 = std::string_view(customization_str0);
      auto md1 = std::string_view(md0);

      auto msg2 = msg1.substr(msg1.find("="sv) + 2, msg1.size());
      auto customization_str2 = customization_str1.substr(customization_str1.find("="sv) + 2, customization_str1.size());
      auto md2 = md1.substr(md1.find("="sv) + 2, md1.size());

      auto msg = hex_to_bytes(msg2);
      auto customization_str = hex_to_bytes(customization_str2);
      auto md = hex_to_bytes(md2);

      std::vector<uint8_t> computed_md(md.size());

      ascon_cxof128::ascon_cxof128_t hasher;
      EXPECT_EQ(hasher.customize(customization_str), ascon_cxof128::ascon_cxof128_status_t::customized);
      EXPECT_EQ(hasher.absorb(msg), ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
      EXPECT_EQ(hasher.finalize(), ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
      EXPECT_EQ(hasher.squeeze(computed_md), ascon_cxof128::ascon_cxof128_status_t::squeezed_output);

      EXPECT_EQ(computed_md, md);

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

TEST(AsconCXOF128, KnownAnswerTests)
{
  ascon_cxof128_KAT_runner("./kats/ascon_cxof128.kat");
}

TEST(AsconCXOF128, ACVPKnownAnswerTests)
{
  ascon_cxof128_KAT_runner("./kats/ascon_cxof128.acvp.kat");
}
