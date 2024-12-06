#include "ascon/hashes/ascon_xof128.hpp"
#include "test_helper.hpp"
#include <fstream>
#include <gtest/gtest.h>

TEST(AsconXof128, KnownAnswerTests)
{
  using namespace std::literals;

  const std::string kat_file = "./kats/ascon_xof128.kat";
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

      auto msg = hex_to_bytes(msg2);
      auto md = hex_to_bytes(md2);

      std::vector<uint8_t> computed_md(md.size());

      ascon_xof128::ascon_xof128_t hasher;
      EXPECT_TRUE(hasher.absorb(msg));
      EXPECT_TRUE(hasher.finalize());
      EXPECT_TRUE(hasher.squeeze(computed_md));

      EXPECT_EQ(computed_md, md);

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}
