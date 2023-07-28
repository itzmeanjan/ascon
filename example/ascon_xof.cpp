#include "hashing/ascon_xof.hpp"
#include <iostream>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include
// example/ascon_xof.cpp
int
main()
{
  constexpr size_t msg_len = 64; // bytes
  constexpr size_t dig_len = 64; // bytes

  std::vector<uint8_t> msg(msg_len);
  std::vector<uint8_t> out(dig_len);

  auto _msg = std::span(msg);
  auto _out = std::span(out);

  ascon_utils::random_data(_msg);

  ascon_xof::ascon_xof_t hasher;
  hasher.absorb(_msg);
  hasher.finalize();
  hasher.squeeze(_out);

  std::cout << "Ascon Xof\n\n";
  std::cout << "Message :\t" << ascon_utils::to_hex(_msg) << "\n";
  std::cout << "Digest  :\t" << ascon_utils::to_hex(_out) << "\n";

  return EXIT_SUCCESS;
}
