#include "hashing/ascon_xofa.hpp"
#include <iostream>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include examples/ascon_xofa.cpp
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

  ascon_xofa::ascon_xofa_t hasher;
  hasher.absorb(_msg);
  hasher.finalize();
  hasher.squeeze(_out);

  std::cout << "Ascon XofA\n\n";
  std::cout << "Message :\t" << ascon_utils::to_hex(_msg) << "\n";
  std::cout << "Digest  :\t" << ascon_utils::to_hex(_out) << "\n";

  return EXIT_SUCCESS;
}
