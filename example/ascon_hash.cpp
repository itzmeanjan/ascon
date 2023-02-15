#include "hash.hpp"
#include <iostream>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include example/ascon_hash.cpp
int
main()
{
  constexpr size_t msg_len = 64; // bytes
  constexpr size_t out_len = 32; // bytes

  // acquire resources
  uint8_t* msg = static_cast<uint8_t*>(malloc(msg_len)); // input
  uint8_t* out = static_cast<uint8_t*>(malloc(out_len)); // digest

  ascon_utils::random_data(msg, msg_len);
  ascon::hash(msg, msg_len, out);

  std::cout << "Ascon Hash\n\n";
  std::cout << "Message :\t" << ascon_utils::to_hex(msg, msg_len) << "\n";
  std::cout << "Digest  :\t" << ascon_utils::to_hex(out, out_len) << "\n";

  // deallocate resources
  free(msg);
  free(out);

  return EXIT_SUCCESS;
}
