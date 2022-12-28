#include "ascon.hpp"
#include <iostream>

// Compile & execute with
//
// g++ -std=c++20 -O3 -I ./include example/ascon_hasha.cpp && ./a.out
int
main()
{
  constexpr const size_t msg_len = 1024; // bytes
  constexpr const size_t out_len = 32;   // bytes

  // acquire resources
  uint8_t* msg = static_cast<uint8_t*>(malloc(msg_len)); // input
  uint8_t* out = static_cast<uint8_t*>(malloc(out_len)); // digest

  // prepare input
#if defined __clang__
#pragma unroll 8
#endif
  for (size_t i = 0; i < msg_len; i++) {
    msg[i] = static_cast<uint8_t>(i);
  }

  // compute digest using Ascon-HashA
  ascon::hash_a(msg, msg_len, out);
  // digest as hex string
  const std::string digest = ascon_utils::to_hex(out, out_len);

  std::cout << "Ascon-HashA digest :\t" << digest << std::endl;

  // deallocate resources
  free(msg);
  free(out);

  return EXIT_SUCCESS;
}
