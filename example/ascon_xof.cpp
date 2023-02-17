#include "ascon_xof.hpp"
#include <iostream>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include example/ascon_xof.cpp
int
main()
{
  constexpr size_t msg_len = 64; // bytes
  constexpr size_t dig_len = 64; // bytes

  // acquire resources
  uint8_t* msg = static_cast<uint8_t*>(malloc(msg_len)); // input
  uint8_t* out = static_cast<uint8_t*>(malloc(dig_len));

  ascon_utils::random_data(msg, msg_len);

  // Opting for using incremental hashing API by passing explicit value `true`
  // to template parameter.
  ascon::ascon_xof<true> hasher;
  hasher.absorb(msg, msg_len);
  hasher.finalize();

  // can request arbitrary many bytes of digest, arbitrary many times
  for (size_t off = 0; off < dig_len; off += 2) {
    hasher.read(out + off, 2);
  }

  std::cout << "Ascon XOF\n\n";
  std::cout << "Message :\t" << ascon_utils::to_hex(msg, msg_len) << "\n";
  std::cout << "Digest  :\t" << ascon_utils::to_hex(out, dig_len) << "\n";

  // deallocate resources
  free(msg);
  free(out);

  return EXIT_SUCCESS;
}
