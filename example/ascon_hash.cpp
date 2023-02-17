#include "ascon_hash.hpp"
#include <iostream>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include example/ascon_hash.cpp
int
main()
{
  constexpr size_t msg_len = 64; // bytes

  // acquire resources
  uint8_t* msg = static_cast<uint8_t*>(malloc(msg_len)); // input
  uint8_t* out = static_cast<uint8_t*>(malloc(ascon::ASCON_HASH_DIGEST_LEN));

  ascon_utils::random_data(msg, msg_len);

  // Opting for using incremental hashing API by passing explicit value `true`
  // to template parameter.
  ascon::ascon_hash<true> hasher;
  hasher.absorb(msg, msg_len);
  hasher.finalize();
  hasher.digest(out);

  std::cout << "Ascon Hash\n\n";
  std::cout << "Message :\t" << ascon_utils::to_hex(msg, msg_len) << "\n";
  std::cout << "Digest  :\t" << ascon_utils::to_hex(out, 32) << "\n";

  // deallocate resources
  free(msg);
  free(out);

  return EXIT_SUCCESS;
}
