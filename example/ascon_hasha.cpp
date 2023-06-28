#include "hashing/ascon_hasha.hpp"
#include <iostream>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include
// example/ascon_hasha.cpp
int
main()
{
  constexpr size_t msg_len = 64; // bytes

  // acquire resources
  uint8_t* msg = static_cast<uint8_t*>(malloc(msg_len));
  uint8_t* out = static_cast<uint8_t*>(malloc(ascon_hasha::DIGEST_LEN));

  ascon_utils::random_data(msg, msg_len);

  ascon_hasha::ascon_hasha hasher;
  hasher.absorb(msg, msg_len);
  hasher.finalize();
  hasher.digest(out);

  std::cout << "Ascon HashA\n\n";
  std::cout << "Message :\t" << ascon_utils::to_hex(msg, msg_len) << "\n";
  std::cout << "Digest  :\t" << ascon_utils::to_hex(out, 32) << "\n";

  // deallocate resources
  free(msg);
  free(out);

  return EXIT_SUCCESS;
}
