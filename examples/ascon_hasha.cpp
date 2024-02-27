#include "ascon/hashing/ascon_hasha.hpp"
#include <iostream>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include examples/ascon_hasha.cpp
int
main()
{
  constexpr size_t msg_len = 64; // bytes

  std::vector<uint8_t> msg(msg_len);
  std::vector<uint8_t> out(ascon_hasha::DIGEST_LEN);

  auto _msg = std::span(msg);
  auto _out = std::span<uint8_t, ascon_hasha::DIGEST_LEN>(out);

  ascon_utils::random_data(_msg);

  ascon_hasha::ascon_hasha_t hasher;
  hasher.absorb(_msg);
  hasher.finalize();
  hasher.digest(_out);

  std::cout << "Ascon HashA\n\n";
  std::cout << "Message :\t" << ascon_utils::to_hex(_msg) << "\n";
  std::cout << "Digest  :\t" << ascon_utils::to_hex(_out) << "\n";

  return EXIT_SUCCESS;
}
