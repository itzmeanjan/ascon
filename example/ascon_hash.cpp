#include "hashing/ascon_hash.hpp"
#include <iostream>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include
// example/ascon_hash.cpp
int
main()
{
  constexpr size_t msg_len = 64; // bytes

  std::vector<uint8_t> msg(msg_len);
  std::vector<uint8_t> out(ascon_hash::DIGEST_LEN);

  auto _msg = std::span(msg);
  auto _out = std::span<uint8_t, ascon_hash::DIGEST_LEN>(out);

  ascon_utils::random_data(_msg);

  ascon_hash::ascon_hash_t hasher;
  hasher.absorb(_msg);
  hasher.finalize();
  hasher.digest(_out);

  std::cout << "Ascon Hash\n\n";
  std::cout << "Message :\t" << ascon_utils::to_hex(_msg) << "\n";
  std::cout << "Digest  :\t" << ascon_utils::to_hex(_out) << "\n";

  return EXIT_SUCCESS;
}
