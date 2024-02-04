#include "auth/ascon_prf.hpp"
#include <iostream>
#include <vector>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -mtune=native -I ./include -I ./subtle/include examples/ascon_prf.cpp
int
main()
{
  constexpr size_t msg_len = 64; // bytes
  constexpr size_t tag_len = 64; // bytes

  std::vector<uint8_t> key(ascon_prf::KEY_LEN);
  std::vector<uint8_t> msg(msg_len);
  std::vector<uint8_t> tag(tag_len);

  auto _key = std::span<uint8_t, ascon_prf::KEY_LEN>(key);
  auto _msg = std::span(msg);
  auto _tag = std::span(tag);

  // Generate random key and message
  ascon_utils::random_data<uint8_t>(_key);
  ascon_utils::random_data(_msg);

  // 1) Initialize PRF with 16 -bytes secret key
  ascon_prf::ascon_prf_t prf(_key);
  // 2) Absorb arbitrary many message bytes into initialized PRF state, by
  // invoking absorb routine any number of times required.
  prf.absorb(_msg);
  // 3) Finalize PRF state, when all message bytes are absorbed into PRF.
  prf.finalize();
  // 4) Squeeze arbitrary many tag bytes from finalized PRF state, by invoking
  // squeeze routine any number of times required.
  prf.squeeze(_tag);

  {
    using namespace ascon_utils;

    std::cout << "Ascon-PRF\n\n";
    std::cout << "Key     :\t" << to_hex(_key) << "\n";
    std::cout << "Message :\t" << to_hex(_msg) << "\n";
    std::cout << "Tag     :\t" << to_hex(_tag) << "\n";
  }

  return EXIT_SUCCESS;
}
