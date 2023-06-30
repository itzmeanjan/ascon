#include "auth/ascon_prfs.hpp"
#include <iostream>
#include <vector>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -mtune=native -I ./include -I
// ./subtle/include example/ascon_prfs.cpp
int
main()
{
  constexpr size_t msg_len = 8; // bytes

  std::vector<uint8_t> key(ascon_prfs::KEY_LEN);
  std::vector<uint8_t> msg(msg_len);
  std::vector<uint8_t> tag(ascon_prfs::MAX_TAG_LEN);

  // Generate random key and message
  ascon_utils::random_data(key.data(), key.size());
  ascon_utils::random_data(msg.data(), msg.size());

  {
    using namespace ascon_prfs;

    // 1) Authenticates a short message i.e. message must be <= 16 -bytes in
    // length, given 16 -bytes secret key. Computes 16 -bytes tag.
    prfs_authenticate(key.data(), msg.data(), msg.size(), tag.data());
    // 2) Verifies 16 -bytes authentication tag, computed for a short (<=16
    // -bytes) message, using a 16 -bytes secret key. Returns truth value, in
    // case of successful authentication check, otherwise returns false.
    bool flag = prfs_verify(key.data(), msg.data(), msg.size(), tag.data());

    // Authentication check must pass !
    assert(flag);
  }

  {
    using namespace ascon_utils;

    std::cout << "Ascon-PRFShort\n\n";
    std::cout << "Key     :\t" << to_hex(key.data(), key.size()) << "\n";
    std::cout << "Message :\t" << to_hex(msg.data(), msg.size()) << "\n";
    std::cout << "Tag     :\t" << to_hex(tag.data(), tag.size()) << "\n";
  }

  return EXIT_SUCCESS;
}
