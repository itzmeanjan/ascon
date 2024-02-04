#include "auth/ascon_prfs.hpp"
#include <iostream>
#include <vector>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -mtune=native -I ./include -I ./subtle/include examples/ascon_prfs.cpp
int
main()
{
  constexpr size_t msg_len = 8; // bytes
  static_assert(msg_len <= ascon_prfs::MAX_MSG_LEN, "Ascon-PRFShort can authenticate at max 16 -bytes message.");

  std::vector<uint8_t> key(ascon_prfs::KEY_LEN);
  std::vector<uint8_t> msg(msg_len);
  std::vector<uint8_t> tag(ascon_prfs::MAX_TAG_LEN);

  auto _key = std::span<uint8_t, ascon_prfs::KEY_LEN>(key);
  auto _msg = std::span(msg);
  auto _tag = std::span<uint8_t, ascon_prfs::MAX_TAG_LEN>(tag);

  // Generate random key and message
  ascon_utils::random_data<uint8_t>(_key);
  ascon_utils::random_data(_msg);

  {
    using namespace ascon_prfs;

    // 1) Authenticates a short message i.e. message must be <= 16 -bytes in
    // length, given 16 -bytes secret key. Computes 16 -bytes tag.
    prfs_authenticate(_key, _msg, _tag);
    // 2) Verifies 16 -bytes authentication tag, computed for a short (<=16
    // -bytes) message, using a 16 -bytes secret key. Returns truth value, in
    // case of successful authentication check, otherwise returns false.
    bool flag = prfs_verify(_key, _msg, _tag);

    // Authentication check must pass !
    assert(flag);
  }

  {
    using namespace ascon_utils;

    std::cout << "Ascon-PRFShort\n\n";
    std::cout << "Key     :\t" << to_hex(_key) << "\n";
    std::cout << "Message :\t" << to_hex(_msg) << "\n";
    std::cout << "Tag     :\t" << to_hex(_tag) << "\n";
  }

  return EXIT_SUCCESS;
}
