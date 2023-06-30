#include "auth/ascon_mac.hpp"
#include <iostream>
#include <vector>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -mtune=native -I ./include -I
// ./subtle/include example/ascon_mac.cpp
int
main()
{
  constexpr size_t msg_len = 64; // bytes

  std::vector<uint8_t> key(ascon_mac::KEY_LEN);
  std::vector<uint8_t> msg(msg_len);
  std::vector<uint8_t> rcvd_tag(ascon_mac::TAG_LEN);
  std::vector<uint8_t> cmtd_tag(ascon_mac::TAG_LEN);

  // Generate random key and message
  ascon_utils::random_data(key.data(), key.size());
  ascon_utils::random_data(msg.data(), msg.size());

  // Sender
  //
  // 1) Sending party initializes MAC with 16 -bytes secret key.
  ascon_mac::ascon_mac mac_snd(key.data());
  // 2) Sender authenticates arbitrary byte length wide message, by invoking
  // authenticate routine as many times required.
  mac_snd.authenticate(msg.data(), msg.size());
  // 3) Sender finalizes state of MAC function, computing 16 -bytes
  // authentication tag ( or mac ).
  mac_snd.finalize(rcvd_tag.data());

  // Receiver
  //
  // 1) Receiving party initializes MAC with 16 -bytes secret key.
  ascon_mac::ascon_mac mac_rcv(key.data());
  // 2) Receiver also authenticates arbitrary bytes input message, by invoking
  // authenticate routine, as many times required.
  mac_rcv.authenticate(msg.data(), msg.size());
  // 3) Receiver finalizes state of MAC function, computing 16 -bytes tag.
  mac_rcv.finalize(cmtd_tag.data());
  // 4) Receiver verifies if locally computed tag is same as the one computed by
  // sender and shared over-the-wire.
  bool flag = mac_rcv.verify(rcvd_tag.data(), cmtd_tag.data());

  // Authentication check must pass !
  assert(flag);

  {
    using namespace ascon_utils;

    std::cout << "Ascon-MAC\n\n";
    std::cout << "Key          :\t" << to_hex(key.data(), key.size()) << "\n";
    std::cout << "Message      :\t" << to_hex(msg.data(), msg.size()) << "\n";
    std::cout << "Sender Tag   :\t" << to_hex(rcvd_tag.data(), rcvd_tag.size())
              << "\n";
    std::cout << "Receiver Tag :\t" << to_hex(cmtd_tag.data(), cmtd_tag.size())
              << "\n";
  }

  return EXIT_SUCCESS;
}
