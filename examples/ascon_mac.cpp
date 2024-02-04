#include "auth/ascon_mac.hpp"
#include <iostream>
#include <vector>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -mtune=native -I ./include -I ./subtle/include examples/ascon_mac.cpp
int
main()
{
  constexpr size_t msg_len = 64; // bytes

  std::vector<uint8_t> key(ascon_mac::KEY_LEN);
  std::vector<uint8_t> msg(msg_len);
  std::vector<uint8_t> rcvd_tag(ascon_mac::TAG_LEN);
  std::vector<uint8_t> cmtd_tag(ascon_mac::TAG_LEN);

  auto _key = std::span<uint8_t, ascon_mac::KEY_LEN>(key);
  auto _msg = std::span(msg);
  auto _rcvd_tag = std::span<uint8_t, ascon_mac::TAG_LEN>(rcvd_tag);
  auto _cmtd_tag = std::span<uint8_t, ascon_mac::TAG_LEN>(cmtd_tag);

  // Generate random key and message
  ascon_utils::random_data<uint8_t>(_key);
  ascon_utils::random_data(_msg);

  // Sender
  //
  // 1) Sending party initializes MAC with 16 -bytes secret key.
  ascon_mac::ascon_mac_t mac_snd(_key);
  // 2) Sender authenticates arbitrary byte length wide message, by invoking
  // authenticate routine as many times required.
  mac_snd.authenticate(_msg);
  // 3) Sender finalizes state of MAC function, computing 16 -bytes
  // authentication tag ( or mac ).
  mac_snd.finalize(_rcvd_tag);

  // Receiver
  //
  // 1) Receiving party initializes MAC with 16 -bytes secret key.
  ascon_mac::ascon_mac_t mac_rcv(_key);
  // 2) Receiver also authenticates arbitrary bytes input message, by invoking
  // authenticate routine, as many times required.
  mac_rcv.authenticate(_msg);
  // 3) Receiver finalizes state of MAC function, computing 16 -bytes tag.
  mac_rcv.finalize(_cmtd_tag);
  // 4) Receiver verifies if locally computed tag is same as the one computed by
  // sender and shared over-the-wire.
  bool flag = mac_rcv.verify(_rcvd_tag, _cmtd_tag);

  // Authentication check must pass !
  assert(flag);

  {
    using namespace ascon_utils;

    std::cout << "Ascon-MAC\n\n";
    std::cout << "Key          :\t" << to_hex(_key) << "\n";
    std::cout << "Message      :\t" << to_hex(_msg) << "\n";
    std::cout << "Sender Tag   :\t" << to_hex(_rcvd_tag) << "\n";
    std::cout << "Receiver Tag :\t" << to_hex(_cmtd_tag) << "\n";
  }

  return EXIT_SUCCESS;
}
