#include "ascon/hashes/ascon_hash256.hpp"
#include "example_helper.hpp"
#include <array>
#include <cassert>
#include <iostream>
#include <vector>

int
main()
{
  constexpr size_t msg_byte_len = 64;

  std::vector<uint8_t> msg(msg_byte_len);
  std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> digest{};

  generate_random_data<uint8_t>(msg);

  ascon_hash256::ascon_hash256_t hasher;
  assert(hasher.absorb(msg));
  assert(hasher.finalize());
  assert(hasher.digest(digest));

  std::cout << "Ascon-Hash256\n\n";
  std::cout << "Message :\t" << bytes_to_hex_string(msg) << "\n";
  std::cout << "Digest  :\t" << bytes_to_hex_string(digest) << "\n";

  return EXIT_SUCCESS;
}
