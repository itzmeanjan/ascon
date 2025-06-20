#include "ascon/hashes/ascon_xof128.hpp"
#include "example_helper.hpp"
#include <cassert>
#include <iostream>
#include <vector>

int
main()
{
  constexpr size_t msg_byte_len = 64;
  constexpr size_t out_byte_len = 64;

  std::vector<uint8_t> msg(msg_byte_len);
  std::vector<uint8_t> out(out_byte_len);

  generate_random_data<uint8_t>(msg);

  ascon_xof128::ascon_xof128_t hasher;
  assert(hasher.absorb(msg) == ascon_xof128::ascon_xof128_status_t::absorbed_data);
  assert(hasher.finalize() == ascon_xof128::ascon_xof128_status_t::finalized_data_absorption_phase);
  assert(hasher.squeeze(out) == ascon_xof128::ascon_xof128_status_t::squeezed_output);

  std::cout << "Ascon-XOF128\n\n";
  std::cout << "Message :\t" << bytes_to_hex_string(msg) << "\n";
  std::cout << "Digest  :\t" << bytes_to_hex_string(out) << "\n";

  return EXIT_SUCCESS;
}
