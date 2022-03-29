#include "test_cipher.hpp"
#include "test_hash.hpp"
#include "test_permutation.hpp"
#include <iostream>

int
main(int argc, char** argv)
{
  ascon_test::p_a();
  std::cout << "[test] passed ascon permutation `p_a`" << std::endl;

  ascon_test::hash();
  std::cout << "[test] passed ascon hash" << std::endl;

  ascon_test::hash_a();
  std::cout << "[test] passed ascon hashA" << std::endl;

  for (size_t data_len = 0; data_len < 32; data_len++) {
#pragma unroll 8
    for (size_t text_len = 0; text_len < 32; text_len++) {
      ascon_test::ascon_128(data_len, text_len);
      ascon_test::ascon_128a(data_len, text_len);
    }
  }

  std::cout << "[test] passed ascon-128" << std::endl;
  std::cout << "[test] passed ascon-128a" << std::endl;

  return EXIT_SUCCESS;
}
