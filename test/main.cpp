#include "test/test_ascon.hpp"
#include <iostream>

int
main()
{
  ascon_test::p_a();
  std::cout << "[test] Ascon permutation `p_a`" << std::endl;

  ascon_test::hash();
  std::cout << "[test] Ascon-hash" << std::endl;

  ascon_test::hash_a();
  std::cout << "[test] Ascon-hashA" << std::endl;

  for (size_t data_len = 0; data_len < 32; data_len++) {
    for (size_t text_len = 0; text_len < 32; text_len++) {
      ascon_test::ascon_128(data_len, text_len);
      ascon_test::ascon_128a(data_len, text_len);
      ascon_test::ascon_80pq(data_len, text_len);
    }
  }

  std::cout << "[test] Ascon-128 AEAD" << std::endl;
  std::cout << "[test] Ascon-128a AEAD" << std::endl;
  std::cout << "[test] Ascon-80pq AEAD" << std::endl;

  return EXIT_SUCCESS;
}
