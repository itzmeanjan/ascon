#include "test/test_ascon.hpp"
#include <iostream>

int
main()
{
  ascon_test::p_a();
  std::cout << "[test] Ascon permutation `p_a`" << std::endl;

  for (size_t dlen = 0; dlen < 32; dlen++) {
    for (size_t ctlen = 0; ctlen < 32; ctlen++) {
      ascon_test::ascon_128(dlen, ctlen);
      ascon_test::ascon_128a(dlen, ctlen);
      ascon_test::ascon_80pq(dlen, ctlen);
    }
  }

  std::cout << "[test] Ascon-128 AEAD" << std::endl;
  std::cout << "[test] Ascon-128a AEAD" << std::endl;
  std::cout << "[test] Ascon-80pq AEAD" << std::endl;

  return EXIT_SUCCESS;
}
