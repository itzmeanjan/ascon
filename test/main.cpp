#include "test/test_ascon.hpp"
#include <iostream>

int
main()
{
  ascon_test::p_a();
  std::cout << "[test] Ascon permutation `p_a`\n";

  ascon_test::test_ascon_hash(64);
  ascon_test::test_ascon_hash(128);
  ascon_test::test_ascon_hash(256);
  ascon_test::test_ascon_hash(512);
  ascon_test::test_ascon_hash(1024);
  ascon_test::test_ascon_hash(2048);
  ascon_test::test_ascon_hash(4096);
  std::cout << "[test] Ascon-Hash oneshot and incremental hashing API\n";

  for (size_t dlen = 0; dlen < 32; dlen++) {
    for (size_t ctlen = 0; ctlen < 32; ctlen++) {
      ascon_test::ascon_128(dlen, ctlen);
      ascon_test::ascon_128a(dlen, ctlen);
      ascon_test::ascon_80pq(dlen, ctlen);
    }
  }

  std::cout << "[test] Ascon-128 AEAD\n";
  std::cout << "[test] Ascon-128a AEAD\n";
  std::cout << "[test] Ascon-80pq AEAD\n";

  return EXIT_SUCCESS;
}
