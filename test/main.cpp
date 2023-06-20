#include "test/test_ascon_suite.hpp"
#include <iostream>

int
main()
{
  ascon_test::p_a();
  std::cout << "[test] Ascon permutation `p_a`\n";

  for (size_t dlen = 0; dlen <= 32; dlen++) {
    for (size_t ctlen = 0; ctlen <= 32; ctlen++) {
      ascon_test::ascon128_aead(dlen, ctlen);
      ascon_test::ascon128a_aead(dlen, ctlen);
      ascon_test::ascon80pq_aead(dlen, ctlen);
    }
  }

  ascon_test::ascon128_aead_kat();
  std::cout << "[test] Ascon-128 AEAD\n";

  ascon_test::ascon128a_aead_kat();
  std::cout << "[test] Ascon-128a AEAD\n";

  ascon_test::ascon80pq_aead_kat();
  std::cout << "[test] Ascon-80pq AEAD\n";

  ascon_test::test_ascon_hash(4096);
  ascon_test::test_ascon_hash_kat();
  std::cout << "[test] Ascon-Hash\n";

  ascon_test::test_ascon_hasha(4096);
  ascon_test::test_ascon_hasha_kat();
  std::cout << "[test] Ascon-HashA\n";

  ascon_test::test_ascon_xof(4096, 4096);
  ascon_test::test_ascon_xof_kat();
  std::cout << "[test] Ascon-Xof\n";

  ascon_test::test_ascon_xofa(64, 64);
  ascon_test::test_ascon_xofa(128, 128);
  ascon_test::test_ascon_xofa(256, 256);
  ascon_test::test_ascon_xofa(512, 512);
  ascon_test::test_ascon_xofa(1024, 1024);
  ascon_test::test_ascon_xofa(2048, 2048);
  ascon_test::test_ascon_xofa(4096, 4096);
  std::cout << "[test] Ascon-XOFA oneshot and incremental hashing API\n";

  return EXIT_SUCCESS;
}
