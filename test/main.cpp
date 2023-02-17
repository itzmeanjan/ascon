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

  ascon_test::test_ascon_hasha(64);
  ascon_test::test_ascon_hasha(128);
  ascon_test::test_ascon_hasha(256);
  ascon_test::test_ascon_hasha(512);
  ascon_test::test_ascon_hasha(1024);
  ascon_test::test_ascon_hasha(2048);
  ascon_test::test_ascon_hasha(4096);
  std::cout << "[test] Ascon-HashA oneshot and incremental hashing API\n";

  ascon_test::test_ascon_xof(64, 64);
  ascon_test::test_ascon_xof(128, 128);
  ascon_test::test_ascon_xof(256, 256);
  ascon_test::test_ascon_xof(512, 512);
  ascon_test::test_ascon_xof(1024, 1024);
  ascon_test::test_ascon_xof(2048, 2048);
  ascon_test::test_ascon_xof(4096, 4096);
  std::cout << "[test] Ascon-XOF oneshot and incremental hashing API\n";

  ascon_test::test_ascon_xofa(64, 64);
  ascon_test::test_ascon_xofa(128, 128);
  ascon_test::test_ascon_xofa(256, 256);
  ascon_test::test_ascon_xofa(512, 512);
  ascon_test::test_ascon_xofa(1024, 1024);
  ascon_test::test_ascon_xofa(2048, 2048);
  ascon_test::test_ascon_xofa(4096, 4096);
  std::cout << "[test] Ascon-XOFA oneshot and incremental hashing API\n";

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
