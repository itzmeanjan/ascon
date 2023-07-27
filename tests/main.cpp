#include "aead/test_ascon128_aead.hpp"
#include "aead/test_ascon128a_aead.hpp"
#include "aead/test_ascon80pq_aead.hpp"
#include "auth/test_ascon_mac.hpp"
#include "auth/test_ascon_prf.hpp"
#include "auth/test_ascon_prfs.hpp"
#include "hashing/test_ascon_hash.hpp"
#include "hashing/test_ascon_hasha.hpp"
#include "hashing/test_ascon_xof.hpp"
#include "hashing/test_ascon_xofa.hpp"
#include "test_permutation.hpp"
#include <iostream>

int
main()
{
  ascon_test::test_ascon_hash(4096);
  ascon_test::test_ascon_hash_kat();
  std::cout << "[test] Ascon-Hash\n";

  ascon_test::test_ascon_hasha(4096);
  ascon_test::test_ascon_hasha_kat();
  std::cout << "[test] Ascon-HashA\n";

  ascon_test::test_ascon_xof(4096, 4096);
  ascon_test::test_ascon_xof_kat();
  std::cout << "[test] Ascon-Xof\n";

  ascon_test::test_ascon_xofa(4096, 4096);
  ascon_test::test_ascon_xofa_kat();
  std::cout << "[test] Ascon-XofA\n";

  ascon_test::test_ascon_prf_kat();
  std::cout << "[test] Ascon-PRF\n";

  ascon_test::test_ascon_mac_kat();
  std::cout << "[test] Ascon-MAC\n";

  ascon_test::test_ascon_prfs_kat();
  std::cout << "[test] Ascon-PRFShort\n";

  return EXIT_SUCCESS;
}
