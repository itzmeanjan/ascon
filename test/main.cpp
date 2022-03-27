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

  return EXIT_SUCCESS;
}
