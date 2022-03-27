#include "test_permutation.hpp"
#include <iostream>

int
main(int argc, char** argv)
{
  ascon_test::p_a();
  std::cout << "[test] passed ascon permutation `p_a`" << std::endl;

  return EXIT_SUCCESS;
}
