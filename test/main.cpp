#include "test_accel_hash.hpp"
#include "test_cipher.hpp"
#include "test_hash.hpp"
#include "test_permutation.hpp"
#include <iostream>

#define MSG_LEN 64ul  // per work-item input message length ( bytes )
#define WI_CNT 1024ul // SYCL work-item count
#define WI_SIZE 32ul  // SYCL work-group size

int
main()
{
  ascon_test::p_a();
  std::cout << "[test] passed ascon permutation `p_a`" << std::endl;

  ascon_test::hash();
  std::cout << "[test] passed ascon-hash" << std::endl;

  ascon_test::hash_a();
  std::cout << "[test] passed ascon-hashA" << std::endl;

  for (size_t data_len = 0; data_len < 32; data_len++) {
    for (size_t text_len = 0; text_len < 32; text_len++) {
      ascon_test::ascon_128(data_len, text_len);
      ascon_test::ascon_128a(data_len, text_len);
    }
  }

  std::cout << "[test] passed ascon-128" << std::endl;
  std::cout << "[test] passed ascon-128a" << std::endl;

  sycl::default_selector s{};
  sycl::device d{ s };
  sycl::context c{};
  sycl::queue q{ c, d };

  accel_ascon_test::hash(q, MSG_LEN, WI_CNT, WI_SIZE);
  std::cout << "[test] passed data-parallel ascon-hash" << std::endl;

  accel_ascon_test::hash_a(q, MSG_LEN, WI_CNT, WI_SIZE);
  std::cout << "[test] passed data-parallel ascon-hashA" << std::endl;

  return EXIT_SUCCESS;
}
