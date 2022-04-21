#include "test_accel_cipher.hpp"
#include "test_accel_hash.hpp"
#include "test_cipher.hpp"
#include "test_hash.hpp"
#include "test_permutation.hpp"
#include <iostream>

#define MSG_LEN 64ul  // per work-item input message length ( bytes )
#define AD_LEN 32ul   // per work-item input associated data length ( bytes )
#define CT_LEN 32ul  // per work-item input plain/ cipher text length ( bytes )
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
      ascon_test::ascon_80pq(data_len, text_len);
    }
  }

  std::cout << "[test] passed ascon-128" << std::endl;
  std::cout << "[test] passed ascon-128a" << std::endl;
  std::cout << "[test] passed ascon-80pq" << std::endl;

  sycl::default_selector s{};
  sycl::device d{ s };
  sycl::context c{ d };
  sycl::queue q{ c, d };

  for (size_t m_len = 0; m_len < MSG_LEN; m_len++) {
    accel_ascon_test::hash(q, m_len, WI_CNT, WI_SIZE);
  }
  std::cout << "[test] passed data-parallel ascon-hash" << std::endl;

  for (size_t m_len = 0; m_len < MSG_LEN; m_len++) {
    accel_ascon_test::hash_a(q, m_len, WI_CNT, WI_SIZE);
  }
  std::cout << "[test] passed data-parallel ascon-hashA" << std::endl;

  for (size_t d_len = 0; d_len < AD_LEN; d_len++) {
    for (size_t c_len = 0; c_len < CT_LEN; c_len++) {
      accel_ascon_test::ascon_128(q, d_len, c_len, WI_CNT, WI_SIZE);
    }
  }
  std::cout << "[test] passed data-parallel ascon-128" << std::endl;

  for (size_t d_len = 0; d_len < AD_LEN; d_len++) {
    for (size_t c_len = 0; c_len < CT_LEN; c_len++) {
      accel_ascon_test::ascon_128a(q, d_len, c_len, WI_CNT, WI_SIZE);
    }
  }
  std::cout << "[test] passed data-parallel ascon-128a" << std::endl;

  for (size_t d_len = 0; d_len < AD_LEN; d_len++) {
    for (size_t c_len = 0; c_len < CT_LEN; c_len++) {
      accel_ascon_test::ascon_80pq(q, d_len, c_len, WI_CNT, WI_SIZE);
    }
  }
  std::cout << "[test] passed data-parallel ascon-80pq" << std::endl;

  return EXIT_SUCCESS;
}
