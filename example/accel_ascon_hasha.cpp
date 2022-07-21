#include "accel_ascon.hpp"

// Compile it with:
//
// dpcpp -std=c++20 -fsycl -O3 -I ./include example/accel_ascon_hasha.cpp
int
main()
{
  sycl::default_selector s{};
  sycl::device d{ s };
  sycl::context c{ d };
  sycl::queue q{ c, d };

  // these many Ascon-HashA digests to be computed in-parallel
  constexpr size_t wi_cnt = 1024ul;
  // these many work-items to be grouped into single work-group
  constexpr size_t wg_size = 32ul;
  // each work-item will compute Ascon-HashA digest on 64 input bytes
  constexpr size_t per_wi_msg_len = 64ul;
  // each work-item will produce Ascon-HashA digest of 32 -bytes
  constexpr size_t per_wi_dig_len = 32ul;

  // total memory allocation for keeping input bytes ( for all work-items )
  constexpr size_t i_len = wi_cnt * per_wi_msg_len;
  // total memory allocation for keeping output digests ( for all work-items )
  constexpr size_t o_len = wi_cnt * per_wi_dig_len;

  uint8_t* msg = static_cast<uint8_t*>(sycl::malloc_shared(i_len, q));
  uint8_t* dig = static_cast<uint8_t*>(sycl::malloc_shared(o_len, q));

  using evt = sycl::event;
  using evts = std::vector<sycl::event>;

  // prepare random input bytes on host
  ascon_utils::random_data(msg, i_len);
  evt e0 = q.memset(dig, 0, o_len);

  // data-parallelly compute Ascon-HashA digests for `wi_cnt` -many independent,
  // non-overlapping input byte sequences & for each of them contiguously place
  // 32 digest bytes in respective memory locations
  evts e1{ e0 };
  evt e2 = accel_ascon::hash_a(q, msg, i_len, dig, o_len, wi_cnt, wg_size, e1);

  // host synchronization
  e2.wait();

  // sequentially rerun same computation on host to be sure that
  // data-parallel computation didn't end up computing some bytes wrong !
  for (size_t wi = 0; wi < wi_cnt; wi++) {
    uint8_t dig_[32];

    const size_t i_off = wi * per_wi_msg_len;
    const size_t o_off = wi * per_wi_dig_len;

    // compute Ascon-HashA digest on single text byte slice;
    // do it for `wi_cnt` -many times !
    ascon::hash_a(msg + i_off, per_wi_msg_len, dig_);

    // now do a byte-by-byte comparison !
    for (size_t b = 0; b < per_wi_dig_len; b++) {
      assert(dig_[b] == dig[o_off + b]);
    }
  }

  std::cout << "Accelerated Ascon-HashA works !" << std::endl;

  // deallocate acquired resources
  sycl::free(msg, q);
  sycl::free(dig, q);

  return EXIT_SUCCESS;
}
