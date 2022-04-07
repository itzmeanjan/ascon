#include "bench_utils.hpp"
#include "table.hpp" // taken from https://github.com/haarcuba/cpp-text-table/blob/f217b3d/TextTable.h
#include <iostream>

int
main()
{

// Which one of available accelerator devices to be chosen in runtime
#if defined SYCL_TARGET_CPU
  sycl::cpu_selector s{};
#pragma message("Using SYCL cpu selector !")
#elif defined SYCL_TARGET_GPU
  sycl::gpu_selector s{};
#pragma message("Using SYCL gpu selector !")
#else
  sycl::default_selector s{};
#pragma message("Using SYCL default selector !")
#endif

  sycl::device d{ s };
  sycl::context c{ d };
  // must enable queue profiling !
  sycl::queue q{ c, d, sycl::property::queue::enable_profiling{} };

  std::cout << "running on " << d.get_info<sycl::info::device::name>()
            << std::endl
            << std::endl;

  // each data-parallel Ascon routine to be run for these many rounds
  // before taking mean execution time of important commands
  constexpr size_t itr_cnt = 8ul;
  // as of now I'm using static work-group size, it can be improved such that
  // that SYCL runtime suggestions are well respected !
  constexpr size_t wg_size = 32ul;

  double* ts = static_cast<double*>(std::malloc(sizeof(double) * 3));

  std::cout << "Benchmarking Ascon-Hash" << std::endl << std::endl;

  TextTable t0('-', '|', '+');

  t0.add("SYCL work-items");
  t0.add("host-to-device b/w");
  t0.add("kernel b/w");
  t0.add("device-to-host b/w");
  t0.endOfRow();

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_hash, ts);

    const size_t h2d_size = wi * MSG_LEN;  // host -> device bytes
    const size_t krnl_size = wi * MSG_LEN; // kernel consumed bytes
    const size_t d2h_size = wi << 5;       // device -> host bytes

    t0.add(std::to_string(wi));
    t0.add(to_readable_bandwidth(h2d_size, ts[0]));
    t0.add(to_readable_bandwidth(krnl_size, ts[1]));
    t0.add(to_readable_bandwidth(d2h_size, ts[2]));
    t0.endOfRow();
  }

  t0.setAlignment(1, TextTable::Alignment::RIGHT);
  t0.setAlignment(2, TextTable::Alignment::RIGHT);
  t0.setAlignment(3, TextTable::Alignment::RIGHT);
  std::cout << t0;

  std::cout << std::endl
            << "Benchmarking Ascon-HashA" << std::endl
            << std::endl;

  TextTable t1('-', '|', '+');

  t1.add("SYCL work-items");
  t1.add("host-to-device b/w");
  t1.add("kernel b/w");
  t1.add("device-to-host b/w");
  t1.endOfRow();

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_hashA, ts);

    const size_t h2d_size = wi * MSG_LEN;  // host -> device bytes
    const size_t krnl_size = wi * MSG_LEN; // kernel consumed bytes
    const size_t d2h_size = wi << 5;       // device -> host bytes

    t1.add(std::to_string(wi));
    t1.add(to_readable_bandwidth(h2d_size, ts[0]));
    t1.add(to_readable_bandwidth(krnl_size, ts[1]));
    t1.add(to_readable_bandwidth(d2h_size, ts[2]));
    t1.endOfRow();
  }

  t1.setAlignment(1, TextTable::Alignment::RIGHT);
  t1.setAlignment(2, TextTable::Alignment::RIGHT);
  t1.setAlignment(3, TextTable::Alignment::RIGHT);
  std::cout << t1;

  std::cout << std::endl
            << "Benchmarking Ascon-128 Encrypt" << std::endl
            << std::endl;

  TextTable t2('-', '|', '+');

  t2.add("SYCL work-items");
  t2.add("host-to-device b/w");
  t2.add("kernel b/w");
  t2.add("device-to-host b/w");
  t2.endOfRow();

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_128_encrypt, ts);

    const size_t ct_size = wi * CT_LEN;
    const size_t ad_size = wi * AD_LEN;
    const size_t knt_size = wi * (sizeof(uint64_t) << 1);

    // host -> device bytes
    const size_t h2d_size = ct_size + ad_size + (knt_size << 1);
    // kernel consumed bytes
    const size_t krnl_size = ct_size + ad_size;
    // device -> host bytes
    const size_t d2h_size = ct_size + knt_size;

    t2.add(std::to_string(wi));
    t2.add(to_readable_bandwidth(h2d_size, ts[0]));
    t2.add(to_readable_bandwidth(krnl_size, ts[1]));
    t2.add(to_readable_bandwidth(d2h_size, ts[2]));
    t2.endOfRow();
  }

  t2.setAlignment(1, TextTable::Alignment::RIGHT);
  t2.setAlignment(2, TextTable::Alignment::RIGHT);
  t2.setAlignment(3, TextTable::Alignment::RIGHT);
  std::cout << t2;

  std::cout << std::endl
            << "Benchmarking Ascon-128 Decrypt" << std::endl
            << std::endl;

  TextTable t3('-', '|', '+');

  t3.add("SYCL work-items");
  t3.add("host-to-device b/w");
  t3.add("kernel b/w");
  t3.add("device-to-host b/w");
  t3.endOfRow();

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_128_decrypt, ts);

    const size_t ct_size = wi * CT_LEN;
    const size_t ad_size = wi * AD_LEN;
    const size_t knt_size = wi * (sizeof(uint64_t) << 1);
    const size_t flg_size = wi * sizeof(bool);

    // host -> device bytes
    const size_t h2d_size = ct_size + ad_size + knt_size * 3;
    // kernel consumed bytes
    const size_t krnl_size = ct_size + ad_size;
    // device -> host bytes
    const size_t d2h_size = ct_size + flg_size;

    t3.add(std::to_string(wi));
    t3.add(to_readable_bandwidth(h2d_size, ts[0]));
    t3.add(to_readable_bandwidth(krnl_size, ts[1]));
    t3.add(to_readable_bandwidth(d2h_size, ts[2]));
    t3.endOfRow();
  }

  t3.setAlignment(1, TextTable::Alignment::RIGHT);
  t3.setAlignment(2, TextTable::Alignment::RIGHT);
  t3.setAlignment(3, TextTable::Alignment::RIGHT);
  std::cout << t3;

  std::cout << std::endl
            << "Benchmarking Ascon-128a Encrypt" << std::endl
            << std::endl;

  TextTable t4('-', '|', '+');

  t4.add("SYCL work-items");
  t4.add("host-to-device b/w");
  t4.add("kernel b/w");
  t4.add("device-to-host b/w");
  t4.endOfRow();

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_128a_encrypt, ts);

    const size_t ct_size = wi * CT_LEN;
    const size_t ad_size = wi * AD_LEN;
    const size_t knt_size = wi * (sizeof(uint64_t) << 1);

    // host -> device bytes
    const size_t h2d_size = ct_size + ad_size + (knt_size << 1);
    // kernel consumed bytes
    const size_t krnl_size = ct_size + ad_size;
    // device -> host bytes
    const size_t d2h_size = ct_size + knt_size;

    t4.add(std::to_string(wi));
    t4.add(to_readable_bandwidth(h2d_size, ts[0]));
    t4.add(to_readable_bandwidth(krnl_size, ts[1]));
    t4.add(to_readable_bandwidth(d2h_size, ts[2]));
    t4.endOfRow();
  }

  t4.setAlignment(1, TextTable::Alignment::RIGHT);
  t4.setAlignment(2, TextTable::Alignment::RIGHT);
  t4.setAlignment(3, TextTable::Alignment::RIGHT);
  std::cout << t4;

  std::cout << std::endl
            << "Benchmarking Ascon-128a Decrypt" << std::endl
            << std::endl;

  TextTable t5('-', '|', '+');

  t5.add("SYCL work-items");
  t5.add("host-to-device b/w");
  t5.add("kernel b/w");
  t5.add("device-to-host b/w");
  t5.endOfRow();

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_128a_decrypt, ts);

    const size_t ct_size = wi * CT_LEN;
    const size_t ad_size = wi * AD_LEN;
    const size_t knt_size = wi * (sizeof(uint64_t) << 1);
    const size_t flg_size = wi * sizeof(bool);

    // host -> device bytes
    const size_t h2d_size = ct_size + ad_size + knt_size * 3;
    // kernel consumed bytes
    const size_t krnl_size = ct_size + ad_size;
    // device -> host bytes
    const size_t d2h_size = ct_size + flg_size;

    t5.add(std::to_string(wi));
    t5.add(to_readable_bandwidth(h2d_size, ts[0]));
    t5.add(to_readable_bandwidth(krnl_size, ts[1]));
    t5.add(to_readable_bandwidth(d2h_size, ts[2]));
    t5.endOfRow();
  }

  t5.setAlignment(1, TextTable::Alignment::RIGHT);
  t5.setAlignment(2, TextTable::Alignment::RIGHT);
  t5.setAlignment(3, TextTable::Alignment::RIGHT);
  std::cout << t5;

  std::free(ts);

  std::cout << std::endl
            << "Benchmarking Ascon-80pq Encrypt" << std::endl
            << std::endl;

  TextTable t6('-', '|', '+');

  t6.add("SYCL work-items");
  t6.add("host-to-device b/w");
  t6.add("kernel b/w");
  t6.add("device-to-host b/w");
  t6.endOfRow();

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_80pq_encrypt, ts);

    const size_t ct_size = wi * CT_LEN;
    const size_t ad_size = wi * AD_LEN;
    const size_t k_size = wi * 20ul;
    const size_t nt_size = wi * (sizeof(uint64_t) << 1);

    // host -> device bytes
    const size_t h2d_size = ct_size + ad_size + k_size + nt_size;
    // kernel consumed bytes
    const size_t krnl_size = ct_size + ad_size;
    // device -> host bytes
    const size_t d2h_size = ct_size + nt_size;

    t6.add(std::to_string(wi));
    t6.add(to_readable_bandwidth(h2d_size, ts[0]));
    t6.add(to_readable_bandwidth(krnl_size, ts[1]));
    t6.add(to_readable_bandwidth(d2h_size, ts[2]));
    t6.endOfRow();
  }

  t6.setAlignment(1, TextTable::Alignment::RIGHT);
  t6.setAlignment(2, TextTable::Alignment::RIGHT);
  t6.setAlignment(3, TextTable::Alignment::RIGHT);
  std::cout << t6;

  std::cout << std::endl
            << "Benchmarking Ascon-80pq Decrypt" << std::endl
            << std::endl;

  TextTable t7('-', '|', '+');

  t7.add("SYCL work-items");
  t7.add("host-to-device b/w");
  t7.add("kernel b/w");
  t7.add("device-to-host b/w");
  t7.endOfRow();

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_80pq_decrypt, ts);

    const size_t ct_size = wi * CT_LEN;
    const size_t ad_size = wi * AD_LEN;
    const size_t k_size = wi * 20ul;
    const size_t nt_size = wi * (sizeof(uint64_t) << 1);
    const size_t flg_size = wi * sizeof(bool);

    // host -> device bytes
    const size_t h2d_size = ct_size + ad_size + (nt_size << 1) + k_size;
    // kernel consumed bytes
    const size_t krnl_size = ct_size + ad_size;
    // device -> host bytes
    const size_t d2h_size = ct_size + flg_size;

    t7.add(std::to_string(wi));
    t7.add(to_readable_bandwidth(h2d_size, ts[0]));
    t7.add(to_readable_bandwidth(krnl_size, ts[1]));
    t7.add(to_readable_bandwidth(d2h_size, ts[2]));
    t7.endOfRow();
  }

  t7.setAlignment(1, TextTable::Alignment::RIGHT);
  t7.setAlignment(2, TextTable::Alignment::RIGHT);
  t7.setAlignment(3, TextTable::Alignment::RIGHT);
  std::cout << t7;

  std::free(ts);

  return EXIT_SUCCESS;
}
