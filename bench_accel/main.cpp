#include "bench_utils.hpp"
#include "table.hpp" // taken from https://github.com/haarcuba/cpp-text-table/blob/f217b3d/TextTable.h
#include <iostream>

int
main()
{
  sycl::default_selector s{};
  sycl::device d{ s };
  sycl::context c{};
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

  t0.add("work items");
  t0.add("host-to-device b/w ( MB/ s )");
  t0.add("kernel b/w ( MB/ s )");
  t0.add("device-to-host b/w ( MB/ s )");
  t0.endOfRow();

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_hash, ts);

    const double i_size = static_cast<double>((wi * MSG_LEN) >> 20); // MB
    const double o_size = static_cast<double>((wi << 5) >> 20);      // MB

    const double bw0 = i_size / (ts[0] * 1e-9); // MB/s
    const double bw1 = i_size / (ts[1] * 1e-9); // MB/s
    const double bw2 = o_size / (ts[2] * 1e-9); // MB/s

    t0.add(std::to_string(wi));
    t0.add(std::to_string(bw0));
    t0.add(std::to_string(bw1));
    t0.add(std::to_string(bw2));
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

  t1.add("work items");
  t1.add("host-to-device b/w ( MB/ s )");
  t1.add("kernel b/w ( MB/ s )");
  t1.add("device-to-host b/w ( MB/ s )");
  t1.endOfRow();

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_hashA, ts);

    const double i_size = static_cast<double>((wi * MSG_LEN) >> 20); // MB
    const double o_size = static_cast<double>((wi << 5) >> 20);      // MB

    const double bw0 = i_size / (ts[0] * 1e-9); // MB/s
    const double bw1 = i_size / (ts[1] * 1e-9); // MB/s
    const double bw2 = o_size / (ts[2] * 1e-9); // MB/s

    t1.add(std::to_string(wi));
    t1.add(std::to_string(bw0));
    t1.add(std::to_string(bw1));
    t1.add(std::to_string(bw2));
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

  t2.add("work items");
  t2.add("host-to-device b/w ( MB/ s )");
  t2.add("kernel b/w ( MB/ s )");
  t2.add("device-to-host b/w ( MB/ s )");
  t2.endOfRow();

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_128_encrypt, ts);

    const double ct_size = static_cast<double>((wi * CT_LEN) >> 20);    // MB
    const double ad_size = static_cast<double>((wi * AD_LEN) >> 20);    // MB
    const size_t knt_size = (2 * wi * (sizeof(uint64_t) << 1)) >> 20;   // MB
    const double i_size0 = ct_size + ad_size;                           // MB
    const double i_size1 = i_size0 + static_cast<double>(knt_size);     // MB
    const double o_size = ct_size + static_cast<double>(knt_size >> 1); // MB

    const double bw0 = i_size1 / (ts[0] * 1e-9); // MB/s
    const double bw1 = i_size0 / (ts[1] * 1e-9); // MB/s
    const double bw2 = o_size / (ts[2] * 1e-9);  // MB/s

    t2.add(std::to_string(wi));
    t2.add(std::to_string(bw0));
    t2.add(std::to_string(bw1));
    t2.add(std::to_string(bw2));
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

  t3.add("work items");
  t3.add("host-to-device b/w ( MB/ s )");
  t3.add("kernel b/w ( MB/ s )");
  t3.add("device-to-host b/w ( MB/ s )");
  t3.endOfRow();

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_128_decrypt, ts);

    const double ct_size = static_cast<double>((wi * CT_LEN) >> 20);       // MB
    const double ad_size = static_cast<double>((wi * AD_LEN) >> 20);       // MB
    const double f_sz = static_cast<double>(wi * sizeof(bool)) / 1048576.; // MB
    const size_t knt_size = (3 * wi * (sizeof(uint64_t) << 1)) >> 20;      // MB
    const double i_size0 = ct_size + ad_size;                              // MB
    const double i_size1 = i_size0 + static_cast<double>(knt_size);        // MB
    const double o_size = ct_size + f_sz;                                  // MB

    const double bw0 = i_size1 / (ts[0] * 1e-9); // MB/s
    const double bw1 = i_size0 / (ts[1] * 1e-9); // MB/s
    const double bw2 = o_size / (ts[2] * 1e-9);  // MB/s

    t3.add(std::to_string(wi));
    t3.add(std::to_string(bw0));
    t3.add(std::to_string(bw1));
    t3.add(std::to_string(bw2));
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

  t4.add("work items");
  t4.add("host-to-device b/w ( MB/ s )");
  t4.add("kernel b/w ( MB/ s )");
  t4.add("device-to-host b/w ( MB/ s )");
  t4.endOfRow();

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_128a_encrypt, ts);

    const double ct_size = static_cast<double>((wi * CT_LEN) >> 20);    // MB
    const double ad_size = static_cast<double>((wi * AD_LEN) >> 20);    // MB
    const size_t knt_size = (2 * wi * (sizeof(uint64_t) << 1)) >> 20;   // MB
    const double i_size0 = ct_size + ad_size;                           // MB
    const double i_size1 = i_size0 + static_cast<double>(knt_size);     // MB
    const double o_size = ct_size + static_cast<double>(knt_size >> 1); // MB

    const double bw0 = i_size1 / (ts[0] * 1e-9); // MB/s
    const double bw1 = i_size0 / (ts[1] * 1e-9); // MB/s
    const double bw2 = o_size / (ts[2] * 1e-9);  // MB/s

    t4.add(std::to_string(wi));
    t4.add(std::to_string(bw0));
    t4.add(std::to_string(bw1));
    t4.add(std::to_string(bw2));
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

  t5.add("work items");
  t5.add("host-to-device b/w ( MB/ s )");
  t5.add("kernel b/w ( MB/ s )");
  t5.add("device-to-host b/w ( MB/ s )");
  t5.endOfRow();

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_128a_decrypt, ts);

    const double ct_size = static_cast<double>((wi * CT_LEN) >> 20);       // MB
    const double ad_size = static_cast<double>((wi * AD_LEN) >> 20);       // MB
    const double f_sz = static_cast<double>(wi * sizeof(bool)) / 1048576.; // MB
    const size_t knt_size = (3 * wi * (sizeof(uint64_t) << 1)) >> 20;      // MB
    const double i_size0 = ct_size + ad_size;                              // MB
    const double i_size1 = i_size0 + static_cast<double>(knt_size);        // MB
    const double o_size = ct_size + f_sz;                                  // MB

    const double bw0 = i_size1 / (ts[0] * 1e-9); // MB/s
    const double bw1 = i_size0 / (ts[1] * 1e-9); // MB/s
    const double bw2 = o_size / (ts[2] * 1e-9);  // MB/s

    t5.add(std::to_string(wi));
    t5.add(std::to_string(bw0));
    t5.add(std::to_string(bw1));
    t5.add(std::to_string(bw2));
    t5.endOfRow();
  }

  t5.setAlignment(1, TextTable::Alignment::RIGHT);
  t5.setAlignment(2, TextTable::Alignment::RIGHT);
  t5.setAlignment(3, TextTable::Alignment::RIGHT);
  std::cout << t5;

  std::free(ts);

  return EXIT_SUCCESS;
}
