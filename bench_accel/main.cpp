#include "bench_utils.hpp"
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
  std::cout << std::setw(24) << std::right << "input size"
            << "\t\t" << std::setw(16) << std::right << "execution time"
            << "\t\t" << std::setw(16) << std::right << "host-to-device tx time"
            << "\t\t" << std::setw(16) << std::right << "device-to-host tx time"
            << "\t\t" << std::setw(16) << std::right << "kernel bandwidth"
            << std::endl;

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_hash, ts);

    const double i_size = static_cast<double>((wi * MSG_LEN) >> 20); // MB
    const double bw = i_size / (ts[1] * 1e-9);                       // MB/s

    std::cout << std::setw(20) << std::right << i_size << " MB"
              << "\t\t" << std::setw(22) << std::right
              << to_readable_timespan(ts[1]) << "\t\t" << std::setw(22)
              << std::right << to_readable_timespan(ts[0]) << "\t\t"
              << std::setw(22) << std::right << to_readable_timespan(ts[2])
              << "\t\t" << std::setw(22) << std::right << bw << " MB/ s"
              << std::endl;
  }

  std::cout << std::endl
            << "Benchmarking Ascon-HashA" << std::endl
            << std::endl;
  std::cout << std::setw(24) << std::right << "input size"
            << "\t\t" << std::setw(16) << std::right << "execution time"
            << "\t\t" << std::setw(16) << std::right << "host-to-device tx time"
            << "\t\t" << std::setw(16) << std::right << "device-to-host tx time"
            << "\t\t" << std::setw(16) << std::right << "kernel bandwidth"
            << std::endl;

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_hashA, ts);

    const double i_size = static_cast<double>((wi * MSG_LEN) >> 20); // MB
    const double bw = i_size / (ts[1] * 1e-9);                       // MB/s

    std::cout << std::setw(20) << std::right << i_size << " MB"
              << "\t\t" << std::setw(22) << std::right
              << to_readable_timespan(ts[1]) << "\t\t" << std::setw(22)
              << std::right << to_readable_timespan(ts[0]) << "\t\t"
              << std::setw(22) << std::right << to_readable_timespan(ts[2])
              << "\t\t" << std::setw(22) << std::right << bw << " MB/ s"
              << std::endl;
  }

  std::cout << std::endl
            << "Benchmarking Ascon-128 Encrypt" << std::endl
            << std::endl;
  std::cout << std::setw(24) << std::right << "total input size"
            << "\t\t" << std::setw(16) << std::right << "execution time"
            << "\t\t" << std::setw(16) << std::right << "host-to-device tx time"
            << "\t\t" << std::setw(16) << std::right << "device-to-host tx time"
            << "\t\t" << std::setw(16) << std::right << "kernel bandwidth"
            << std::endl;

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_128_encrypt, ts);

    const double ct_size = static_cast<double>((wi * CT_LEN) >> 20);  // MB
    const double ad_size = static_cast<double>((wi * AD_LEN) >> 20);  // MB
    const size_t knt_size = (2 * wi * (sizeof(uint64_t) << 1)) >> 20; // MB
    const double i_size0 = ct_size + ad_size;                         // MB
    const double i_size1 = i_size0 + static_cast<double>(knt_size);   // MB
    const double bw = i_size0 / (ts[1] * 1e-9);                       // MB/s

    std::cout << std::setw(20) << std::right << i_size1 << " MB"
              << "\t\t" << std::setw(22) << std::right
              << to_readable_timespan(ts[1]) << "\t\t" << std::setw(22)
              << std::right << to_readable_timespan(ts[0]) << "\t\t"
              << std::setw(22) << std::right << to_readable_timespan(ts[2])
              << "\t\t" << std::setw(22) << std::right << bw << " MB/ s"
              << std::endl;
  }

  std::cout << std::endl
            << "Benchmarking Ascon-128 Decrypt" << std::endl
            << std::endl;
  std::cout << std::setw(24) << std::right << "total input size"
            << "\t\t" << std::setw(16) << std::right << "execution time"
            << "\t\t" << std::setw(16) << std::right << "host-to-device tx time"
            << "\t\t" << std::setw(16) << std::right << "device-to-host tx time"
            << "\t\t" << std::setw(16) << std::right << "kernel bandwidth"
            << std::endl;

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_128_decrypt, ts);

    const double ct_size = static_cast<double>((wi * CT_LEN) >> 20);  // MB
    const double ad_size = static_cast<double>((wi * AD_LEN) >> 20);  // MB
    const size_t knt_size = (3 * wi * (sizeof(uint64_t) << 1)) >> 20; // MB
    const double i_size0 = ct_size + ad_size;                         // MB
    const double i_size1 = i_size0 + static_cast<double>(knt_size);   // MB
    const double bw = i_size0 / (ts[1] * 1e-9);                       // MB/s

    std::cout << std::setw(20) << std::right << i_size1 << " MB"
              << "\t\t" << std::setw(22) << std::right
              << to_readable_timespan(ts[1]) << "\t\t" << std::setw(22)
              << std::right << to_readable_timespan(ts[0]) << "\t\t"
              << std::setw(22) << std::right << to_readable_timespan(ts[2])
              << "\t\t" << std::setw(22) << std::right << bw << " MB/ s"
              << std::endl;
  }

  std::cout << std::endl
            << "Benchmarking Ascon-128a Encrypt" << std::endl
            << std::endl;
  std::cout << std::setw(24) << std::right << "total input size"
            << "\t\t" << std::setw(16) << std::right << "execution time"
            << "\t\t" << std::setw(16) << std::right << "host-to-device tx time"
            << "\t\t" << std::setw(16) << std::right << "device-to-host tx time"
            << "\t\t" << std::setw(16) << std::right << "kernel bandwidth"
            << std::endl;

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_128a_encrypt, ts);

    const double ct_size = static_cast<double>((wi * CT_LEN) >> 20);  // MB
    const double ad_size = static_cast<double>((wi * AD_LEN) >> 20);  // MB
    const size_t knt_size = (2 * wi * (sizeof(uint64_t) << 1)) >> 20; // MB
    const double i_size0 = ct_size + ad_size;                         // MB
    const double i_size1 = i_size0 + static_cast<double>(knt_size);   // MB
    const double bw = i_size0 / (ts[1] * 1e-9);                       // MB/s

    std::cout << std::setw(20) << std::right << i_size1 << " MB"
              << "\t\t" << std::setw(22) << std::right
              << to_readable_timespan(ts[1]) << "\t\t" << std::setw(22)
              << std::right << to_readable_timespan(ts[0]) << "\t\t"
              << std::setw(22) << std::right << to_readable_timespan(ts[2])
              << "\t\t" << std::setw(22) << std::right << bw << " MB/ s"
              << std::endl;
  }

  std::cout << std::endl
            << "Benchmarking Ascon-128a Decrypt" << std::endl
            << std::endl;
  std::cout << std::setw(24) << std::right << "total input size"
            << "\t\t" << std::setw(16) << std::right << "execution time"
            << "\t\t" << std::setw(16) << std::right << "host-to-device tx time"
            << "\t\t" << std::setw(16) << std::right << "device-to-host tx time"
            << "\t\t" << std::setw(16) << std::right << "kernel bandwidth"
            << std::endl;

  for (size_t wi = 1ul << 16; wi <= 1ul << 18; wi <<= 1) {
    exec_kernel(q, wi, wg_size, itr_cnt, ascon_variant::ascon_128a_decrypt, ts);

    const double ct_size = static_cast<double>((wi * CT_LEN) >> 20);  // MB
    const double ad_size = static_cast<double>((wi * AD_LEN) >> 20);  // MB
    const size_t knt_size = (3 * wi * (sizeof(uint64_t) << 1)) >> 20; // MB
    const double i_size0 = ct_size + ad_size;                         // MB
    const double i_size1 = i_size0 + static_cast<double>(knt_size);   // MB
    const double bw = i_size0 / (ts[1] * 1e-9);                       // MB/s

    std::cout << std::setw(20) << std::right << i_size1 << " MB"
              << "\t\t" << std::setw(22) << std::right
              << to_readable_timespan(ts[1]) << "\t\t" << std::setw(22)
              << std::right << to_readable_timespan(ts[0]) << "\t\t"
              << std::setw(22) << std::right << to_readable_timespan(ts[2])
              << "\t\t" << std::setw(22) << std::right << bw << " MB/ s"
              << std::endl;
  }

  std::free(ts);

  return EXIT_SUCCESS;
}
