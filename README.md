# ascon
Accelerating Ascon: Light Weight Cryptography

## Overview

`ascon` is very first cryptographic suite I decided to implement from the list of algorithms competing in final round of NIST **L**ight **W**eight **C**ryptography competition. I suggest you follow [this](https://csrc.nist.gov/Projects/Lightweight-Cryptography). Here I keep a zero-dependency, C++ header-only library implementation of `ascon` LWC suite, which should be easy to use; find examples below. Following functions are implemented

- Ascon-128 authenticated encryption/ verified decryption ( AEAD )
- Ascon-128a authenticated encryption/ verified decryption ( AEAD )
- Ascon-80pq authenticated encryption/ verified decryption ( AEAD )
- Ascon-Hash
- Ascon-HashA

> Read more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

> While working on this project, I've relied on Ascon [specification](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf)

This implementation doesn't depend on anything else, except C++ standard library ( which implements C++20 specification ). I've also written Python wrapper interface to C++ implementation using `ctypes`, which is used for testing functional correctness using Known Answer Tests, provided with NIST LWC submission package of `ascon`. Benchmarking C++ interface makes use of `google-benchmark` library; see below. While it's also possible to benchmark Python wrapper API using `pytest-benchmark`; see details below.

Other than lean & simple Ascon implementation, I've also written SYCL kernels which can be used for data-parallelly computing

- Ascon-Hash of N -many independent, equal length byte slices
- Ascon-HashA of N -many independent, equal length byte slices
- N -many independent, non-overlapping, equal-length cipher text slices and authentication tags ( 128 -bit each ) using Ascon-128 authenticated encryption algorithm
- N -many independent, non-overlapping, equal-length plain text slices and verification flags ( boolean ) using Ascon-128 verified decryption algorithm
- N -many independent, non-overlapping, equal-length cipher text slices and authentication tags ( 128 -bit each ) using Ascon-128a authenticated encryption algorithm
- N -many independent, non-overlapping, equal-length plain text slices and verification flags ( boolean ) using Ascon-128a verified decryption algorithm
- N -many independent, non-overlapping, equal-length cipher text slices and authentication tags ( 128 -bit each ) using Ascon-80pq authenticated encryption algorithm
- N -many independent, non-overlapping, equal-length plain text slices and verification flags ( boolean ) using Ascon-80pq verified decryption algorithm

on heterogeneous accelerator devices i.e. multi-core CPUs, GPGPUs etc. Benchmark results on multiple accelerator devices can be found below. Example of using SYCL accelerated Ascon kernel API can also be found below.

## Prerequisites

- Make sure you've `g++`/ `clang++`/ `dpcpp` installed; find more about `dpcpp` [here](https://www.intel.com/content/www/us/en/developer/tools/oneapi/dpc-compiler.html), which is what I prefer using

```bash
$ dpcpp --version # I'm using
Intel(R) oneAPI DPC++/C++ Compiler 2022.0.0 (2022.0.0.20211123)
Target: x86_64-unknown-linux-gnu
Thread model: posix
InstalledDir: /opt/intel/oneapi/compiler/2022.0.2/linux/bin-llvm
```

```bash
$ g++ --version # used for benchmarking
g++ (Ubuntu 11.2.0-19ubuntu1) 11.2.0
```

> When targeting Nvidia CUDA devices for accelerated Ascon kernels, I'm using Intel's `clang++`, compiled from source with `--cuda` flag; find more [here](https://intel.github.io/llvm-docs/GetStartedGuide.html#prerequisites)

```bash
$ clang++ --version
clang version 15.0.0 (https://github.com/intel/llvm ff254ca03f514222a32694dd3e3b421a2903cce8)
Target: x86_64-unknown-linux-gnu
Thread model: posix
InstalledDir: /home/ubuntu/sycl_workspace/llvm/build/bin
```

- System development utilities like `make`, `cmake` will be required for ease of building library/ testing/ benchmarking

```bash
$ make -v
GNU Make 4.2.1
```

```bash
$ cmake  --version
cmake version 3.16.3
```

- You'll need `python3`, if you want to explore ( test/ benchmark/ use ) `ascon` Python wrapper API

```bash
$ python3 --version
Python 3.8.10
```

- Along with that you'll also need to install dependencies like

```bash
python3 -m pip install --user -r wrapper/python/requirements.txt
```

- Actually it's better idea to use `venv` to keep this project dependencies isolated

```bash
pushd wrapper/python

python3 -m venv .
source bin/activate
python3 -m pip install -r requirements.txt
#
# ... use Python wrapper API ...
#
deactivate

popd
```

- For benchmarking C++ implementation, I use `google-benchmark`, ensure it's globally installed; follow [this](https://github.com/google/benchmark/tree/60b16f1#installation)

## Testing

- Minimal functional testing of Ascon cryptographic suite can be done using

```bash
make
```

> Above command directly tests C++ implementation

- For running detailed functional testing, using **K**nown **A**nswer **T**ests, provided with NIST submission of Ascon, consider running

```bash
make kat_test_python # needs installation of Python dependencies
```

> Last command uses Python API for testing underlying C++ implementation of Ascon cryptographic suite

## Benchmarking

There're two ways to benchmark all implemented routines of Ascon cryptographic suite. Following functions are benchmarked

- Ascon-128 ( encrypt/ decrypt )
- Ascon-128a ( encrypt/ decrypt )
- Ascon-80pq ( encrypt/ decrypt )
- Ascon-Hash
- Ascon-HashA

---

1. For benchmarking C++ API, `google-benchmark` is used ( make sure it's available ), issue

```bash
make bench_cpp
```

### On ARM Cortex-A72

```bash
2022-06-08T07:20:45+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.15, 0.13, 0.06
------------------------------------------------------------------------------
Benchmark                    Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------
ascon_hash/64             1134 ns         1134 ns       617183 bytes_per_second=53.8303M/s
ascon_hash/128            1774 ns         1774 ns       394519 bytes_per_second=68.7992M/s
ascon_hash/256            3063 ns         3063 ns       228532 bytes_per_second=79.7054M/s
ascon_hash/512            5625 ns         5625 ns       124446 bytes_per_second=86.8087M/s
ascon_hash/1024          10749 ns        10749 ns        65123 bytes_per_second=90.8544M/s
ascon_hash/2048          20996 ns        20995 ns        33340 bytes_per_second=93.0264M/s
ascon_hash/4096          41491 ns        41491 ns        16871 bytes_per_second=94.1474M/s
ascon_hash_a/64            813 ns          813 ns       860840 bytes_per_second=75.0592M/s
ascon_hash_a/128          1245 ns         1245 ns       562344 bytes_per_second=98.0683M/s
ascon_hash_a/256          2116 ns         2116 ns       330886 bytes_per_second=115.368M/s
ascon_hash_a/512          3842 ns         3842 ns       182207 bytes_per_second=127.1M/s
ascon_hash_a/1024         7295 ns         7295 ns        95950 bytes_per_second=133.872M/s
ascon_hash_a/2048        14201 ns        14200 ns        49294 bytes_per_second=137.54M/s
ascon_hash_a/4096        28014 ns        28013 ns        24989 bytes_per_second=139.445M/s
ascon_128_enc/64          1041 ns         1041 ns       672600 bytes_per_second=117.296M/s
ascon_128_enc/128         1371 ns         1371 ns       510428 bytes_per_second=133.518M/s
ascon_128_enc/256         2033 ns         2033 ns       344364 bytes_per_second=150.13M/s
ascon_128_enc/512         3363 ns         3363 ns       208134 bytes_per_second=163.333M/s
ascon_128_enc/1024        6009 ns         6009 ns       116493 bytes_per_second=172.688M/s
ascon_128_enc/2048       11299 ns        11299 ns        61948 bytes_per_second=178.256M/s
ascon_128_enc/4096       21881 ns        21881 ns        31991 bytes_per_second=181.313M/s
ascon_128_dec/64          1039 ns         1039 ns       673977 bytes_per_second=117.534M/s
ascon_128_dec/128         1366 ns         1366 ns       512525 bytes_per_second=134.069M/s
ascon_128_dec/256         2020 ns         2020 ns       346505 bytes_per_second=151.066M/s
ascon_128_dec/512         3342 ns         3342 ns       209488 bytes_per_second=164.389M/s
ascon_128_dec/1024        5959 ns         5959 ns       117464 bytes_per_second=174.13M/s
ascon_128_dec/2048       11194 ns        11194 ns        62533 bytes_per_second=179.937M/s
ascon_128_dec/4096       21665 ns        21664 ns        32310 bytes_per_second=183.125M/s
ascon_128a_enc/64          891 ns          891 ns       785618 bytes_per_second=136.999M/s
ascon_128a_enc/128        1133 ns         1133 ns       618032 bytes_per_second=161.668M/s
ascon_128a_enc/256        1616 ns         1616 ns       433076 bytes_per_second=188.806M/s
ascon_128a_enc/512        2584 ns         2584 ns       270895 bytes_per_second=212.583M/s
ascon_128a_enc/1024       4528 ns         4528 ns       154597 bytes_per_second=229.159M/s
ascon_128a_enc/2048       8399 ns         8398 ns        83345 bytes_per_second=239.825M/s
ascon_128a_enc/4096      16140 ns        16140 ns        43370 bytes_per_second=245.808M/s
ascon_128a_dec/64          868 ns          868 ns       806418 bytes_per_second=140.633M/s
ascon_128a_dec/128        1091 ns         1091 ns       641744 bytes_per_second=167.87M/s
ascon_128a_dec/256        1536 ns         1536 ns       455632 bytes_per_second=198.643M/s
ascon_128a_dec/512        2427 ns         2427 ns       288370 bytes_per_second=226.304M/s
ascon_128a_dec/1024       4217 ns         4216 ns       166011 bytes_per_second=246.082M/s
ascon_128a_dec/2048       7781 ns         7781 ns        89961 bytes_per_second=258.858M/s
ascon_128a_dec/4096      14910 ns        14909 ns        46948 bytes_per_second=266.093M/s
ascon_80pq_enc/64         1053 ns         1053 ns       664794 bytes_per_second=115.933M/s
ascon_80pq_enc/128        1384 ns         1384 ns       505921 bytes_per_second=132.338M/s
ascon_80pq_enc/256        2045 ns         2045 ns       342295 bytes_per_second=149.233M/s
ascon_80pq_enc/512        3375 ns         3375 ns       207376 bytes_per_second=162.739M/s
ascon_80pq_enc/1024       6021 ns         6021 ns       116253 bytes_per_second=172.33M/s
ascon_80pq_enc/2048      11312 ns        11312 ns        61881 bytes_per_second=178.058M/s
ascon_80pq_enc/4096      21894 ns        21894 ns        31971 bytes_per_second=181.206M/s
ascon_80pq_dec/64         1041 ns         1041 ns       672605 bytes_per_second=117.296M/s
ascon_80pq_dec/128        1368 ns         1368 ns       511737 bytes_per_second=133.862M/s
ascon_80pq_dec/256        2022 ns         2022 ns       346134 bytes_per_second=150.91M/s
ascon_80pq_dec/512        3340 ns         3340 ns       209578 bytes_per_second=164.461M/s
ascon_80pq_dec/1024       5957 ns         5957 ns       117486 bytes_per_second=174.169M/s
ascon_80pq_dec/2048      11193 ns        11192 ns        62542 bytes_per_second=179.957M/s
ascon_80pq_dec/4096      21662 ns        21662 ns        32314 bytes_per_second=183.144M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-06-08T11:15:40+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.83, 1.81, 1.76
------------------------------------------------------------------------------
Benchmark                    Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------
ascon_hash/64              618 ns          613 ns      1129634 bytes_per_second=99.6147M/s
ascon_hash/128             992 ns          984 ns       710725 bytes_per_second=124.061M/s
ascon_hash/256            1751 ns         1737 ns       406504 bytes_per_second=140.547M/s
ascon_hash/512            3236 ns         3210 ns       217926 bytes_per_second=152.122M/s
ascon_hash/1024           6236 ns         6180 ns       112972 bytes_per_second=158.008M/s
ascon_hash/2048          12292 ns        12194 ns        58378 bytes_per_second=160.166M/s
ascon_hash/4096          23656 ns        23505 ns        30345 bytes_per_second=166.188M/s
ascon_hash_a/64            419 ns          416 ns      1703893 bytes_per_second=146.627M/s
ascon_hash_a/128           670 ns          665 ns      1042924 bytes_per_second=183.606M/s
ascon_hash_a/256          1179 ns         1170 ns       602259 bytes_per_second=208.719M/s
ascon_hash_a/512          2170 ns         2151 ns       323674 bytes_per_second=227.033M/s
ascon_hash_a/1024         4136 ns         4106 ns       168976 bytes_per_second=237.866M/s
ascon_hash_a/2048         8152 ns         8089 ns        86078 bytes_per_second=241.456M/s
ascon_hash_a/4096        16313 ns        16138 ns        44076 bytes_per_second=242.052M/s
ascon_128_enc/64           562 ns          560 ns      1174812 bytes_per_second=218.079M/s
ascon_128_enc/128          789 ns          785 ns       878426 bytes_per_second=233.402M/s
ascon_128_enc/256         1230 ns         1221 ns       570255 bytes_per_second=249.867M/s
ascon_128_enc/512         2098 ns         2083 ns       335931 bytes_per_second=263.719M/s
ascon_128_enc/1024        3846 ns         3815 ns       183157 bytes_per_second=271.973M/s
ascon_128_enc/2048        7301 ns         7247 ns        95585 bytes_per_second=277.944M/s
ascon_128_enc/4096       14280 ns        14170 ns        48999 bytes_per_second=279.968M/s
ascon_128_dec/64           564 ns          560 ns      1234873 bytes_per_second=217.827M/s
ascon_128_dec/128          755 ns          750 ns       931929 bytes_per_second=244.161M/s
ascon_128_dec/256         1174 ns         1153 ns       608823 bytes_per_second=264.616M/s
ascon_128_dec/512         1913 ns         1901 ns       363014 bytes_per_second=289.036M/s
ascon_128_dec/1024        3383 ns         3369 ns       201761 bytes_per_second=307.941M/s
ascon_128_dec/2048        6457 ns         6428 ns       108033 bytes_per_second=313.32M/s
ascon_128_dec/4096       13075 ns        12943 ns        55111 bytes_per_second=306.514M/s
ascon_128a_enc/64          500 ns          491 ns      1406928 bytes_per_second=248.433M/s
ascon_128a_enc/128         639 ns          630 ns      1095667 bytes_per_second=290.562M/s
ascon_128a_enc/256         933 ns          917 ns       771180 bytes_per_second=332.88M/s
ascon_128a_enc/512        1488 ns         1466 ns       477089 bytes_per_second=374.612M/s
ascon_128a_enc/1024       2617 ns         2584 ns       276329 bytes_per_second=401.508M/s
ascon_128a_enc/2048       4844 ns         4791 ns       145745 bytes_per_second=420.404M/s
ascon_128a_enc/4096       9301 ns         9219 ns        75647 bytes_per_second=430.361M/s
ascon_128a_dec/64          431 ns          428 ns      1648114 bytes_per_second=285.361M/s
ascon_128a_dec/128         567 ns          562 ns      1254211 bytes_per_second=325.596M/s
ascon_128a_dec/256         838 ns          832 ns       826027 bytes_per_second=366.802M/s
ascon_128a_dec/512        1386 ns         1375 ns       507519 bytes_per_second=399.452M/s
ascon_128a_dec/1024       2466 ns         2445 ns       288473 bytes_per_second=424.406M/s
ascon_128a_dec/2048       4616 ns         4580 ns       151613 bytes_per_second=439.799M/s
ascon_128a_dec/4096       8951 ns         8885 ns        78910 bytes_per_second=446.532M/s
ascon_80pq_enc/64          578 ns          573 ns      1189505 bytes_per_second=212.883M/s
ascon_80pq_enc/128         792 ns          787 ns       879784 bytes_per_second=232.777M/s
ascon_80pq_enc/256        1229 ns         1221 ns       573799 bytes_per_second=249.948M/s
ascon_80pq_enc/512        2095 ns         2080 ns       330954 bytes_per_second=264.036M/s
ascon_80pq_enc/1024       3907 ns         3872 ns       181839 bytes_per_second=267.94M/s
ascon_80pq_enc/2048       7307 ns         7255 ns        94610 bytes_per_second=277.627M/s
ascon_80pq_enc/4096      14506 ns        14369 ns        48668 bytes_per_second=276.109M/s
ascon_80pq_dec/64          566 ns          562 ns      1275603 bytes_per_second=217.367M/s
ascon_80pq_dec/128         764 ns          757 ns       915152 bytes_per_second=242.027M/s
ascon_80pq_dec/256        1166 ns         1156 ns       603323 bytes_per_second=263.925M/s
ascon_80pq_dec/512        1952 ns         1938 ns       362171 bytes_per_second=283.405M/s
ascon_80pq_dec/1024       3527 ns         3501 ns       197024 bytes_per_second=296.341M/s
ascon_80pq_dec/2048       6758 ns         6713 ns       105791 bytes_per_second=300.026M/s
ascon_80pq_dec/4096      13217 ns        13094 ns        54253 bytes_per_second=302.977M/s
```

---

2. And for benchmarking `ascon` Python wrapper API, `pytest-benchmark` is used

```bash
make bench_python
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
------------------------------------------------------------------------------------------- benchmark: 8 tests -------------------------------------------------------------------------------------------
Name (time in us)                     Min                   Max               Mean             StdDev             Median               IQR            Outliers  OPS (Kops/s)            Rounds  Iterations
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
test_bench_ascon_hasha             9.0260 (1.0)      9,428.6130 (53.69)    11.2271 (1.0)      78.9193 (7.59)      9.5350 (1.0)      0.3335 (1.0)       12;1687       89.0702 (1.0)       14488           1
test_bench_ascon_hash             12.1540 (1.35)       175.6240 (1.0)      13.9209 (1.24)     10.8109 (1.04)     12.6490 (1.33)     0.4205 (1.26)         3;34       71.8345 (0.81)        239           1
test_bench_ascon_128_encrypt      18.0770 (2.00)       264.0930 (1.50)     21.0252 (1.87)     10.3964 (1.0)      19.2420 (2.02)     0.6220 (1.87)     439;1073       47.5620 (0.53)      12052           1
test_bench_ascon_128a_encrypt     18.2200 (2.02)       253.1850 (1.44)     22.0808 (1.97)     13.0963 (1.26)     19.2890 (2.02)     0.6680 (2.00)      398;842       45.2882 (0.51)       7285           1
test_bench_ascon_80pq_encrypt     18.5210 (2.05)       248.9030 (1.42)     22.0310 (1.96)     11.4594 (1.10)     19.9060 (2.09)     0.6660 (2.00)     512;1101       45.3906 (0.51)      11929           1
test_bench_ascon_128_decrypt      18.6030 (2.06)       346.4190 (1.97)     22.3230 (1.99)     11.5591 (1.11)     20.0910 (2.11)     0.6400 (1.92)    1484;3262       44.7968 (0.50)      30953           1
test_bench_ascon_128a_decrypt     18.8170 (2.08)       370.0150 (2.11)     22.3928 (1.99)     12.3355 (1.19)     19.9650 (2.09)     0.6365 (1.91)    1429;3450       44.6572 (0.50)      30564           1
test_bench_ascon_80pq_decrypt     19.4510 (2.15)       283.0880 (1.61)     23.0147 (2.05)     11.7192 (1.13)     20.6670 (2.17)     0.5460 (1.64)    1365;3571       43.4505 (0.49)      29339           1
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Legend:
  Outliers: 1 Standard Deviation from Mean; 1.5 IQR (InterQuartile Range) from 1st Quartile and 3rd Quartile.
  OPS: Operations Per Second, computed as 1 / Mean
===================================================================================== 8 passed, 5 deselected in 6.34s ======================================================================================
```

## Usage

### Basic Ascon API

`ascon` being a header-only C++ library, it's pretty easy to start using its C++ API. Just include the header file ( i.e. `include/ascon.hpp` ) and use functions living inside `ascon::` namespace. Namespace like `ascon_utils::` might also be of your interest, which has some utility routines implemented.

```cpp
// ascon_hash.cpp
// see https://github.com/itzmeanjan/ascon/blob/2e45d60/example/ascon_hash.cpp

#include "ascon.hpp"
#include <iostream>

int
main(int argc, char** argv)
{
  constexpr size_t msg_len = 1024; // bytes
  constexpr size_t out_len = 32;   // bytes

  // acquire resources
  uint8_t* msg = static_cast<uint8_t*>(malloc(msg_len)); // input
  uint8_t* out = static_cast<uint8_t*>(malloc(out_len)); // digest

  // prepare input
#pragma unroll 8
  for (size_t i = 0; i < msg_len; i++) {
    msg[i] = static_cast<uint8_t>(i);
  }

  // compute digest using Ascon-Hash
  ascon::hash(msg, msg_len, out);
  // digest as hex string
  const std::string digest = ascon_utils::tohex(out, out_len);

  std::cout << "Ascon-Hash digest :\t" << digest << std::endl;

  // deallocate resources
  free(msg);
  free(out);

  return EXIT_SUCCESS;
}
```

Now you can compile & run

```bash
$ dpcpp -Wall -std=c++20 -O3 -I./include example/ascon_hash.cpp && ./a.out

Ascon-Hash digest :     2eb89744de7f9a6f47d53db756bb2f67b127da96762a1c47a5d7bfc1f7273f5c
```

See example of using

- [Ascon-Hash API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_hash.cpp)
- [Ascon-HashA API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_hasha.cpp)
- [Ascon-128 authenticated encryption/ verified decryption API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_128.cpp)
- [Ascon-128a authenticated encryption/ verified decryption API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_128a.cpp)
- [Ascon-80pq authenticated encryption/ verified decryption API](https://github.com/itzmeanjan/ascon/blob/b680d4b/example/ascon_80pq.cpp)

---

### Accelerated Ascon Kernel API

For using accelerated Ascon API, where data-parallel variants of all basic Ascon cryptographic functions are written, using SYCL heterogeneous API, in form of SYCL kernels, which can be compiled targeting multi-core CPUs, GPGPUs, do following

```cpp
// accel_ascon_hasha.cpp
// see https://github.com/itzmeanjan/ascon/blob/92f2c3e/example/accel_ascon_hasha.cpp

#include "accel_ascon.hpp"

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
```

Compile & run it with

```bash
$ dpcpp -std=c++20 -fsycl -O3 -I ./include example/accel_ascon_hasha.cpp && ./a.out

Accelerated Ascon-HashA works !
```

For offloading SYCL kernels, implementing accelerated Ascon cryptographic suite, import `include/accel_ascon.hpp` & start using functions defined inside `accel_ascon::` namespace.

Find example of using all `accel_ascon::` namespaced SYCL kernels

- [Ascon-Hash SYCL Kernel API](https://github.com/itzmeanjan/ascon/blob/92f2c3e/example/accel_ascon_hash.cpp)
- [Ascon-HashA SYCL Kernel API](https://github.com/itzmeanjan/ascon/blob/92f2c3e/example/accel_ascon_hasha.cpp)
- [Ascon-128 authenticated encryption/ verified decryption SYCL Kernel API](https://github.com/itzmeanjan/ascon/blob/92f2c3e/example/accel_ascon_128.cpp)
- [Ascon-128a authenticated encryption/ verified decryption SYCL Kernel API](https://github.com/itzmeanjan/ascon/blob/92f2c3e/example/accel_ascon_128a.cpp)
- [Ascon-80pq authenticated encryption/ verified decryption SYCL Kernel API](https://github.com/itzmeanjan/ascon/blob/7a2964f/example/accel_ascon_80pq.cpp)

---

### Wrapper Python API

For using `ascon` Python wrapper API, first you've to generate shared library object

```bash
make lib
file wrapper/libascon.so # okay to skip it
```

Now you can use Python interface

```bash
$ pushd wrapper/python
$ python3 # consider enabling `venv`

>>> import ascon
>>> msg = ascon.np.empty(0, dtype=ascon.np.uint8) # 0 -bytes message ( numpy byte array )
>>> ascon.hash(msg).tobytes().hex()               # computing ascon-hash digest
'7346bc14f036e87ae03d0997913088f5f68411434b3cf8b54fa796a80d251f91'
>>>

$ popd
```

Example script demonstrating usage of `ascon` Python API, can be found [here](https://github.com/itzmeanjan/ascon/blob/e3ead2b/wrapper/python/example.py)

```bash
make lib # must do !

pushd wrapper/python
python3 example.py
popd
```

> I suggest you read `ascon` Python API documentation [here](https://github.com/itzmeanjan/ascon/blob/92f218b/wrapper/python/ascon.py).

> Going through Python API benchmark file should give you good overview of how to use `ascon`; follow [this](https://github.com/itzmeanjan/ascon/blob/92f218b/wrapper/python/test_ascon.py#L212-L343)

## Benchmark SYCL accelerated Ascon

I've written SYCL kernels which can be used for computing Ascon-Hash digest/ Ascon-HashA digest/ encrypted bytes & authentication tags using Ascon-128, Ascon-128a, Ascon-80pq/ decrypted text bytes & boolean verification flags using Ascon-128, Ascon-128a, Ascon-80pq, in data-parallel fashion on accelerator devices like multi-core CPUs, GPGPUs.

These kernels themselves are pretty simple as they import standard Ascon cryptographic suite ( read `ascon::` namespace ) and invoke N -many instances of relevant cryptographic routine on N -many independent, non-overlapping input byte slices producing N -many independent output bytes --- meaning N -many SYCL work-items are dispatched for some kernel ( say Ascon-Hash ) and without any in work-group communication/ synchronization N -many Ascon-Hash digests ( each 32 -bytes wide ) are computed & placed in respective memory locations, in contiguous fashion. These digests can now be transferred back to host & consumed for other purposes.

Similarly for Ascon-128 encryption algorithm, N -many independent, non-overlapping, equal length plain text slices are encrypted to N -many equal length cipher slices, also computing N -many authentication tags ( each 128 -bit wide ) while also using independent, non-overlapping secret keys ( N -many ), public message nonces ( N -many ) & associated data byte slices ( each slice of same length, total N -many ) as input to encryption algorithm. These encrypted message slices can now be data-parallelly decrypted by dispatching N -many SYCL work-items while each of these work-items to consume respective secret key ( 128 -bit ), public message nonce ( 128 -bit ), authentication tag ( 128 -bit ), ciphered byte slice & associated data byte slice, producing plain text bytes and boolean flag denoting verification status of decryption process.

Here I keep minimal benchmark results of SYCL kernels implementing following functionalities.

- [Ascon-Hash/ Ascon-HashA](https://github.com/itzmeanjan/ascon/blob/ee890f9/include/bench_utils.hpp#L110-L160)
- [Ascon-128 Encrypt/ Ascon-128a Encrypt](https://github.com/itzmeanjan/ascon/blob/ee890f9/include/bench_utils.hpp#L161-L298)
- [Ascon-128 Decrypt/ Ascon-128a Decrypt](https://github.com/itzmeanjan/ascon/blob/ee890f9/include/bench_utils.hpp#L299-L481)
- [Ascon-80pq Encrypt](https://github.com/itzmeanjan/ascon/blob/7a2964f/include/bench_utils.hpp#L489-L607)
- [Ascon-80pq Decrypt](https://github.com/itzmeanjan/ascon/blob/7a2964f/include/bench_utils.hpp#L608-L759)

Browse through results & respective build commands

- [Nvidia GPU](./results/gpu/nvidia.md)
- [Intel CPU](./results/cpu/intel.md)
- [Intel GPU](./results/gpu/intel.md)
