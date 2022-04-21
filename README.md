# ascon
Accelerating Ascon: Light Weight Cryptography

## Overview

`ascon` is very first cryptographic suite I decided to implement from the list of algorithms competing in final round of NIST **L**ight **W**eight **C**ryptography competition. I suggest you follow [this](https://csrc.nist.gov/Projects/Lightweight-Cryptography). Here I keep a C++ header-only library implementation of `ascon` LWC suite, which should be easy to use; find examples below. Following functions are implemented

- Ascon-128 authenticated encryption/ verified decryption ( AEAD )
- Ascon-128a authenticated encryption/ verified decryption ( AEAD )
- Ascon-80pq authenticated encryption/ verified decryption ( AEAD )
- Ascon-Hash
- Ascon-HashA

> Read more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

> While working on this project, I've relied on Ascon [specification](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf)

This implementation doesn't depend on anything else, except C++ standard library ( which implements C++20 specification ). I've also written Python interface to C++ implementation using `ctypes`, which is used for testing functional correctness using Known Answer Tests, provided with NIST LWC submission package of `ascon`. Benchmarking C++ interface makes use of `google-benchmark` library; see below. While it's also possible to benchmark Python wrapper API using `pytest-benchmark`; details below.

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

> When using compiler other than `dpcpp`, you've to update `Makefile`

```bash
$ dpcpp --version # I'm using

Intel(R) oneAPI DPC++/C++ Compiler 2022.0.0 (2022.0.0.20211123)
Target: x86_64-unknown-linux-gnu
Thread model: posix
InstalledDir: /opt/intel/oneapi/compiler/2022.0.2/linux/bin-llvm
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
make kat_test_python
```

> Last command uses Python API for testing underlying C++ implementation of Ascon cryptographic suite

## Benchmarking

There're two ways to benchmark all implemented fundamental functions of Ascon cryptographic suite. Following functions are benchmarked

- Ascon-128 ( encrypt/ decrypt )
- Ascon-128a ( encrypt/ decrypt )
- Ascon-80pq ( encrypt/ decrypt )
- Ascon-Hash
- Ascon-HashA

---

1. For benchmarking using C++ API, `google-benchmark` is used ( make sure it's available )

```bash
make bench_cpp
```

```bash
2022-04-21T16:14:03+00:00
Running ./bench/a.out
Run on (4 X 2300.14 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.15, 0.05, 0.01
-------------------------------------------------------------------------
Benchmark               Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------
ascon_hash          33816 ns        33814 ns        20658 bytes_per_second=115.523M/s items_per_second=29.574k/s
ascon_hash_a        23443 ns        23441 ns        30941 bytes_per_second=166.642M/s items_per_second=42.6604k/s
ascon_128_enc       17467 ns        17466 ns        40461 bytes_per_second=227.143M/s items_per_second=57.254k/s
ascon_128_dec       17199 ns        17198 ns        41602 bytes_per_second=230.689M/s items_per_second=58.1478k/s
ascon_128a_enc      13545 ns        13542 ns        52513 bytes_per_second=292.954M/s items_per_second=73.8425k/s
ascon_128a_dec      11163 ns        11163 ns        62680 bytes_per_second=355.404M/s items_per_second=89.5837k/s
ascon_80pq_enc      17688 ns        17687 ns        39601 bytes_per_second=224.303M/s items_per_second=56.5382k/s
ascon_80pq_dec      16858 ns        16858 ns        41660 bytes_per_second=235.339M/s items_per_second=59.3198k/s
```

---

2. And for benchmarking `ascon` Python wrapper API, `pytest-benchmark` is used

```bash
make bench_python
```

```bash
-------------------------------------------------------------------------------------------- benchmark: 8 tests -------------------------------------------------------------------------------------------
Name (time in us)                     Min                   Max               Mean              StdDev             Median               IQR            Outliers  OPS (Kops/s)            Rounds  Iterations
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
test_bench_ascon_hasha            14.7969 (1.0)        283.2972 (1.26)     17.3031 (1.0)        9.9935 (1.0)      15.7580 (1.0)      0.4731 (1.05)     703;1144       57.7933 (1.0)       15144           1
test_bench_ascon_hash             15.5382 (1.05)     9,850.5802 (43.67)    19.3500 (1.12)     127.0850 (12.72)    16.3466 (1.04)     0.4508 (1.0)         5;485       51.6796 (0.89)       6022           1
test_bench_ascon_128_encrypt      30.2121 (2.04)       225.5440 (1.0)      33.4573 (1.93)      12.5854 (1.26)     31.5197 (2.00)     0.8158 (1.81)      257;823       29.8889 (0.52)       9029           1
test_bench_ascon_128a_encrypt     30.6256 (2.07)       229.7089 (1.02)     33.9579 (1.96)      12.5606 (1.26)     32.1195 (2.04)     0.7600 (1.69)      279;716       29.4482 (0.51)       9690           1
test_bench_ascon_128a_decrypt     31.3483 (2.12)       306.1034 (1.36)     35.7931 (2.07)      14.4296 (1.44)     32.8794 (2.09)     0.8568 (1.90)     818;1348       27.9384 (0.48)      13547           1
test_bench_ascon_80pq_encrypt     32.2126 (2.18)       246.1337 (1.09)     35.5822 (2.06)      12.6274 (1.26)     33.7437 (2.14)     0.8047 (1.79)      286;754       28.1039 (0.49)       9843           1
test_bench_ascon_128_decrypt      32.4883 (2.20)       329.6062 (1.46)     35.9194 (2.08)      12.9967 (1.30)     33.9150 (2.15)     0.7227 (1.60)     511;1142       27.8401 (0.48)      15591           1
test_bench_ascon_80pq_decrypt     33.1849 (2.24)       267.8931 (1.19)     36.4118 (2.10)      12.5121 (1.25)     34.8464 (2.21)     0.6855 (1.52)     374;1103       27.4636 (0.48)      16862           1
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Legend:
  Outliers: 1 Standard Deviation from Mean; 1.5 IQR (InterQuartile Range) from 1st Quartile and 3rd Quartile.
  OPS: Operations Per Second, computed as 1 / Mean
================================================================================ 8 passed, 5 deselected in 5.24s ================================================================================
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
  constexpr const size_t msg_len = 1024; // bytes
  constexpr const size_t out_len = 32;   // bytes

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
