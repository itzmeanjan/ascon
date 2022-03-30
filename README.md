# ascon
Accelerating Ascon: Light Weight Cryptography

## Overview

`ascon` is very first cryptographic suite I decided to implement from the list algorithms competing in final round of NIST **L**ight **W**eight **C**ryptography competition. I suggest you follow [this](https://csrc.nist.gov/Projects/Lightweight-Cryptography). Here I keep a C++ header-only library implementation of `ascon` LWC suite, which should be easy to use; find examples below. Following functions are implemented

- Ascon-128 authenticated encryption/ verified decryption ( AEAD )
- Ascon-128a authenticated encryption/ verified decryption ( AEAD )
- Ascon-Hash
- Ascon-HashA

> Read more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

> While working on this project, I've relied on Ascon [specification](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf)

This implementation doesn't depend on anything else, except C++ standard library. I've also written Python interface to C++ implementation using `ctypes`, which is used for testing functional correctness using Known Answer Tests provided with NIST LWC submission package of `ascon`. Benchmarking C++ interface makes use of `google-benchmark` library; see below. While it's also possible to benchmark Python wrapper API using `pytest-benchmark`; details below.

Eventually I'd like to integrate `ascon` with SYCL heterogeneous data parallel API ( invoking from SYCL kernels ) for accelerating cryptographic hashing, authenticated encryption & verified decryption using `ascon` --- running it on CPUs, GPUs & FPGAs. Note, `ascon` itself is pretty light weight, so speed up obtained when running multiple instances of `ascon` LWC suite in data parallel fashion, on high-end GPU, should be impressive [ **WIP** ]

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

There're two ways to benchmark all implemented functions of Ascon crytographic suite. Following functions are benchmarked

- Ascon-128 ( encrypt/ decrypt )
- Ascon-128a ( encrypt/ decrypt )
- Ascon-Hash
- Ascon-HashA

---

1. For benchmarking using C++ API, `google-benchmark` is used ( make sure it's available )

```bash
make bench_cpp
```

```bash
2022-03-30T14:11:33+00:00
Running ./bench/a.out
Run on (4 X 2300.14 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.20, 0.07, 0.01
-------------------------------------------------------------------------
Benchmark               Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------
ascon_hash          33800 ns        33798 ns        20715 bytes_per_second=115.577M/s items_per_second=29.5877k/s
ascon_hash_a        22482 ns        22480 ns        31198 bytes_per_second=173.766M/s items_per_second=44.4841k/s
ascon_128_enc       17467 ns        17465 ns        40114 bytes_per_second=227.151M/s items_per_second=57.2561k/s
ascon_128_dec       17021 ns        17020 ns        41128 bytes_per_second=233.092M/s items_per_second=58.7534k/s
ascon_128a_enc      13303 ns        13301 ns        52673 bytes_per_second=298.263M/s items_per_second=75.1806k/s
ascon_128a_dec      11201 ns        11201 ns        62374 bytes_per_second=354.175M/s items_per_second=89.2738k/s
```

---

2. And for benchmarking `ascon` Python wrapper API, `pytest-benchmark` is used

```bash
make bench_python
```

```bash
-------------------------------------------------------------------------------------------- benchmark: 6 tests -------------------------------------------------------------------------------------------
Name (time in us)                     Min                   Max               Mean              StdDev             Median               IQR            Outliers  OPS (Kops/s)            Rounds  Iterations
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
test_bench_ascon_hasha            15.0390 (1.0)        185.8063 (1.0)      16.7846 (1.0)        8.7322 (1.0)      15.9033 (1.0)      0.4061 (1.0)       218;793       59.5783 (1.0)       15036           1
test_bench_ascon_hash             15.2551 (1.01)     9,874.9287 (53.15)    18.5198 (1.10)     120.8451 (13.84)    16.0486 (1.01)     0.4396 (1.08)        5;391       53.9964 (0.91)       6749           1
test_bench_ascon_128a_encrypt     30.2382 (2.01)       189.3044 (1.02)     33.3974 (1.99)      11.6782 (1.34)     31.9704 (2.01)     0.7786 (1.92)      197;641       29.9424 (0.50)      10252           1
test_bench_ascon_128_encrypt      30.7076 (2.04)       226.2965 (1.22)     34.0247 (2.03)      12.0334 (1.38)     32.5143 (2.04)     0.7767 (1.91)      181;598       29.3905 (0.49)       8884           1
test_bench_ascon_128_decrypt      31.2030 (2.07)       211.7380 (1.14)     34.2008 (2.04)      11.7221 (1.34)     32.7229 (2.06)     0.7413 (1.83)     349;1124       29.2391 (0.49)      16845           1
test_bench_ascon_128a_decrypt     31.6724 (2.11)       217.4154 (1.17)     34.5162 (2.06)      11.8649 (1.36)     33.1178 (2.08)     0.6892 (1.70)     312;1109       28.9719 (0.49)      17012           1
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Legend:
  Outliers: 1 Standard Deviation from Mean; 1.5 IQR (InterQuartile Range) from 1st Quartile and 3rd Quartile.
  OPS: Operations Per Second, computed as 1 / Mean
======================================================================================================================= 6 passed, 4 deselected in 3.84s ========================================================================================================================
```

## Usage

`ascon` being a header-only library, it's pretty easy to start using its C++ API. Just import the header file and use functions living inside `ascon::` namespace. Namespace like `ascon_utils::` might also be of your interest, which has some utility routines implemented.

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
dpcpp -Wall -std=c++20 -O3 -I./include example/ascon_hash.cpp && ./a.out

Ascon-Hash digest :     2eb89744de7f9a6f47d53db756bb2f67b127da96762a1c47a5d7bfc1f7273f5c
```

See example of using

- [Ascon-Hash API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_hash.cpp)
- [Ascon-HashA API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_hasha.cpp)
- [Ascon-128 authenticated encryption/ verified decryption API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_128.cpp)
- [Ascon-128a authenticated encryption/ verified decryption API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_128a.cpp)

---

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

> I suggest you read `ascon` Python API documentation [here](https://github.com/itzmeanjan/ascon/blob/92f218b/wrapper/python/ascon.py).

> Going through Python API benchmark file should give you good overview of how to use `ascon`; follow [this](https://github.com/itzmeanjan/ascon/blob/92f218b/wrapper/python/test_ascon.py#L212-L343)
