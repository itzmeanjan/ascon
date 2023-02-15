# ascon
Accelerated Ascon: Light Weight Cryptography

## Overview

`ascon` is selected by NIST as winner of **L**ight **W**eight **C**ryptography standardization effort. Find more details @ https://www.nist.gov/news-events/news/2023/02/nist-selects-lightweight-cryptography-algorithms-protect-small-devices.

Following functionalities from Ascon cipher suite are implemented in this zero-dependency, header-only C++ library

- Ascon-128 AEAD
- Ascon-128a AEAD
- Ascon-80pq AEAD
- Ascon-Hash
- Ascon-HashA

> **Note** Read more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption).

> **Note** I've followed Ascon [specification](https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf) while working on this implementation. I suggest you also go through the specification to better understand Ascon.

## Prerequisites

- Make sure you've a C++ compiler `g++`/ `clang++` installed, along with C++20 standard library.

```bash
$ g++ --version
g++ (Ubuntu 11.2.0-19ubuntu1) 11.2.0

$ clang++ --version
Ubuntu clang version 14.0.0-1ubuntu1
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
```

- System development utilities like `make`, `cmake` and `python3` will be required for ease of building/ testing/ benchmarking.

```bash
$ make -v
GNU Make 4.3

$ cmake  --version
cmake version 3.22.1

$ python3 --version
Python 3.10.6
```

- You'll also need to install Python dependencies by issuing

```bash
python3 -m pip install --user -r wrapper/python/requirements.txt
```

- Actually it's better idea to use `venv` to keep this project isolated from existing system environment

```bash
# make sure you've `venv`
# see https://pypi.org/project/virtualenv
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

- For benchmarking this implementation, you need to have `google-benchmark` header and library --- ensure it's globally installed; follow [this](https://github.com/google/benchmark/tree/60b16f1#installation)

## Testing

For ensuring that Ascon is implemented correctly and it's conformant with the specification

- Ensure functional correctness of Ascon AEAD routines i.e. $\{{encrypt(), decrypt()}\}$ for various combination of inputs
- Assess whether this implementation of Ascon is conformant with specification, using **K**nown **A**nswer **T**ests, provided with NIST submission of Ascon

```bash
make             # test_ascon + test_kat

make test_ascon  # only functional correctness
make test_kat    # conformance with KATs ( needs Python )
```

## Benchmarking

For benchmarking Ascon lightweight crypto suite, using `google-benchmark` library, while targeting CPU systems, with variable length input data, one may issue

```bash
make benchmark
```

Following routines are benchmarked

- Ascon Permutation
- Ascon-Hash
- Ascon-HashA
- Ascon-128 ( encrypt/ decrypt )
- Ascon-128a ( encrypt/ decrypt )
- Ascon-80pq ( encrypt/ decrypt )

> **Note** Benchmark recipe expects presence of `google-benchmark` header and library in well known $PATH ( so that it can be found by the compiler ).

> **Warning** Because most of the CPUs employ dynamic frequency boosting technique, when benchmarking routines, you may want to disable CPU frequency scaling by following [this](https://github.com/google/benchmark/blob/60b16f1/docs/user_guide.md#disabling-cpu-frequency-scaling) guide.

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz ( Compiled with Clang )

```bash
2023-01-06T16:56:23+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 2.25, 1.96, 1.85
----------------------------------------------------------------------------------------
Benchmark                              Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------------------
bench_ascon::permutation<1>         4.73 ns         4.68 ns    124521925 bytes_per_second=7.96574G/s
bench_ascon::permutation<6>         25.3 ns         25.0 ns     27161260 bytes_per_second=1.49099G/s
bench_ascon::permutation<8>         35.4 ns         33.9 ns     21023673 bytes_per_second=1124.51M/s
bench_ascon::permutation<12>        49.7 ns         49.2 ns     13964530 bytes_per_second=775.653M/s
bench_ascon::hash/64                 562 ns          560 ns      1235091 bytes_per_second=108.907M/s
bench_ascon::hash_a/64               407 ns          403 ns      1584187 bytes_per_second=151.58M/s
bench_ascon::hash/128                971 ns          962 ns       689255 bytes_per_second=126.841M/s
bench_ascon::hash_a/128              658 ns          653 ns      1034600 bytes_per_second=187.026M/s
bench_ascon::hash/256               1760 ns         1750 ns       393241 bytes_per_second=139.548M/s
bench_ascon::hash_a/256             1189 ns         1178 ns       581806 bytes_per_second=207.283M/s
bench_ascon::hash/512               3231 ns         3220 ns       218017 bytes_per_second=151.66M/s
bench_ascon::hash_a/512             2201 ns         2159 ns       322158 bytes_per_second=226.111M/s
bench_ascon::hash/1024              6620 ns         6511 ns       106364 bytes_per_second=149.98M/s
bench_ascon::hash_a/1024            4224 ns         4195 ns       165815 bytes_per_second=232.784M/s
bench_ascon::hash/2048             12625 ns        12522 ns        54615 bytes_per_second=155.981M/s
bench_ascon::hash_a/2048            8409 ns         8339 ns        85579 bytes_per_second=234.219M/s
bench_ascon::hash/4096             24431 ns        24270 ns        27028 bytes_per_second=160.95M/s
bench_ascon::hash_a/4096           16332 ns        16248 ns        41928 bytes_per_second=240.414M/s
bench_ascon::enc_128/64/32           423 ns          421 ns      1668419 bytes_per_second=217.633M/s
bench_ascon::dec_128/64/32           433 ns          429 ns      1708817 bytes_per_second=213.371M/s
bench_ascon::enc_128/128/32          648 ns          640 ns      1062764 bytes_per_second=238.281M/s
bench_ascon::dec_128/128/32          651 ns          645 ns      1029487 bytes_per_second=236.59M/s
bench_ascon::enc_128/256/32         1027 ns         1021 ns       708115 bytes_per_second=269.09M/s
bench_ascon::dec_128/256/32          977 ns          976 ns       687690 bytes_per_second=281.388M/s
bench_ascon::enc_128/512/32         1752 ns         1750 ns       393219 bytes_per_second=296.46M/s
bench_ascon::dec_128/512/32         1764 ns         1762 ns       396646 bytes_per_second=294.379M/s
bench_ascon::enc_128/1024/32        3282 ns         3278 ns       209940 bytes_per_second=307.178M/s
bench_ascon::dec_128/1024/32        3304 ns         3301 ns       207684 bytes_per_second=305.067M/s
bench_ascon::enc_128/2048/32        6412 ns         6396 ns       110288 bytes_per_second=310.119M/s
bench_ascon::dec_128/2048/32        7238 ns         7124 ns        96678 bytes_per_second=278.457M/s
bench_ascon::enc_128/4096/32       13576 ns        13362 ns        54401 bytes_per_second=294.627M/s
bench_ascon::dec_128/4096/32       13085 ns        13007 ns        53879 bytes_per_second=302.655M/s
bench_ascon::enc_128a/64/32          350 ns          350 ns      1932826 bytes_per_second=261.512M/s
bench_ascon::dec_128a/64/32          380 ns          376 ns      2005036 bytes_per_second=243.476M/s
bench_ascon::enc_128a/128/32         508 ns          503 ns      1325331 bytes_per_second=303.117M/s
bench_ascon::dec_128a/128/32         482 ns          479 ns      1480626 bytes_per_second=318.364M/s
bench_ascon::enc_128a/256/32         789 ns          779 ns       908183 bytes_per_second=352.643M/s
bench_ascon::dec_128a/256/32         778 ns          769 ns       882557 bytes_per_second=357.3M/s
bench_ascon::enc_128a/512/32        1213 ns         1212 ns       574788 bytes_per_second=428.035M/s
bench_ascon::dec_128a/512/32        1337 ns         1323 ns       577396 bytes_per_second=392.022M/s
bench_ascon::enc_128a/1024/32       2258 ns         2252 ns       291266 bytes_per_second=447.164M/s
bench_ascon::dec_128a/1024/32       2192 ns         2189 ns       315232 bytes_per_second=460.094M/s
bench_ascon::enc_128a/2048/32       4398 ns         4350 ns       157749 bytes_per_second=456.008M/s
bench_ascon::dec_128a/2048/32       4620 ns         4559 ns       169528 bytes_per_second=435.128M/s
bench_ascon::enc_128a/4096/32       8052 ns         8046 ns        81555 bytes_per_second=489.259M/s
bench_ascon::dec_128a/4096/32       8031 ns         8023 ns        85692 bytes_per_second=490.684M/s
bench_ascon::enc_80pq/64/32          413 ns          412 ns      1695535 bytes_per_second=222.049M/s
bench_ascon::dec_80pq/64/32          418 ns          417 ns      1696020 bytes_per_second=219.666M/s
bench_ascon::enc_80pq/128/32         621 ns          619 ns      1078084 bytes_per_second=246.687M/s
bench_ascon::dec_80pq/128/32         613 ns          612 ns      1127704 bytes_per_second=249.168M/s
bench_ascon::enc_80pq/256/32         982 ns          981 ns       701797 bytes_per_second=279.882M/s
bench_ascon::dec_80pq/256/32         984 ns          983 ns       695362 bytes_per_second=279.36M/s
bench_ascon::enc_80pq/512/32        1784 ns         1778 ns       400009 bytes_per_second=291.801M/s
bench_ascon::dec_80pq/512/32        1931 ns         1906 ns       364627 bytes_per_second=272.183M/s
bench_ascon::enc_80pq/1024/32       3451 ns         3417 ns       191437 bytes_per_second=294.723M/s
bench_ascon::dec_80pq/1024/32       3512 ns         3478 ns       204852 bytes_per_second=289.528M/s
bench_ascon::enc_80pq/2048/32       6748 ns         6675 ns       110307 bytes_per_second=297.165M/s
bench_ascon::dec_80pq/2048/32       6813 ns         6746 ns       100699 bytes_per_second=294.042M/s
bench_ascon::enc_80pq/4096/32      13370 ns        13230 ns        52011 bytes_per_second=297.555M/s
bench_ascon::dec_80pq/4096/32      12688 ns        12649 ns        52823 bytes_per_second=311.224M/s
```

## Usage

### C++ API

`ascon` being a header-only C++ library, it's pretty easy to start using it. Just include the header file 

- For AEAD : `include/aead.hpp`
- For Hashing : `include/hash.hpp` 

and use functions living inside `ascon::` namespace. Finally when compiling the program, let your compiler know where it can find the header files using `-I` flag.

I maintain some examples demonstrating usage of Ascon Hash and AEAD API

Scheme | Example
--- | --:
Ascon Hash | [example/ascon_hash.cpp](./example/ascon_hash.cpp)
Ascon HashA | [example/ascon_hasha.cpp](./example/ascon_hasha.cpp)
Ascon-128 AEAD | [example/ascon_128.cpp](./example/ascon_128.cpp)
Ascon-128a AEAD | [example/ascon_128a.cpp](./example/ascon_128a.cpp)
Ascon-80pq AEAD | [example/ascon_80pq.cpp](./example/ascon_80pq.cpp)

```bash
$ g++ -std=c++20 -Wall -O3 -march=native -I ./include example/ascon_hash.cpp && ./a.out
Ascon Hash

Message :	a2309f40cae3efc99941641caf1c2cddf6fcd52a031ff199dfe5f185bb5142e91539b0d6777ad7fe8c2300d42015b623517f31b5db0a94d7e3c8cb521f03aabb
Digest  :	b467a2107aa34754a8679dfbac795660a5a2be927f2b0216a8fad50202d17249

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I ./include example/ascon_hasha.cpp && ./a.out
Ascon HashA

Message :	b11a401ec0ad387fdc890962e86158432ba31e50b8810e3360b4c6143a73f6f82364f6bd895938b7f0babdab065c17c7e0e7196c4a15eb345eb174f4f1da2de5
Digest  :	aa7463f3284c6b5d84aaf0c56a18ae79a2fbaf0e095111a0e65824e24892e419

# ---------------

$ g++ -std=c++20 -Wall -O3 -march=native -I ./include example/ascon_128.cpp && ./a.out
Ascon-128 AEAD

Key       :	06a819d82123676245b7b88e864b01ac
Nonce     :	aaf550e27747555336e6e1efe29618dc
Data      :	a738688dfb1d2fcfab22502e11fe2559ffca02a26c60780103c88d25c611fa83
Text      :	22bbe3e728cc9355298c614a503471b69c27a193db9331e41ba42791b63d12e8b53547daa720aa8ecef3262edd52bfd871f5425f2fc3e1c7cbc0b20a69ccc1d4
Encrypted :	f5a716b9f709329a75deceeb0a72e4dbed86b89679beb99d26e1e47ff8f26f984785ac3f80677570240efb10e0bf5e93bde8c2662599052fa67026783fe2a061
Decrypted :	22bbe3e728cc9355298c614a503471b69c27a193db9331e41ba42791b63d12e8b53547daa720aa8ecef3262edd52bfd871f5425f2fc3e1c7cbc0b20a69ccc1d4

# ----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I ./include example/ascon_128a.cpp && ./a.out
Ascon-128a AEAD

Key       :	88119fff6f0673cfc8d0269bac8ca328
Nonce     :	0c4b7bda5d47fda1b24b06b7292dd125
Data      :	49abcffb323076de7b068b5cba32344064a9462833a32ce2f8296947d16fb708
Text      :	2b2e331614af85f38500a3fbe182ec4c00bd0b5a200b852f582a63249363892043c040f0950dec14038cb82a91fd057a0edb81b691fe726be9a1fa3848b38e3d
Encrypted :	d71d984670a27cb8eb033d0c10be866966315d7ad60b048fc7f5f9a90fc02534f7c807baf6f32255bd94d7872a12e47dd3bf99439da8634d996ffe1e8cf08dcf
Decrypted :	2b2e331614af85f38500a3fbe182ec4c00bd0b5a200b852f582a63249363892043c040f0950dec14038cb82a91fd057a0edb81b691fe726be9a1fa3848b38e3d

# -----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I ./include example/ascon_80pq.cpp && ./a.out
Ascon-80pq AEAD

Key       :	93afc9866d8fafb4d4895a97147da2639e652407
Nonce     :	6962c11757edcfd96ac6e3312bb22615
Data      :	8c132efaa2b27795f0da45846af44f44a8fa2d98df99e301639baa0f59c57035
Text      :	6d27382a7c6184fe52ea354574bfc8da49cbd7cb830183820d3e47368489428d89c4954a42ffb4f602b0cd1a9c678a25b8cc93d8b4ec39b56ea1b8157fc44864
Encrypted :	00fe776e96d074e556f84a47bc826f7be113436bda07198b3237f1f7d261ae60847609341d7c5b0c317244d9c0e3cb662e29440a43fc614d3a2a6ca488426225
Decrypted :	6d27382a7c6184fe52ea354574bfc8da49cbd7cb830183820d3e47368489428d89c4954a42ffb4f602b0cd1a9c678a25b8cc93d8b4ec39b56ea1b8157fc44864
```

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
>>> ascon.hash(b'').hex()               # computing ascon-hash digest
'7346bc14f036e87ae03d0997913088f5f68411434b3cf8b54fa796a80d251f91'
>>>

$ popd
```

Example script demonstrating usage of `ascon` Python API, can be found [here](./wrapper/python/example.py)

```bash
make lib # must do !

pushd wrapper/python
python3 example.py
popd
```

> **Note** I suggest you read `ascon` Python API documentation [here](./wrapper/python/ascon.py).
