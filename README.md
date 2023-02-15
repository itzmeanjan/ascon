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
2023-02-15T09:37:49+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.85, 1.51, 1.46
----------------------------------------------------------------------------------------
Benchmark                              Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------------------
bench_ascon::permutation<1>         4.26 ns         4.26 ns    162453324 bytes_per_second=8.74782G/s
bench_ascon::permutation<6>         23.7 ns         23.7 ns     29463140 bytes_per_second=1.57083G/s
bench_ascon::permutation<8>         31.1 ns         31.1 ns     22525132 bytes_per_second=1.19919G/s
bench_ascon::permutation<12>        46.2 ns         46.1 ns     14905859 bytes_per_second=828.19M/s
bench_ascon::hash/64                 551 ns          549 ns      1248974 bytes_per_second=111.114M/s
bench_ascon::hash_a/64               378 ns          377 ns      1850520 bytes_per_second=161.74M/s
bench_ascon::hash/128                919 ns          918 ns       760498 bytes_per_second=132.942M/s
bench_ascon::hash_a/128              631 ns          630 ns      1088901 bytes_per_second=193.625M/s
bench_ascon::hash/256               1655 ns         1650 ns       424248 bytes_per_second=147.968M/s
bench_ascon::hash_a/256             1124 ns         1121 ns       614057 bytes_per_second=217.783M/s
bench_ascon::hash/512               3124 ns         3120 ns       221233 bytes_per_second=156.525M/s
bench_ascon::hash_a/512             2128 ns         2122 ns       332610 bytes_per_second=230.157M/s
bench_ascon::hash/1024              6093 ns         6072 ns       114215 bytes_per_second=160.837M/s
bench_ascon::hash_a/1024            4035 ns         4032 ns       173366 bytes_per_second=242.231M/s
bench_ascon::hash/2048             11811 ns        11803 ns        57142 bytes_per_second=165.481M/s
bench_ascon::hash_a/2048            7881 ns         7876 ns        86952 bytes_per_second=248M/s
bench_ascon::hash/4096             23474 ns        23451 ns        29623 bytes_per_second=166.568M/s
bench_ascon::hash_a/4096           15615 ns        15602 ns        44455 bytes_per_second=250.363M/s
bench_ascon::enc_128/64/32           409 ns          409 ns      1685711 bytes_per_second=224.075M/s
bench_ascon::dec_128/64/32           414 ns          413 ns      1704586 bytes_per_second=221.642M/s
bench_ascon::enc_128/128/32          604 ns          603 ns      1135258 bytes_per_second=253.205M/s
bench_ascon::dec_128/128/32          603 ns          602 ns      1146076 bytes_per_second=253.667M/s
bench_ascon::enc_128/256/32          979 ns          978 ns       707628 bytes_per_second=280.887M/s
bench_ascon::dec_128/256/32         1000 ns          995 ns       685979 bytes_per_second=275.99M/s
bench_ascon::enc_128/512/32         1753 ns         1748 ns       399261 bytes_per_second=296.721M/s
bench_ascon::dec_128/512/32         1793 ns         1792 ns       388151 bytes_per_second=289.567M/s
bench_ascon::enc_128/1024/32        3258 ns         3257 ns       214646 bytes_per_second=309.22M/s
bench_ascon::dec_128/1024/32        3311 ns         3310 ns       211289 bytes_per_second=304.291M/s
bench_ascon::enc_128/2048/32        6273 ns         6270 ns       109186 bytes_per_second=316.384M/s
bench_ascon::dec_128/2048/32        6392 ns         6389 ns       107242 bytes_per_second=310.491M/s
bench_ascon::enc_128/4096/32       12300 ns        12292 ns        55755 bytes_per_second=320.27M/s
bench_ascon::dec_128/4096/32       12577 ns        12571 ns        54978 bytes_per_second=313.174M/s
bench_ascon::enc_128a/64/32          324 ns          324 ns      2149547 bytes_per_second=282.309M/s
bench_ascon::dec_128a/64/32          322 ns          322 ns      2165332 bytes_per_second=284.303M/s
bench_ascon::enc_128a/128/32         446 ns          446 ns      1576204 bytes_per_second=342.309M/s
bench_ascon::dec_128a/128/32         443 ns          443 ns      1573702 bytes_per_second=344.55M/s
bench_ascon::enc_128a/256/32         698 ns          698 ns       985513 bytes_per_second=393.673M/s
bench_ascon::dec_128a/256/32         704 ns          703 ns       987195 bytes_per_second=390.648M/s
bench_ascon::enc_128a/512/32        1181 ns         1180 ns       585240 bytes_per_second=439.593M/s
bench_ascon::dec_128a/512/32        1178 ns         1178 ns       579821 bytes_per_second=440.528M/s
bench_ascon::enc_128a/1024/32       2151 ns         2149 ns       323764 bytes_per_second=468.571M/s
bench_ascon::dec_128a/1024/32       2197 ns         2195 ns       317604 bytes_per_second=458.789M/s
bench_ascon::enc_128a/2048/32       4102 ns         4098 ns       171816 bytes_per_second=484.002M/s
bench_ascon::dec_128a/2048/32       4129 ns         4127 ns       168881 bytes_per_second=480.693M/s
bench_ascon::enc_128a/4096/32       7976 ns         7970 ns        86837 bytes_per_second=493.925M/s
bench_ascon::dec_128a/4096/32       8040 ns         8034 ns        86295 bytes_per_second=490.044M/s
bench_ascon::enc_80pq/64/32          411 ns          411 ns      1700226 bytes_per_second=222.627M/s
bench_ascon::dec_80pq/64/32          412 ns          411 ns      1699652 bytes_per_second=222.541M/s
bench_ascon::enc_80pq/128/32         604 ns          603 ns      1149557 bytes_per_second=253.031M/s
bench_ascon::dec_80pq/128/32         604 ns          603 ns      1149822 bytes_per_second=252.884M/s
bench_ascon::enc_80pq/256/32         983 ns          982 ns       709342 bytes_per_second=279.762M/s
bench_ascon::dec_80pq/256/32         988 ns          988 ns       692850 bytes_per_second=277.975M/s
bench_ascon::enc_80pq/512/32        1734 ns         1733 ns       397574 bytes_per_second=299.331M/s
bench_ascon::dec_80pq/512/32        1799 ns         1797 ns       388306 bytes_per_second=288.624M/s
bench_ascon::enc_80pq/1024/32       3238 ns         3235 ns       216541 bytes_per_second=311.311M/s
bench_ascon::dec_80pq/1024/32       3319 ns         3317 ns       210745 bytes_per_second=303.65M/s
bench_ascon::enc_80pq/2048/32       6259 ns         6255 ns       110805 bytes_per_second=317.12M/s
bench_ascon::dec_80pq/2048/32       6772 ns         6762 ns       107510 bytes_per_second=293.339M/s
bench_ascon::enc_80pq/4096/32      12240 ns        12235 ns        56512 bytes_per_second=321.773M/s
bench_ascon::dec_80pq/4096/32      12654 ns        12648 ns        54236 bytes_per_second=311.248M/s
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
>>> import random
>>> ascon.hash(b'').hex()               # computing ascon-hash digest
'7346bc14f036e87ae03d0997913088f5f68411434b3cf8b54fa796a80d251f91'
>>> key = random.randbytes(16)
>>> nonce = random.randbytes(16)
>>> msg = b'abcd'
>>> enc, tag = ascon.encrypt_128a(key, nonce, b'', msg)
>>> verf, dec = ascon.decrypt_128a(key, nonce, b'', enc, tag)
>>> assert verf
>>> assert msg == dec

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
