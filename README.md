> **Warning** **This implementation is not yet audited. If you consider using it in production, be careful !**

# ascon
Accelerated Ascon: Light Weight Cryptography

## Overview

`ascon` is selected by NIST as winner of **L**ight **W**eight **C**ryptography standardization effort. Find more details @ https://www.nist.gov/news-events/news/2023/02/nist-selects-lightweight-cryptography-algorithms-protect-small-devices.

Following functionalities, from Ascon light weight cryptography suite, are implemented in this zero-dependency, header-only C++ library

Scheme | Input | Output
--- | --: | --:
Ascon-128 AEAD | 16B key, 16B nonce, N -bytes associated data and M -bytes plain text | 16B authentication tag and M -bytes cipher text
Ascon-128A AEAD | 16B key, 16B nonce, N -bytes associated data and M -bytes plain text | 16B authentication tag and M -bytes cipher text
Ascon-80pq AEAD | 20B key, 16B nonce, N -bytes associated data and M -bytes plain text | 16B authentication tag and M -bytes cipher text
Ascon-Hash | N -bytes message | 32B digest
Ascon-HashA | N -bytes message | 32B digest
Ascon-XOF | N -bytes message | Arbitrary many bytes digest
Ascon-XOFA | N -bytes message | Arbitrary many bytes digest

> **Note** Ascon-{Hash, HashA, XOF, XOFA} supports both oneshot and incremental hashing. If all message bytes are not ready to be absorbed into hash state in a single go, one opts for using ( compile-time decision ) incremental hashing API where arbitrary number of absorptions of arbitrary many bytes is allowed before state is finalized and ready to be squeezed.

> **Note** Read more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption).

> **Warning** Associated data is never encrypted. AEAD scheme provides secrecy only for plain text but authenticity and integrity for both associated data and plain text.

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

- Ensure functional correctness of Ascon AEAD, Hash and XOF routines for various combination of inputs.
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
- Ascon-XOF
- Ascon-XOFA
- Ascon-128 ( encrypt/ decrypt )
- Ascon-128a ( encrypt/ decrypt )
- Ascon-80pq ( encrypt/ decrypt )

> **Note** Benchmark recipe expects presence of `google-benchmark` header and library in well known $PATH ( so that it can be found by the compiler ).

> **Warning** Because most of the CPUs employ dynamic frequency boosting technique, when benchmarking routines, you may want to disable CPU frequency scaling by following [this](https://github.com/google/benchmark/blob/60b16f1/docs/user_guide.md#disabling-cpu-frequency-scaling) guide.

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz ( Compiled with Clang )

```bash
2023-02-17T14:14:28+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 3.43, 3.53, 2.52
----------------------------------------------------------------------------------------
Benchmark                              Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------------------
bench_ascon::permutation<1>         4.24 ns         4.23 ns    164508859 bytes_per_second=8.79776G/s
bench_ascon::permutation<6>         23.6 ns         23.6 ns     29310901 bytes_per_second=1.57837G/s
bench_ascon::permutation<8>         30.7 ns         30.7 ns     22643829 bytes_per_second=1.21201G/s
bench_ascon::permutation<12>        46.0 ns         45.9 ns     15194105 bytes_per_second=830.531M/s
bench_ascon::hash/64                 592 ns          592 ns      1161749 bytes_per_second=154.762M/s
bench_ascon::hasha/64                409 ns          409 ns      1710074 bytes_per_second=224.071M/s
bench_ascon::xof/64/32               599 ns          598 ns      1145869 bytes_per_second=153M/s
bench_ascon::xofa/64/32              416 ns          416 ns      1677961 bytes_per_second=220.229M/s
bench_ascon::hash/128                959 ns          959 ns       715322 bytes_per_second=159.175M/s
bench_ascon::hasha/128               682 ns          680 ns      1023317 bytes_per_second=224.547M/s
bench_ascon::xof/128/64             1178 ns         1177 ns       588933 bytes_per_second=155.507M/s
bench_ascon::xofa/128/64             806 ns          805 ns       854471 bytes_per_second=227.443M/s
bench_ascon::hash/256               1727 ns         1725 ns       401204 bytes_per_second=159.184M/s
bench_ascon::hasha/256              1132 ns         1131 ns       613470 bytes_per_second=242.747M/s
bench_ascon::xof/256/128            2330 ns         2328 ns       297575 bytes_per_second=157.302M/s
bench_ascon::xofa/256/128           1560 ns         1558 ns       449762 bytes_per_second=235.006M/s
bench_ascon::hash/512               3172 ns         3169 ns       221144 bytes_per_second=163.713M/s
bench_ascon::hasha/512              2132 ns         2130 ns       327224 bytes_per_second=243.513M/s
bench_ascon::xof/512/256            4550 ns         4547 ns       153840 bytes_per_second=161.085M/s
bench_ascon::xofa/512/256           3097 ns         3095 ns       226133 bytes_per_second=236.663M/s
bench_ascon::hash/1024              6071 ns         6064 ns       115697 bytes_per_second=166.082M/s
bench_ascon::hasha/1024             4044 ns         4041 ns       172820 bytes_per_second=249.185M/s
bench_ascon::xof/1024/512           8980 ns         8974 ns        76524 bytes_per_second=163.229M/s
bench_ascon::xofa/1024/512          6077 ns         6073 ns       113226 bytes_per_second=241.208M/s
bench_ascon::hash/2048             11809 ns        11803 ns        58264 bytes_per_second=168.064M/s
bench_ascon::hasha/2048             7855 ns         7852 ns        87159 bytes_per_second=252.622M/s
bench_ascon::xof/2048/1024         17761 ns        17749 ns        39102 bytes_per_second=165.064M/s
bench_ascon::xofa/2048/1024        12051 ns        12044 ns        57657 bytes_per_second=243.249M/s
bench_ascon::hash/4096             23340 ns        23329 ns        29886 bytes_per_second=168.75M/s
bench_ascon::hasha/4096            15501 ns        15492 ns        44621 bytes_per_second=254.111M/s
bench_ascon::xof/4096/2048         35528 ns        35508 ns        19648 bytes_per_second=165.017M/s
bench_ascon::xofa/4096/2048        23915 ns        23903 ns        29008 bytes_per_second=245.135M/s
bench_ascon::enc_128/64/32           407 ns          407 ns      1710647 bytes_per_second=225.16M/s
bench_ascon::dec_128/64/32           409 ns          409 ns      1701830 bytes_per_second=224.02M/s
bench_ascon::enc_128/128/32          598 ns          598 ns      1147259 bytes_per_second=255.197M/s
bench_ascon::dec_128/128/32          602 ns          602 ns      1142652 bytes_per_second=253.529M/s
bench_ascon::enc_128/256/32          984 ns          984 ns       704835 bytes_per_second=279.199M/s
bench_ascon::dec_128/256/32          990 ns          989 ns       693021 bytes_per_second=277.722M/s
bench_ascon::enc_128/512/32         1734 ns         1733 ns       401204 bytes_per_second=299.333M/s
bench_ascon::dec_128/512/32         1800 ns         1799 ns       386886 bytes_per_second=288.33M/s
bench_ascon::enc_128/1024/32        3229 ns         3227 ns       216129 bytes_per_second=312.104M/s
bench_ascon::dec_128/1024/32        3335 ns         3333 ns       209964 bytes_per_second=302.192M/s
bench_ascon::enc_128/2048/32        6253 ns         6250 ns       107337 bytes_per_second=317.384M/s
bench_ascon::dec_128/2048/32        6384 ns         6378 ns       107331 bytes_per_second=310.998M/s
bench_ascon::enc_128/4096/32       12300 ns        12292 ns        55730 bytes_per_second=320.266M/s
bench_ascon::dec_128/4096/32       12560 ns        12550 ns        54998 bytes_per_second=313.688M/s
bench_ascon::enc_128a/64/32          325 ns          325 ns      2155352 bytes_per_second=281.75M/s
bench_ascon::dec_128a/64/32          324 ns          324 ns      2157437 bytes_per_second=283.004M/s
bench_ascon::enc_128a/128/32         444 ns          444 ns      1573299 bytes_per_second=343.572M/s
bench_ascon::dec_128a/128/32         443 ns          443 ns      1577500 bytes_per_second=344.62M/s
bench_ascon::enc_128a/256/32         697 ns          697 ns       975093 bytes_per_second=394.131M/s
bench_ascon::dec_128a/256/32         695 ns          694 ns       988617 bytes_per_second=395.578M/s
bench_ascon::enc_128a/512/32        1181 ns         1180 ns       586132 bytes_per_second=439.662M/s
bench_ascon::dec_128a/512/32        1177 ns         1176 ns       587357 bytes_per_second=441.295M/s
bench_ascon::enc_128a/1024/32       2144 ns         2142 ns       325146 bytes_per_second=470.116M/s
bench_ascon::dec_128a/1024/32       2199 ns         2198 ns       318862 bytes_per_second=458.238M/s
bench_ascon::enc_128a/2048/32       4075 ns         4072 ns       171668 bytes_per_second=487.123M/s
bench_ascon::dec_128a/2048/32       4122 ns         4120 ns       168813 bytes_per_second=481.477M/s
bench_ascon::enc_128a/4096/32       7969 ns         7962 ns        86266 bytes_per_second=494.457M/s
bench_ascon::dec_128a/4096/32       8017 ns         8010 ns        85949 bytes_per_second=491.49M/s
bench_ascon::enc_80pq/64/32          409 ns          409 ns      1711584 bytes_per_second=223.997M/s
bench_ascon::dec_80pq/64/32          415 ns          414 ns      1686954 bytes_per_second=220.964M/s
bench_ascon::enc_80pq/128/32         603 ns          602 ns      1146132 bytes_per_second=253.326M/s
bench_ascon::dec_80pq/128/32         606 ns          605 ns      1119964 bytes_per_second=252.046M/s
bench_ascon::enc_80pq/256/32         976 ns          975 ns       707643 bytes_per_second=281.627M/s
bench_ascon::dec_80pq/256/32        1005 ns         1004 ns       686423 bytes_per_second=273.576M/s
bench_ascon::enc_80pq/512/32        1732 ns         1730 ns       400469 bytes_per_second=299.861M/s
bench_ascon::dec_80pq/512/32        1810 ns         1809 ns       383171 bytes_per_second=286.719M/s
bench_ascon::enc_80pq/1024/32       3222 ns         3221 ns       216382 bytes_per_second=312.664M/s
bench_ascon::dec_80pq/1024/32       3344 ns         3342 ns       208820 bytes_per_second=301.326M/s
bench_ascon::enc_80pq/2048/32       6231 ns         6227 ns       108987 bytes_per_second=318.573M/s
bench_ascon::dec_80pq/2048/32       6419 ns         6416 ns       107273 bytes_per_second=309.17M/s
bench_ascon::enc_80pq/4096/32      12208 ns        12201 ns        55878 bytes_per_second=322.654M/s
bench_ascon::dec_80pq/4096/32      12539 ns        12534 ns        54918 bytes_per_second=314.096M/s
```

## Usage

### C++ API

`ascon` being a header-only C++ library, it's pretty easy to start using it. Just include the header file 

- For AEAD : `include/aead.hpp`
- For Hashing : `include/hash.hpp` 

and use functions/ structs/ constants living inside `ascon::` namespace. Finally when compiling the program, let your compiler know where it can find the header files using `-I` flag.

I maintain some examples demonstrating usage of Ascon Hash, XOF and AEAD API

Scheme | Header | Example
--- | --: | --:
Ascon Hash | `include/ascon_hash.hpp` | [example/ascon_hash.cpp](./example/ascon_hash.cpp)
Ascon HashA | `include/ascon_hasha.hpp` | [example/ascon_hasha.cpp](./example/ascon_hasha.cpp)
Ascon XOF | `include/ascon_xof.hpp` | [example/ascon_xof.cpp](./example/ascon_xof.cpp)
Ascon XOFA | `include/ascon_xofa.hpp` | [example/ascon_xofa.cpp](./example/ascon_xofa.cpp)
Ascon-128 AEAD | `include/aead.hpp` | [example/ascon_128.cpp](./example/ascon_128.cpp)
Ascon-128a AEAD | `include/aead.hpp` | [example/ascon_128a.cpp](./example/ascon_128a.cpp)
Ascon-80pq AEAD | `include/aead.hpp` | [example/ascon_80pq.cpp](./example/ascon_80pq.cpp)

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

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I ./include example/ascon_xof.cpp && ./a.out
Ascon XOF

Message :	5265ce4d5d0b3a0d89c757e4b14049a4da449be528e9bb7606363717c16bf1f751ff64c4214aebe385ed4629b7eb14ff1a3f0ca6754ce6e54210efd33d117d41
Digest  :	65e2631e1478b8cec2fcbc8efbd954aefc4b20649d48818f06e95d355e4bda2b4d830ff05cd88f92a0d312c08e9c9959dcc8bb0e68c9ac0c0164becda6cd5acc

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I ./include example/ascon_xofa.cpp && ./a.out
Ascon XOFA

Message :	6970b5465e902633d16179a2c6f68cb8ad52e853bda99cf72b9bb33bbb23d0df6b22b67e7e4dbe53e04abaa63d69ee84b0e8e87a3cdd94c9da105622ffa50755
Digest  :	52644d6ba60bd3eca3aa2dabfe69ae397ddcdd0f0abd5151bf1d0e23cb4da41b3ab75634e26bae4b19f78e95fbdd54961b35cb5c7ef3ec7639816f0833ffaea7

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
>>>
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
