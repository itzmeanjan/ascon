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
2023-03-28T12:34:15+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 2.27, 1.98, 2.07
----------------------------------------------------------------------------------------
Benchmark                              Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------------------
bench_ascon::permutation<1>         4.30 ns         4.28 ns    162816067 bytes_per_second=8.69732G/s
bench_ascon::permutation<6>         24.2 ns         24.0 ns     28998716 bytes_per_second=1.54978G/s
bench_ascon::permutation<8>         31.2 ns         31.1 ns     22255570 bytes_per_second=1.19909G/s
bench_ascon::permutation<12>        46.4 ns         46.3 ns     15173586 bytes_per_second=823.559M/s
bench_ascon::hash/64                 599 ns          597 ns      1121094 bytes_per_second=153.428M/s
bench_ascon::hasha/64                415 ns          413 ns      1689136 bytes_per_second=221.804M/s
bench_ascon::xof/64/32               603 ns          602 ns      1136253 bytes_per_second=151.993M/s
bench_ascon::xofa/64/32              417 ns          417 ns      1673300 bytes_per_second=219.549M/s
bench_ascon::hash/128                959 ns          958 ns       721070 bytes_per_second=159.2M/s
bench_ascon::hasha/128               655 ns          654 ns      1041124 bytes_per_second=233.251M/s
bench_ascon::xof/128/64             1181 ns         1179 ns       587776 bytes_per_second=155.258M/s
bench_ascon::xofa/128/64             807 ns          806 ns       833760 bytes_per_second=227.11M/s
bench_ascon::hash/256               1796 ns         1795 ns       384415 bytes_per_second=153.01M/s
bench_ascon::hasha/256              1137 ns         1136 ns       611824 bytes_per_second=241.777M/s
bench_ascon::xof/256/128            2333 ns         2332 ns       297415 bytes_per_second=157.048M/s
bench_ascon::xofa/256/128           1553 ns         1552 ns       448339 bytes_per_second=236.007M/s
bench_ascon::hash/512               3171 ns         3169 ns       221247 bytes_per_second=163.713M/s
bench_ascon::hasha/512              2143 ns         2138 ns       322208 bytes_per_second=242.651M/s
bench_ascon::xof/512/256            4541 ns         4537 ns       153577 bytes_per_second=161.424M/s
bench_ascon::xofa/512/256           3098 ns         3095 ns       226184 bytes_per_second=236.658M/s
bench_ascon::hash/1024              6070 ns         6064 ns       115198 bytes_per_second=166.067M/s
bench_ascon::hasha/1024             4042 ns         4040 ns       172218 bytes_per_second=249.261M/s
bench_ascon::xof/1024/512           8960 ns         8952 ns        76358 bytes_per_second=163.635M/s
bench_ascon::xofa/1024/512          6219 ns         6215 ns       112367 bytes_per_second=235.709M/s
bench_ascon::hash/2048             11830 ns        11822 ns        58255 bytes_per_second=167.796M/s
bench_ascon::hasha/2048             7865 ns         7861 ns        86546 bytes_per_second=252.333M/s
bench_ascon::xof/2048/1024         17853 ns        17847 ns        38644 bytes_per_second=164.154M/s
bench_ascon::xofa/2048/1024        12064 ns        12056 ns        57411 bytes_per_second=243.009M/s
bench_ascon::hash/4096             23693 ns        23670 ns        29553 bytes_per_second=166.316M/s
bench_ascon::hasha/4096            15553 ns        15547 ns        44170 bytes_per_second=253.211M/s
bench_ascon::xof/4096/2048         35431 ns        35405 ns        19596 bytes_per_second=165.498M/s
bench_ascon::xofa/4096/2048        23998 ns        23987 ns        28982 bytes_per_second=244.272M/s
bench_ascon::enc_128/64/32           410 ns          410 ns      1699797 bytes_per_second=223.569M/s
bench_ascon::dec_128/64/32           409 ns          408 ns      1704361 bytes_per_second=224.222M/s
bench_ascon::enc_128/128/32          605 ns          605 ns      1137952 bytes_per_second=252.395M/s
bench_ascon::dec_128/128/32          601 ns          601 ns      1147654 bytes_per_second=254.05M/s
bench_ascon::enc_128/256/32          977 ns          977 ns       712497 bytes_per_second=281.194M/s
bench_ascon::dec_128/256/32          982 ns          981 ns       705304 bytes_per_second=279.987M/s
bench_ascon::enc_128/512/32         1735 ns         1735 ns       394905 bytes_per_second=299.069M/s
bench_ascon::dec_128/512/32         1799 ns         1798 ns       387008 bytes_per_second=288.618M/s
bench_ascon::enc_128/1024/32        3253 ns         3251 ns       215981 bytes_per_second=309.802M/s
bench_ascon::dec_128/1024/32        3329 ns         3326 ns       210531 bytes_per_second=302.792M/s
bench_ascon::enc_128/2048/32        6254 ns         6250 ns       109932 bytes_per_second=317.388M/s
bench_ascon::dec_128/2048/32        6423 ns         6418 ns       105571 bytes_per_second=309.078M/s
bench_ascon::enc_128/4096/32       12283 ns        12278 ns        56270 bytes_per_second=320.629M/s
bench_ascon::dec_128/4096/32       12517 ns        12511 ns        54703 bytes_per_second=314.673M/s
bench_ascon::enc_128a/64/32          325 ns          325 ns      2149237 bytes_per_second=281.98M/s
bench_ascon::dec_128a/64/32          323 ns          322 ns      2174541 bytes_per_second=284.031M/s
bench_ascon::enc_128a/128/32         445 ns          445 ns      1564026 bytes_per_second=343.007M/s
bench_ascon::dec_128a/128/32         444 ns          443 ns      1578123 bytes_per_second=344.073M/s
bench_ascon::enc_128a/256/32         701 ns          700 ns       990169 bytes_per_second=392.444M/s
bench_ascon::dec_128a/256/32         705 ns          703 ns      1011239 bytes_per_second=390.704M/s
bench_ascon::enc_128a/512/32        1189 ns         1186 ns       582785 bytes_per_second=437.46M/s
bench_ascon::dec_128a/512/32        1180 ns         1179 ns       589191 bytes_per_second=440.138M/s
bench_ascon::enc_128a/1024/32       2173 ns         2170 ns       321641 bytes_per_second=464.032M/s
bench_ascon::dec_128a/1024/32       2189 ns         2188 ns       315066 bytes_per_second=460.314M/s
bench_ascon::enc_128a/2048/32       4089 ns         4087 ns       171025 bytes_per_second=485.315M/s
bench_ascon::dec_128a/2048/32       4112 ns         4110 ns       169190 bytes_per_second=482.639M/s
bench_ascon::enc_128a/4096/32       7940 ns         7935 ns        85587 bytes_per_second=496.133M/s
bench_ascon::dec_128a/4096/32       8007 ns         8003 ns        85751 bytes_per_second=491.937M/s
bench_ascon::enc_80pq/64/32          416 ns          416 ns      1684883 bytes_per_second=220.028M/s
bench_ascon::dec_80pq/64/32          414 ns          413 ns      1691904 bytes_per_second=221.452M/s
bench_ascon::enc_80pq/128/32         599 ns          599 ns      1137693 bytes_per_second=254.888M/s
bench_ascon::dec_80pq/128/32         603 ns          602 ns      1149746 bytes_per_second=253.468M/s
bench_ascon::enc_80pq/256/32         991 ns          990 ns       702247 bytes_per_second=277.294M/s
bench_ascon::dec_80pq/256/32         981 ns          980 ns       698429 bytes_per_second=280.24M/s
bench_ascon::enc_80pq/512/32        1774 ns         1770 ns       397459 bytes_per_second=293.136M/s
bench_ascon::dec_80pq/512/32        1843 ns         1833 ns       355117 bytes_per_second=283.075M/s
bench_ascon::enc_80pq/1024/32       3276 ns         3273 ns       213540 bytes_per_second=307.656M/s
bench_ascon::dec_80pq/1024/32       3310 ns         3309 ns       209649 bytes_per_second=304.391M/s
bench_ascon::enc_80pq/2048/32       6239 ns         6236 ns       109665 bytes_per_second=318.097M/s
bench_ascon::dec_80pq/2048/32       6362 ns         6357 ns       108510 bytes_per_second=312.02M/s
bench_ascon::enc_80pq/4096/32      12230 ns        12222 ns        56617 bytes_per_second=322.102M/s
bench_ascon::dec_80pq/4096/32      12459 ns        12452 ns        54673 bytes_per_second=316.167M/s
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
