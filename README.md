> **Warning** This implementation attempts to provide you with constant-timeness though it is not yet audited. If you consider using it in production, be careful !

# ascon
Accelerated Ascon Cipher Suite: Light Weight Cryptography

## Overview

`ascon` cipher suite is selected by NIST as winner of **L**ight **W**eight **C**ryptography standardization effort and it's being standardized at the time of writing. Find more details @ https://www.nist.gov/news-events/news/2023/02/nist-selects-lightweight-cryptography-algorithms-protect-small-devices.

Following functionalities, from Ascon light weight cryptography suite, are implemented in this zero-dependency, header-only C++ library.

Scheme | What does it do ? | Comments
:-- | :-: | --:
Ascon-128 AEAD | Given 16B key, 16B nonce, N -bytes associated data and M -bytes plain text, encryption routine can be used for computing 16B authentication tag and M -bytes cipher text. While decryption algorithm can be used for decrypting cipher text, producing equal length plain text, given key, nonce, associated data ( if any ) and authentication tag. It only releases plain text if tag can be verified, in constant-time. | Primary AEAD candidate.
Ascon-128A AEAD | Same as above. | Secondary AEAD candidate, though executes faster due to higher RATE.
Ascon-80pq AEAD | Same as above, only difference is that it uses 20 -bytes secret key. | Post-quantum AEAD candidate, because it has key length of 160 -bits.
Ascon-Hash | Given N -bytes input message, hasher can be used for producing 32 -bytes digest. | Primary hash function candidate.
Ascon-HashA | Same as above. | Secondary hash function candidate, faster because it has smaller number of permutation rounds.
Ascon-XOF | Given N -bytes input message, hasher can be used for squeezing arbitrary many digest bytes. | Primary extendable output function candidate.
Ascon-XOFA | Same as above. | Secondary extendable output function candidate, faster because it has smaller number of permutation rounds.
Ascon-PRF | Given 16 -bytes key and N -bytes input message, this routine can be used for squeezing arbitrary many tag bytes. | Pseudo-random function for arbitrary length messages, proposed in https://ia.cr/2021/1574.
Ascon-MAC | Given 16 -bytes key and N -bytes input message, this routine can be used for computing 16 -bytes tag, during authentication phase. While during verification, received tag can be verified by locally computing 16 -bytes tag and comparing it constant-time. | Messaege authentication code function proposed in https://ia.cr/2021/1574, built using Ascon-PRF.
Ascon-PRFShort | Given 16 -bytes key and <= 16 -bytes input message, to be authenticated, this routine can be used for computing a <= 16 -bytes authentication tag. This PRF scheme can be used for building a message authentication code algorithm for short input messages. | Pseudo-random function for short input messages, proposed in https://ia.cr/2021/1574.

> **Note** Ascon-{Hash, HashA, Xof, XofA} supports incremental message absorption. If all message bytes are not ready to be absorbed into hash state in a single go, one can absorb messages as they become available. One may invoke absorb routine as many times necessary, until state is finalized and ready to be squeezed.

> **Note** Read more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption).

> **Warning** Associated data is never encrypted. AEAD scheme provides secrecy only for plain text but authenticity and integrity for both associated data and cipher text.

> **Note** Ascon based psuedo-random function and message authentication code scheme i.e. Ascon-PRF and Ascon-MAC respectively, support incremental message absorption/ authentication and squeezing.

> **Note** I've followed Ascon [specification](https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf) and another follow-up [paper](https://eprint.iacr.org/2021/1574.pdf), describing Ascon based authentication schemes, while working on this library implementation. I suggest you also go through these specifications to better understand Ascon cipher suite.

## Prerequisites

- Make sure you've a C++ compiler `g++`/ `clang++` installed, along with C++20 standard library.

```bash
$ g++ --version
g++ (Ubuntu 13.1.0-2ubuntu2~23.04) 13.1.0

$ clang++ --version
Ubuntu clang version 16.0.0 (1~exp5ubuntu3)
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
```

- Build tools like `make`, `cmake` will be required for ease of building/ testing/ benchmarking.

```bash
$ make -v
GNU Make 4.3

$ cmake  --version
cmake version 3.25.1
```

- `subtle` is a ( git submodule -based ) dependency of this project - used for constant-time authentication tag comparison and setting memory locations of plain text to zero bytes, in case of authentication failure. Import `subtle` by issuing

```bash
# assuming you've already cloned `ascon`
git submodule update --init
```

- For benchmarking this library implementation, you need to have `google-benchmark` header and library installed --- ensure it's globally installed; follow [this](https://github.com/google/benchmark/#installation) guide.
- **Note:** If you are on a machine running GNU/Linux kernel and you want to obtain following (see list below), for Ascon based constructions, you should consider building google-benchmark library with libPFM support, following [this](https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7) step-by-step guide. Find more about libPFM @ https://perfmon2.sourceforge.net.
    1) CPU cycle count.
    2) Retired instruction count.
    3) Cycles/ byte ( aka cpb ).
    4) Retired instructions/ cycle ( aka ipc ).

## Testing

For ensuring that Ascon cipher suite is implemented correctly and it's conformant with the specification.

- Ensure functional correctness of Ascon AEAD, Hash and Xof routines for various combination of inputs.
- Assess whether this implementation of Ascon cipher suite is conformant with specification, using **K**nown **A**nswer **T**ests, which can be found inside [kats](./kats/) directory. These KAT files are originally taken from Ascon reference implementation repository i.e. https://github.com/ascon/ascon-c.git.

```bash
make -j $(nproc --all)
```

```bash
[==========] Running 21 tests from 4 test suites.
[----------] Global test environment set-up.
[----------] 4 tests from AsconPermutation
[ RUN      ] AsconPermutation.AsconPermWithAsconHashIV
[       OK ] AsconPermutation.AsconPermWithAsconHashIV (0 ms)
[ RUN      ] AsconPermutation.AsconPermWithAsconHashAIV
[       OK ] AsconPermutation.AsconPermWithAsconHashAIV (0 ms)
[ RUN      ] AsconPermutation.AsconPermWithAsconXofIV
[       OK ] AsconPermutation.AsconPermWithAsconXofIV (0 ms)
[ RUN      ] AsconPermutation.AsconPermWithAsconXofAIV
[       OK ] AsconPermutation.AsconPermWithAsconXofAIV (0 ms)
[----------] 4 tests from AsconPermutation (0 ms total)

[----------] 6 tests from AsconAEAD
[ RUN      ] AsconAEAD.CorrectnessTestAscon128AEAD
[       OK ] AsconAEAD.CorrectnessTestAscon128AEAD (69 ms)
[ RUN      ] AsconAEAD.KnownAnswerTestsAscon128AEAD
[       OK ] AsconAEAD.KnownAnswerTestsAscon128AEAD (0 ms)
[ RUN      ] AsconAEAD.CorrectnessTestAscon128aAEAD
[       OK ] AsconAEAD.CorrectnessTestAscon128aAEAD (67 ms)
[ RUN      ] AsconAEAD.KnownAnswerTestsAscon128aAEAD
[       OK ] AsconAEAD.KnownAnswerTestsAscon128aAEAD (0 ms)
[ RUN      ] AsconAEAD.CorrectnessTestAscon80pqAEAD
[       OK ] AsconAEAD.CorrectnessTestAscon80pqAEAD (69 ms)
[ RUN      ] AsconAEAD.KnownAnswerTestsAscon80pqAEAD
[       OK ] AsconAEAD.KnownAnswerTestsAscon80pqAEAD (0 ms)
[----------] 6 tests from AsconAEAD (209 ms total)

[----------] 8 tests from AsconHashing
[ RUN      ] AsconHashing.IncrementalMessageAbsorptionAsconHash
[       OK ] AsconHashing.IncrementalMessageAbsorptionAsconHash (7 ms)
[ RUN      ] AsconHashing.KnownAnswerTestsAsconHash
[       OK ] AsconHashing.KnownAnswerTestsAsconHash (3 ms)
[ RUN      ] AsconHashing.IncrementalMessageAbsorptionAsconHashA
[       OK ] AsconHashing.IncrementalMessageAbsorptionAsconHashA (6 ms)
[ RUN      ] AsconHashing.KnownAnswerTestsAsconHashA
[       OK ] AsconHashing.KnownAnswerTestsAsconHashA (2 ms)
[ RUN      ] AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXof
[       OK ] AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXof (2238 ms)
[ RUN      ] AsconHashing.KnownAnswerTestsAsconXof
[       OK ] AsconHashing.KnownAnswerTestsAsconXof (3 ms)
[ RUN      ] AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXofA
[       OK ] AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXofA (1734 ms)
[ RUN      ] AsconHashing.KnownAnswerTestsAsconXofA
[       OK ] AsconHashing.KnownAnswerTestsAsconXofA (2 ms)
[----------] 8 tests from AsconHashing (3999 ms total)

[----------] 3 tests from AsconAuth
[ RUN      ] AsconAuth.KnownAnswerTestsAsconMac
[       OK ] AsconAuth.KnownAnswerTestsAsconMac (1 ms)
[ RUN      ] AsconAuth.KnownAnswerTestsAsconPRF
[       OK ] AsconAuth.KnownAnswerTestsAsconPRF (1 ms)
[ RUN      ] AsconAuth.KnownAnswerTestsAsconPRFShort
[       OK ] AsconAuth.KnownAnswerTestsAsconPRFShort (0 ms)
[----------] 3 tests from AsconAuth (3 ms total)

[----------] Global test environment tear-down
[==========] 21 tests from 4 test suites ran. (4212 ms total)
[  PASSED  ] 21 tests.
```

## Benchmarking

For benchmarking routines of Ascon lightweight cipher suite, using `google-benchmark` library, while targeting CPU systems, with variable length input data, one may issue following commands.

```bash
make benchmark -j $(nproc --all) # If you haven't built google-benchmark library with libPFM support.
make perf -j $(nproc --all)      # Must do if your google-benchmark library is built with libPFM support.
```

Following routines are benchmarked

- Ascon Permutation
- Ascon-128 ( encrypt/ decrypt )
- Ascon-128a ( encrypt/ decrypt )
- Ascon-80pq ( encrypt/ decrypt )
- Ascon-Hash
- Ascon-HashA
- Ascon-XOF
- Ascon-XOFA
- Ascon-PRF
- Ascon-MAC ( authenticate/ verify )
- Ascon-PRFShort ( authenticate/ verify )

> **Note** Benchmark recipe expects presence of `google-benchmark` header and library in `$PATH` ( so that it can be found by the compiler ).

> **Warning** Ensure that you've disabled CPU frequency scaling, when benchmarking routines, following [this](https://github.com/google/benchmark/blob/main/docs/reducing_variance.md) guide.

> **Note** `make perf -j $(nproc --all)` - was issued when collecting following benchmarks. Notice, columns such as *cycles*, *cycles/ byte*, *instructions* and *instructions/ cycle*. Follow [this](https://github.com/google/benchmark/blob/main/docs/perf_counters.md) for more details.

### On 12th Gen Intel(R) Core(TM) i7-1260P ( Compiled with GCC-13.1.0 )

```bash
2023-08-04T22:55:24+04:00
Running ./benchmarks/perf.out
Run on (16 X 4606.6 MHz CPU s)
CPU Caches:             
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.40, 0.71, 0.76           
***WARNING*** There are 133 benchmarks with threads and 2 performance counters were requested. Beware counters will reflect the combined usage across all threads.
---------------------------------------------------------------------------------------------------------------------------------------------------
Benchmark                               Time             CPU   Iterations     CYCLES CYCLES/ BYTE INSTRUCTIONS INSTRUCTIONS/ CYCLE bytes_per_second
---------------------------------------------------------------------------------------------------------------------------------------------------
ascon_permutation<1>                 6.70 ns         6.69 ns    104570667    31.1741     0.779351           57             1.82844       5.56429G/s
ascon_permutation<6>                 22.0 ns         22.0 ns     31981901    102.361      2.55902          265             2.58888       1.69286G/s
ascon_permutation<8>                 27.7 ns         27.7 ns     25087250    129.818      3.24544          370             2.85015       1.34264G/s
ascon_permutation<12>                39.7 ns         39.7 ns     17492543    185.857      4.64643          546             2.93774       960.593M/s
ascon128_aead_encrypt/64/32           328 ns          328 ns      2139005    1.5328k      15.9667       4.745k             3.09564       278.811M/s
ascon128_aead_encrypt/128/32          478 ns          478 ns      1458932   2.23522k      13.9701       6.849k             3.06413       319.484M/s
ascon128_aead_encrypt/256/32          782 ns          782 ns       889108   3.65354k      12.6859      11.057k             3.02638       351.304M/s
ascon128_aead_encrypt/512/32         1383 ns         1383 ns       506743   6.45108k      11.8586      19.473k             3.01856       375.141M/s
ascon128_aead_encrypt/1024/32        2609 ns         2608 ns       269461   12.1853k      11.5391      36.305k             2.97941       386.094M/s
ascon128_aead_encrypt/2048/32        5001 ns         5000 ns       139844   23.3381k      11.2202      69.969k             2.99806       396.721M/s
ascon128_aead_encrypt/4096/32        9808 ns         9807 ns        71392   45.8982k      11.1187     137.297k             2.99134       401.408M/s
ascon128_aead_decrypt/64/32           339 ns          339 ns      2056330   1.58359k      16.4958       4.918k              3.1056       270.128M/s
ascon128_aead_decrypt/128/32          489 ns          489 ns      1427851   2.28701k      14.2938       7.016k             3.06777       311.851M/s
ascon128_aead_decrypt/256/32          799 ns          799 ns       878847   3.72825k      12.9453      11.212k             3.00731       343.778M/s
ascon128_aead_decrypt/512/32         1408 ns         1408 ns       499173   6.56265k      12.0637      19.604k             2.98721       368.551M/s
ascon128_aead_decrypt/1024/32        2655 ns         2651 ns       265104   12.3431k      11.6885      36.388k             2.94805       379.855M/s
ascon128_aead_decrypt/2048/32        5104 ns         5103 ns       136038   23.8266k      11.4551      69.956k             2.93605       388.685M/s
ascon128_aead_decrypt/4096/32        9997 ns         9996 ns        70287   46.5557k       11.278     137.092k             2.94469       393.824M/s
ascon128a_aead_encrypt/64/32          248 ns          248 ns      2788076   1.16139k      12.0978       3.973k              3.4209       368.698M/s
ascon128a_aead_encrypt/128/32         345 ns          345 ns      2030790    1.6113k      10.0706       5.557k             3.44877       441.692M/s
ascon128a_aead_encrypt/256/32         542 ns          542 ns      1293288      2.53k      8.78473       8.725k             3.44861       507.013M/s
ascon128a_aead_encrypt/512/32         928 ns          928 ns       755520   4.33203k      7.96329      15.061k             3.47666       559.275M/s
ascon128a_aead_encrypt/1024/32       1698 ns         1698 ns       412989   7.93491k      7.51412      27.733k             3.49506       592.982M/s
ascon128a_aead_encrypt/2048/32       3239 ns         3239 ns       214732   15.1426k      7.28008      53.077k             3.50515       612.516M/s
ascon128a_aead_encrypt/4096/32       6326 ns         6325 ns       109787   29.5779k      7.16519     103.765k             3.50819       622.389M/s
ascon128a_aead_decrypt/64/32          261 ns          261 ns      2685111   1.21835k      12.6912       4.206k             3.45221       350.754M/s
ascon128a_aead_decrypt/128/32         356 ns          356 ns      1970177    1.6613k      10.3831       5.824k             3.50569       428.089M/s
ascon128a_aead_decrypt/256/32         548 ns          548 ns      1281800   2.55972k      8.88792        9.06k             3.53945       500.983M/s
ascon128a_aead_decrypt/512/32         930 ns          930 ns       751833   4.34359k      7.98454      15.532k             3.57584       557.614M/s
ascon128a_aead_decrypt/1024/32       1690 ns         1690 ns       408059   7.90347k      7.48435      28.476k             3.60297       596.073M/s
ascon128a_aead_decrypt/2048/32       3231 ns         3231 ns       217195   15.0761k      7.24814      54.364k             3.60597       613.906M/s
ascon128a_aead_decrypt/4096/32       6279 ns         6278 ns       111764   29.3399k      7.10754      106.14k              3.6176       627.069M/s
ascon80pq_aead_encrypt/64/32          336 ns          336 ns      2087283   1.56873k       16.341       4.762k             3.03557       272.287M/s
ascon80pq_aead_encrypt/128/32         490 ns          490 ns      1432389   2.28824k      14.3015       6.874k             3.00406       311.208M/s
ascon80pq_aead_encrypt/256/32         801 ns          801 ns       874705   3.73183k      12.9578      11.098k             2.97387        343.08M/s
ascon80pq_aead_encrypt/512/32        1416 ns         1416 ns       494198   6.61593k      12.1616      19.546k             2.95439        366.33M/s
ascon80pq_aead_encrypt/1024/32       2655 ns         2655 ns       263978   12.3812k      11.7246      36.442k             2.94333       379.353M/s
ascon80pq_aead_encrypt/2048/32       5138 ns         5138 ns       136854   23.9306k      11.5051      70.234k             2.93491       386.086M/s
ascon80pq_aead_encrypt/4096/32      10056 ns        10055 ns        68577   47.0301k       11.393     137.818k             2.93042       391.538M/s
ascon80pq_aead_decrypt/64/32          340 ns          340 ns      2062984   1.58351k      16.4949       4.966k             3.13608       269.631M/s
ascon80pq_aead_decrypt/128/32         494 ns          494 ns      1410364   2.31222k      14.4514       7.064k             3.05507       308.818M/s
ascon80pq_aead_decrypt/256/32         795 ns          795 ns       877799   3.71848k      12.9114       11.26k             3.02812       345.534M/s
ascon80pq_aead_decrypt/512/32        1415 ns         1415 ns       496453   6.59731k      12.1274      19.652k             2.97879       366.646M/s
ascon80pq_aead_decrypt/1024/32       2614 ns         2614 ns       266074   12.2255k      11.5772      36.436k             2.98033       385.315M/s
ascon80pq_aead_decrypt/2048/32       5095 ns         5095 ns       137797   23.7403k      11.4136      70.004k             2.94874       389.334M/s
ascon80pq_aead_decrypt/4096/32       9995 ns         9994 ns        70154   46.7366k      11.3219      137.14k             2.93432       393.906M/s
ascon_hash/64                         477 ns          477 ns      1466982   2.22683k      23.1961       7.099k             3.18794       191.824M/s
ascon_hash/128                        759 ns          759 ns       920462   3.53929k      22.1206      11.379k             3.21505       201.114M/s
ascon_hash/256                       1324 ns         1324 ns       528793   6.17414k       21.438      19.939k             3.22944       207.467M/s
ascon_hash/512                       2451 ns         2450 ns       286770   11.4237k      20.9995      37.059k             3.24404       211.713M/s
ascon_hash/1024                      4700 ns         4700 ns       149161   21.9303k      20.7673      71.299k             3.25116       214.266M/s
ascon_hash/2048                      9260 ns         9259 ns        76100   42.9522k      20.6501     139.779k             3.25429       214.238M/s
ascon_hash/4096                     18361 ns        18359 ns        38405   84.9936k      20.5895     276.739k               3.256       214.431M/s
ascon_hasha/64                        343 ns          343 ns      2035744   1.59948k      16.6612       5.019k              3.1379       267.154M/s
ascon_hasha/128                       540 ns          540 ns      1300165   2.51798k      15.7374       7.899k             3.13704       282.741M/s
ascon_hasha/256                       930 ns          930 ns       754292   4.34982k      15.1035      13.659k             3.14013       295.249M/s
ascon_hasha/512                      1718 ns         1718 ns       408278   8.01645k      14.7361      25.179k             3.14092       301.943M/s
ascon_hasha/1024                     3285 ns         3285 ns       213711   15.3411k      14.5276      48.219k             3.14312       306.568M/s
ascon_hasha/2048                     6426 ns         6425 ns       109228   29.9758k      14.4114      94.299k             3.14584        308.72M/s
ascon_hasha/4096                    12699 ns        12698 ns        55327   59.2744k      14.3591     186.459k             3.14569       310.037M/s
ascon_xof/64/32                       479 ns          479 ns      1465132   2.23575k       23.289       7.105k             3.17791       191.146M/s
ascon_xof/128/32                      766 ns          766 ns       910750   3.57323k      22.3327      11.361k             3.17947       199.215M/s
ascon_xof/256/32                     1341 ns         1341 ns       523133   6.26062k      21.7383      19.873k             3.17429        204.84M/s
ascon_xof/512/32                     2485 ns         2484 ns       280096   11.6122k       21.346      36.897k             3.17742       208.819M/s
ascon_xof/1024/32                    4775 ns         4775 ns       145664   22.3199k      21.1362      70.945k             3.17856       210.909M/s
ascon_xof/2048/32                    9396 ns         9395 ns        74478   43.7807k      21.0484     139.041k             3.17585       211.138M/s
ascon_xof/4096/32                   18581 ns        18579 ns        37762    86.676k      20.9971     275.233k             3.17542       211.894M/s
ascon_xof/64/64                       636 ns          636 ns      1101014   2.96552k      23.1681       9.345k             3.15122       192.034M/s
ascon_xof/128/64                      921 ns          921 ns       747247   4.30414k      22.4174      13.601k             3.15998       198.821M/s
ascon_xof/256/64                     1497 ns         1497 ns       468946   6.98602k      21.8313      22.113k             3.16532       203.918M/s
ascon_xof/512/64                     2644 ns         2644 ns       263277   12.2898k      21.3364     38.9635k             3.17041       207.777M/s
ascon_xof/1024/64                    4941 ns         4940 ns       141592    23.063k      21.1976      73.185k             3.17327       210.035M/s
ascon_xof/2048/64                    9548 ns         9547 ns        73626   44.5199k      21.0795     141.281k             3.17344       210.968M/s
ascon_xof/4096/64                   18693 ns        18691 ns        37156   87.3863k      21.0063     277.473k             3.17525       212.253M/s
ascon_xofa/64/32                      339 ns          339 ns      2074048   1.57871k      16.4449       5.058k             3.20389       269.864M/s
ascon_xofa/128/32                     532 ns          532 ns      1322055   2.47966k      15.4979       7.938k             3.20125       286.966M/s
ascon_xofa/256/32                     920 ns          919 ns       761865   4.29111k      14.8997      13.698k             3.19218        298.71M/s
ascon_xofa/512/32                    1699 ns         1698 ns       414409   7.90326k       14.528      25.218k             3.19084       305.469M/s
ascon_xofa/1024/32                   3235 ns         3234 ns       215134   15.1193k      14.3176      48.258k              3.1918       311.377M/s
ascon_xofa/2048/32                   6334 ns         6334 ns       110232   29.6044k      14.2329      94.338k             3.18662        313.18M/s
ascon_xofa/4096/32                  12545 ns        12544 ns        55906   58.5954k      14.1946     186.498k             3.18281       313.843M/s
ascon_xofa/64/64                      448 ns          448 ns      1564940   2.08839k      16.3155       6.626k             3.17278       272.262M/s
ascon_xofa/128/64                     641 ns          641 ns      1097364   2.98952k      15.5704       9.506k             3.17977       285.788M/s
ascon_xofa/256/64                    1029 ns         1029 ns       679161    4.8041k      15.0128      15.266k              3.1777        296.66M/s
ascon_xofa/512/64                    1801 ns         1801 ns       388396   8.41307k       14.606      26.786k             3.18385       305.052M/s
ascon_xofa/1024/64                   3348 ns         3347 ns       208196   15.6431k      14.3778      49.826k             3.18518       309.968M/s
ascon_xofa/2048/64                   6548 ns         6547 ns       100986   30.5249k      14.4531      95.906k              3.1419        307.65M/s
ascon_xofa/4096/64                  12673 ns        12672 ns        55238     59.13k      14.2139     188.066k             3.18055       313.082M/s
ascon_prf/64/16                       188 ns          188 ns      3718330    880.269      11.0034       2.822k             3.20584       404.826M/s
ascon_prf/128/16                      261 ns          261 ns      2691582   1.21729k      8.45341       3.918k             3.21862       526.293M/s
ascon_prf/256/16                      406 ns          406 ns      1729774   1.89441k      6.96473        6.11k             3.22529       638.781M/s
ascon_prf/512/16                      696 ns          696 ns      1008529   3.24902k      6.15344      10.494k              3.2299       723.433M/s
ascon_prf/1024/16                    1281 ns         1281 ns       547641   5.98409k      5.75394      19.262k             3.21887        774.03M/s
ascon_prf/2048/16                    2449 ns         2449 ns       286372   11.4171k      5.53152      36.798k             3.22307       803.868M/s
ascon_prf/4096/16                    4779 ns         4778 ns       146811   22.2664k      5.41497       71.87k             3.22774       820.665M/s
ascon_prf/64/32                       227 ns          227 ns      3088520    1061.49      11.0571       3.381k             3.18516       402.639M/s
ascon_prf/128/32                      299 ns          299 ns      2327302   1.39912k      8.74448       4.477k             3.19988       509.666M/s
ascon_prf/256/32                      444 ns          444 ns      1567138   2.07608k       7.2086       6.669k             3.21231        618.31M/s
ascon_prf/512/32                      735 ns          734 ns       946673   3.43256k      6.30985      11.053k             3.22004       706.356M/s
ascon_prf/1024/32                    1324 ns         1324 ns       531006   6.16967k      5.84249      19.821k             3.21265       760.798M/s
ascon_prf/2048/32                    2485 ns         2485 ns       280744   11.6084k      5.58097      37.357k              3.2181         798.4M/s
ascon_prf/4096/32                    4821 ns         4820 ns       145157   22.4659k      5.44233      72.429k             3.22395       816.734M/s
ascon_prf/64/64                       305 ns          305 ns      2285544   1.42247k      11.1131       4.499k              3.1628        400.82M/s
ascon_prf/128/64                      377 ns          377 ns      1847234   1.76053k      9.16943       5.595k             3.17802       485.899M/s
ascon_prf/256/64                      523 ns          523 ns      1342579   2.44042k       7.6263       7.787k             3.19085        583.24M/s
ascon_prf/512/64                      815 ns          815 ns       860208   3.79393k      6.58668      12.171k             3.20802       674.172M/s
ascon_prf/1024/64                    1399 ns         1399 ns       501433   6.52713k       5.9992      20.939k             3.20799       741.659M/s
ascon_prf/2048/64                    2565 ns         2565 ns       273512   11.9629k      5.66426      38.475k             3.21619       785.296M/s
ascon_prf/4096/64                    4891 ns         4890 ns       142812   22.8449k      5.49156      73.547k             3.21941       811.226M/s
ascon_mac_authenticate/64             191 ns          191 ns      3669734    891.396      11.1424       2.784k             3.12319       398.924M/s
ascon_mac_authenticate/128            264 ns          264 ns      2657102   1.23009k       8.5423        3.88k             3.15424       519.697M/s
ascon_mac_authenticate/256            409 ns          409 ns      1706807   1.90807k      7.01498       6.072k             3.18227        633.99M/s
ascon_mac_authenticate/512            699 ns          699 ns      1003214    3.2593k      6.17291      10.456k             3.20805       720.527M/s
ascon_mac_authenticate/1024          1275 ns         1274 ns       549446   5.94138k      5.71286      19.224k             3.23561       778.215M/s
ascon_mac_authenticate/2048          2430 ns         2430 ns       288853   11.3313k      5.48996       36.76k             3.24412       809.943M/s
ascon_mac_authenticate/4096          4760 ns         4759 ns       147637   22.1593k      5.38894      71.832k             3.24161       823.987M/s
ascon_mac_verify/64                   196 ns          196 ns      3537675    914.371       9.5247       2.931k             3.20548       468.183M/s
ascon_mac_verify/128                  269 ns          269 ns      2607687   1.25334k      7.83336       4.027k             3.21302       568.204M/s
ascon_mac_verify/256                  415 ns          415 ns      1693760   1.93558k      6.72075       6.219k               3.213       662.306M/s
ascon_mac_verify/512                  708 ns          708 ns       991215   3.29709k      6.06083      10.603k             3.21586       732.847M/s
ascon_mac_verify/1024                1289 ns         1289 ns       537867   6.01269k      5.69383      19.371k             3.22169       781.559M/s
ascon_mac_verify/2048                2457 ns         2457 ns       285412   11.4596k      5.50944      36.907k             3.22061       807.499M/s
ascon_mac_verify/4096                4795 ns         4794 ns       146771   22.3299k      5.40937      71.979k             3.22344       821.157M/s
ascon_prfs_authenticate/1            46.1 ns         46.1 ns     15216649    214.812       12.636          601             2.79779       351.793M/s
ascon_prfs_authenticate/2            46.5 ns         46.5 ns     15000672    217.195      12.0664          603              2.7763        369.51M/s
ascon_prfs_authenticate/4            46.2 ns         46.2 ns     15108560    215.898      10.7949          600             2.77909       412.681M/s
ascon_prfs_authenticate/8            36.5 ns         36.5 ns     19065986    169.252      7.05217          598             3.53319       627.625M/s
ascon_prfs_authenticate/16           36.7 ns         36.7 ns     19173931    169.118      5.28495          599              3.5419         832.2M/s
ascon_prfs_verify/1                  50.3 ns         50.2 ns     10000000    234.365      13.7862          754             3.21721       322.654M/s
ascon_prfs_verify/2                  50.1 ns         50.1 ns     13969327    234.228      13.0127          756             3.22762       342.711M/s
ascon_prfs_verify/4                  49.8 ns         49.8 ns     14047526    232.328      11.6164          753              3.2411       383.314M/s
ascon_prfs_verify/8                  45.5 ns         45.5 ns     15615859    208.597      8.69156          751             3.60024       502.646M/s
ascon_prfs_verify/16                 45.4 ns         45.4 ns     15599778    206.821      6.46315          752               3.636       672.632M/s
```

## Usage

`ascon` is a zero-dependency, header-only C++ library, which is pretty easy to get started with.

- Include proper header file(s) ( living in `include` directory ) in your header/ source file.
- Use functions/ constants living under proper namespace of interest.
- When compiling, let your compiler know where it can find header files i.e. inside `include` and `subtle/include`, by using `-I` flag.

Scheme | Header to include | Namespace of interest | Example
:-: | :-- | :-- | :-:
Ascon-128 AEAD | `include/aead/ascon128.hpp` | `ascon128_aead::` | [example/ascon128_aead.cpp](./example/ascon128_aead.cpp)
Ascon-128a AEAD | `include/aead/ascon128a.hpp` | `ascon128a_aead::`  | [example/ascon128a_aead.cpp](./example/ascon128a_aead.cpp)
Ascon-80pq AEAD | `include/aead/ascon80pq.hpp` | `ascon80pq_aead::`  | [example/ascon80pq_aead.cpp](./example/ascon80pq_aead.cpp)
Ascon Hash | `include/hashing/ascon_hash.hpp` | `ascon_hash::` | [example/ascon_hash.cpp](./example/ascon_hash.cpp)
Ascon HashA | `include/hashing/ascon_hasha.hpp` | `ascon_hasha::` | [example/ascon_hasha.cpp](./example/ascon_hasha.cpp)
Ascon Xof | `include/hashing/ascon_xof.hpp` | `ascon_xof::` | [example/ascon_xof.cpp](./example/ascon_xof.cpp)
Ascon XofA | `include/hashing/ascon_xofa.hpp` | `ascon_xofa::` | [example/ascon_xofa.cpp](./example/ascon_xofa.cpp)
Ascon-PRF | `include/auth/ascon_prf.hpp` | `ascon_prf::` | [example/ascon_prf.cpp](./example/ascon_prf.cpp)
Ascon-MAC | `include/auth/ascon_mac.hpp` | `ascon_mac::` | [example/ascon_mac.cpp](./example/ascon_mac.cpp)
Ascon-MAC | `include/auth/ascon_prfs.hpp` | `ascon_prfs::` | [example/ascon_prfs.cpp](./example/ascon_prfs.cpp)

> **Note** Don't forget to also include path ( `-I ./subtle/include` ) to dependency library `subtle`, when compiling translation units, using this library.

I maintain some examples demonstrating usage of Ascon AEAD, Hash, Xof, PRF and MAC API.

```bash
# Assuming you've already cloned this ascon library and enabled git submodule.
$ ASCON_HEADERS=./include
$ SUBTLE_HEADERS=./subtle/include

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon128_aead.cpp && ./a.out
Ascon-128 AEAD

Key       :	06a819d82123676245b7b88e864b01ac
Nonce     :	aaf550e27747555336e6e1efe29618dc
Data      :	a738688dfb1d2fcfab22502e11fe2559ffca02a26c60780103c88d25c611fa83
Text      :	22bbe3e728cc9355298c614a503471b69c27a193db9331e41ba42791b63d12e8b53547daa720aa8ecef3262edd52bfd871f5425f2fc3e1c7cbc0b20a69ccc1d4
Encrypted :	f5a716b9f709329a75deceeb0a72e4dbed86b89679beb99d26e1e47ff8f26f984785ac3f80677570240efb10e0bf5e93bde8c2662599052fa67026783fe2a061
Decrypted :	22bbe3e728cc9355298c614a503471b69c27a193db9331e41ba42791b63d12e8b53547daa720aa8ecef3262edd52bfd871f5425f2fc3e1c7cbc0b20a69ccc1d4

# ----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon128a_aead.cpp && ./a.out
Ascon-128a AEAD

Key       :	88119fff6f0673cfc8d0269bac8ca328
Nonce     :	0c4b7bda5d47fda1b24b06b7292dd125
Data      :	49abcffb323076de7b068b5cba32344064a9462833a32ce2f8296947d16fb708
Text      :	2b2e331614af85f38500a3fbe182ec4c00bd0b5a200b852f582a63249363892043c040f0950dec14038cb82a91fd057a0edb81b691fe726be9a1fa3848b38e3d
Encrypted :	d71d984670a27cb8eb033d0c10be866966315d7ad60b048fc7f5f9a90fc02534f7c807baf6f32255bd94d7872a12e47dd3bf99439da8634d996ffe1e8cf08dcf
Decrypted :	2b2e331614af85f38500a3fbe182ec4c00bd0b5a200b852f582a63249363892043c040f0950dec14038cb82a91fd057a0edb81b691fe726be9a1fa3848b38e3d

# -----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon80pq_aead.cpp && ./a.out
Ascon-80pq AEAD

Key       :	93afc9866d8fafb4d4895a97147da2639e652407
Nonce     :	6962c11757edcfd96ac6e3312bb22615
Data      :	8c132efaa2b27795f0da45846af44f44a8fa2d98df99e301639baa0f59c57035
Text      :	6d27382a7c6184fe52ea354574bfc8da49cbd7cb830183820d3e47368489428d89c4954a42ffb4f602b0cd1a9c678a25b8cc93d8b4ec39b56ea1b8157fc44864
Encrypted :	00fe776e96d074e556f84a47bc826f7be113436bda07198b3237f1f7d261ae60847609341d7c5b0c317244d9c0e3cb662e29440a43fc614d3a2a6ca488426225
Decrypted :	6d27382a7c6184fe52ea354574bfc8da49cbd7cb830183820d3e47368489428d89c4954a42ffb4f602b0cd1a9c678a25b8cc93d8b4ec39b56ea1b8157fc44864

# -----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon_hash.cpp && ./a.out
Ascon Hash

Message :	a2309f40cae3efc99941641caf1c2cddf6fcd52a031ff199dfe5f185bb5142e91539b0d6777ad7fe8c2300d42015b623517f31b5db0a94d7e3c8cb521f03aabb
Digest  :	b467a2107aa34754a8679dfbac795660a5a2be927f2b0216a8fad50202d17249

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon_hasha.cpp && ./a.out
Ascon HashA

Message :	b11a401ec0ad387fdc890962e86158432ba31e50b8810e3360b4c6143a73f6f82364f6bd895938b7f0babdab065c17c7e0e7196c4a15eb345eb174f4f1da2de5
Digest  :	aa7463f3284c6b5d84aaf0c56a18ae79a2fbaf0e095111a0e65824e24892e419

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon_xof.cpp && ./a.out
Ascon XOF

Message :	5265ce4d5d0b3a0d89c757e4b14049a4da449be528e9bb7606363717c16bf1f751ff64c4214aebe385ed4629b7eb14ff1a3f0ca6754ce6e54210efd33d117d41
Digest  :	65e2631e1478b8cec2fcbc8efbd954aefc4b20649d48818f06e95d355e4bda2b4d830ff05cd88f92a0d312c08e9c9959dcc8bb0e68c9ac0c0164becda6cd5acc

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon_xofa.cpp && ./a.out
Ascon XOFA

Message :	6970b5465e902633d16179a2c6f68cb8ad52e853bda99cf72b9bb33bbb23d0df6b22b67e7e4dbe53e04abaa63d69ee84b0e8e87a3cdd94c9da105622ffa50755
Digest  :	52644d6ba60bd3eca3aa2dabfe69ae397ddcdd0f0abd5151bf1d0e23cb4da41b3ab75634e26bae4b19f78e95fbdd54961b35cb5c7ef3ec7639816f0833ffaea7

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon_prf.cpp && ./a.out
Ascon-PRF

Key     :	518d6223f8895a8ad637e6c3fce66084
Message :	6a3fedca32ad7587663de617074eddbe64c084c658dbbb419dca2b4db5200af252a316cdcd042fdc31f11ba84a9925484d5f978e43172f3cf627a3b19e5f12f6
Tag     :	46e7936bf2468ead291854196bbaf4e00fc676a06fe33bd6326f31ac968e4aff73e8c3eb6cbc09884c226daceda36a26f0f601a93268ebcc384cc1d24baa6d5d

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon_mac.cpp && ./a.out
Ascon-MAC

Key          :	53dffb5673f089f77f363fadcee2c69f
Message      :	13da8497fe16a3e4a61a937530f30ca072f470ec2a68449336264b272af354796037b8312479233f9d189bcc6e2a178b1dd5f91fc0094b59811541ac45b33b0a
Sender Tag   :	7fb21a028858927b54e148c6b25e68e2
Receiver Tag :	7fb21a028858927b54e148c6b25e68e2

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon_prfs.cpp && ./a.out
Ascon-PRFShort

Key     :	f4c9dc526a8b03c3467abdc890575afc
Message :	f6ea9d6f4322de5c
Tag     :	3947e5220bf37c8ca807f2a1330134ad
```
