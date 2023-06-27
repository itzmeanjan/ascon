> **Warning** **This implementation attempts to provide you with constant-timeness though it is not yet audited. If you consider using it in production, be careful !**

# ascon
Accelerated Ascon Cipher Suite: Light Weight Cryptography

## Overview

`ascon` cipher suite is selected by NIST as winner of **L**ight **W**eight **C**ryptography standardization effort and it's being standardized right now. Find more details @ https://www.nist.gov/news-events/news/2023/02/nist-selects-lightweight-cryptography-algorithms-protect-small-devices.

Following functionalities, from Ascon light weight cryptography suite, are implemented in this zero-dependency, header-only C++ library

Scheme | Input | Output
:-- | :-: | --:
Ascon-128 AEAD | 16B key, 16B nonce, N -bytes associated data and M -bytes plain text | 16B authentication tag and M -bytes cipher text
Ascon-128A AEAD | 16B key, 16B nonce, N -bytes associated data and M -bytes plain text | 16B authentication tag and M -bytes cipher text
Ascon-80pq AEAD | 20B key, 16B nonce, N -bytes associated data and M -bytes plain text | 16B authentication tag and M -bytes cipher text
Ascon-Hash | N -bytes message | 32B digest
Ascon-HashA | N -bytes message | 32B digest
Ascon-XOF | N -bytes message | Arbitrary many bytes digest
Ascon-XOFA | N -bytes message | Arbitrary many bytes digest

> **Note** Ascon-{Hash, HashA, XOF, XOFA} supports incremental hashing. If all message bytes are not ready to be absorbed into hash state in a single go, one can absorb message using incremental hashing API s.t. arbitrary number of absorption calls can be made, each time arbitrary many bytes are consumed, until state is finalized and ready to be squeezed.

> **Note** Read more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption).

> **Warning** Associated data is never encrypted. AEAD scheme provides secrecy only for plain text but authenticity and integrity for both associated data and cipher text.

> **Note** I've followed Ascon [specification](https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf) while working on this implementation. I suggest you also go through the specification to better understand Ascon.

## Prerequisites

- Make sure you've a C++ compiler `g++`/ `clang++` installed, along with C++20 standard library.

```bash
$ g++ --version
g++ (Ubuntu 12.2.0-17ubuntu1) 12.2.0

$ clang++ --version
Ubuntu clang version 15.0.7
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
# assuming you're already cloned `ascon`
git submodule update --init
```

- For benchmarking this library implementation, you need to have `google-benchmark` header and library installed --- ensure it's globally installed; follow [this](https://github.com/google/benchmark/#installation). If you are on linux kernel and you want to obtain CPU cycle counts/ instruction counts for Ascon based constructions, you should consider building google-benchmark library with libPFM support, following [these](https://github.com/google/benchmark/blob/main/docs/perf_counters.md) instructions. Find more about libPFM @ https://perfmon2.sourceforge.net.

## Testing

For ensuring that Ascon cipher suite is implemented correctly and it's conformant with the specification

- Ensure functional correctness of Ascon AEAD, Hash and Xof routines for various combination of inputs.
- Assess whether this implementation of Ascon cipher suite is conformant with specification, using **K**nown **A**nswer **T**ests, which can be found in the reference implementation repository i.e. https://github.com/ascon/ascon-c.git.

```bash
$ make

[test] Ascon permutation `p_a`
[test] Ascon-128 AEAD
[test] Ascon-128a AEAD
[test] Ascon-80pq AEAD
[test] Ascon-Hash
[test] Ascon-HashA
[test] Ascon-Xof
[test] Ascon-XofA
```

## Benchmarking

For benchmarking routines of Ascon lightweight cipher suite, using `google-benchmark` library, while targeting CPU systems, with variable length input data, one may issue

```bash
make benchmark # If you haven't built google-benchmark library with libPFM support.
make perf # If you have built google-benchmark library with libPFM support.
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

> **Note** Benchmark recipe expects presence of `google-benchmark` header and library in `$PATH` ( so that it can be found by the compiler ).

> **Warning** Ensure that you've disabled CPU frequency scaling, when benchmarking routines, following [this](https://github.com/google/benchmark/blob/main/docs/reducing_variance.md) guide.

> **Note** `make perf` - was issued when collecting following benchmarks. Notice, CPU cycle count column. Read https://github.com/google/benchmark/blob/main/docs/perf_counters.md in case you're interested in getting performance measurements, other than just CPU cycles.

### On 12th Gen Intel(R) Core(TM) i7-1260P ( Compiled with GCC )

```bash
2023-06-27T16:17:01+04:00
Running ./benchmarks/perf.out
Run on (16 X 4648.05 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.34, 0.35, 0.36
***WARNING*** There are 88 benchmarks with threads and 1 performance counters were requested. Beware counters will reflect the combined usage across all threads.
------------------------------------------------------------------------------------------------------------------
Benchmark                                            Time             CPU   Iterations     CYCLES bytes_per_second
------------------------------------------------------------------------------------------------------------------
bench_ascon::ascon_permutation<1>                 3.25 ns         3.25 ns    217356442    15.1337       11.4799G/s
bench_ascon::ascon_permutation<6>                 18.2 ns         18.2 ns     38622719    84.8518       2.04789G/s
bench_ascon::ascon_permutation<8>                 23.8 ns         23.8 ns     29360473    111.448       1.56461G/s
bench_ascon::ascon_permutation<12>                35.7 ns         35.7 ns     19606043    166.942        1069.9M/s
bench_ascon::ascon128_aead_encrypt/64/32           316 ns          316 ns      2216228   1.47837k       289.731M/s
bench_ascon::ascon128_aead_encrypt/128/32          467 ns          467 ns      1497210   2.18697k       326.586M/s
bench_ascon::ascon128_aead_encrypt/256/32          770 ns          770 ns       907871   3.60448k       356.624M/s
bench_ascon::ascon128_aead_encrypt/512/32         1376 ns         1375 ns       509110   6.43954k       377.186M/s
bench_ascon::ascon128_aead_encrypt/1024/32        2622 ns         2622 ns       270176   11.4364k       384.132M/s
bench_ascon::ascon128_aead_encrypt/2048/32        5028 ns         5027 ns       139437   23.2372k       394.591M/s
bench_ascon::ascon128_aead_encrypt/4096/32        9871 ns         9870 ns        70732   46.1388k       398.865M/s
bench_ascon::ascon128_aead_decrypt/64/32           327 ns          327 ns      2143891   1.52516k       280.314M/s
bench_ascon::ascon128_aead_decrypt/128/32          478 ns          478 ns      1462703   2.23718k       318.925M/s
bench_ascon::ascon128_aead_decrypt/256/32          785 ns          785 ns       893617   3.66321k       350.052M/s
bench_ascon::ascon128_aead_decrypt/512/32         1394 ns         1394 ns       500555   6.51334k       372.099M/s
bench_ascon::ascon128_aead_decrypt/1024/32        2626 ns         2625 ns       267329   12.2695k       383.602M/s
bench_ascon::ascon128_aead_decrypt/2048/32        5061 ns         5060 ns       138580   23.6673k       392.007M/s
bench_ascon::ascon128_aead_decrypt/4096/32        9907 ns         9906 ns        70599   46.3411k       397.417M/s
bench_ascon::ascon128a_aead_encrypt/64/32          249 ns          249 ns      2816022   1.15962k        368.38M/s
bench_ascon::ascon128a_aead_encrypt/128/32         350 ns          350 ns      2001756   1.63464k       435.983M/s
bench_ascon::ascon128a_aead_encrypt/256/32         552 ns          552 ns      1260330   2.58244k       497.347M/s
bench_ascon::ascon128a_aead_encrypt/512/32         962 ns          962 ns       729810   4.49818k       539.223M/s
bench_ascon::ascon128a_aead_encrypt/1024/32       1766 ns         1766 ns       394211    8.2499k       570.377M/s
bench_ascon::ascon128a_aead_encrypt/2048/32       3386 ns         3385 ns       207578   15.7872k       585.925M/s
bench_ascon::ascon128a_aead_encrypt/4096/32       6608 ns         6608 ns       105215   30.7853k       595.779M/s
bench_ascon::ascon128a_aead_decrypt/64/32          254 ns          254 ns      2750936   1.18346k       360.612M/s
bench_ascon::ascon128a_aead_decrypt/128/32         349 ns          349 ns      1997819   1.63242k       436.732M/s
bench_ascon::ascon128a_aead_decrypt/256/32         544 ns          544 ns      1287449   2.54025k       505.333M/s
bench_ascon::ascon128a_aead_decrypt/512/32         939 ns          939 ns       740201   4.38589k       552.448M/s
bench_ascon::ascon128a_aead_decrypt/1024/32       1728 ns         1728 ns       405333   8.07267k       582.837M/s
bench_ascon::ascon128a_aead_decrypt/2048/32       3317 ns         3316 ns       210326   15.5169k       598.126M/s
bench_ascon::ascon128a_aead_decrypt/4096/32       6523 ns         6523 ns       107829   30.4962k       603.538M/s
bench_ascon::ascon80pq_aead_encrypt/64/32          317 ns          317 ns      2202744    1.4831k        288.51M/s
bench_ascon::ascon80pq_aead_encrypt/128/32         468 ns          468 ns      1491297   2.18743k       326.193M/s
bench_ascon::ascon80pq_aead_encrypt/256/32         770 ns          770 ns       907756   3.59979k       356.843M/s
bench_ascon::ascon80pq_aead_encrypt/512/32        1372 ns         1372 ns       510000   6.41734k       378.251M/s
bench_ascon::ascon80pq_aead_encrypt/1024/32       2580 ns         2579 ns       271447   12.0745k       390.442M/s
bench_ascon::ascon80pq_aead_encrypt/2048/32       4991 ns         4991 ns       140308    23.358k       397.455M/s
bench_ascon::ascon80pq_aead_encrypt/4096/32       9809 ns         9808 ns        71488   45.9049k        401.38M/s
bench_ascon::ascon80pq_aead_decrypt/64/32          326 ns          326 ns      2143625   1.52571k       280.741M/s
bench_ascon::ascon80pq_aead_decrypt/128/32         479 ns          479 ns      1463141    2.2298k       318.788M/s
bench_ascon::ascon80pq_aead_decrypt/256/32         778 ns          778 ns       895228   3.63869k       353.021M/s
bench_ascon::ascon80pq_aead_decrypt/512/32        1381 ns         1380 ns       506888   6.45679k       375.826M/s
bench_ascon::ascon80pq_aead_decrypt/1024/32       2592 ns         2592 ns       270000   12.1019k       388.567M/s
bench_ascon::ascon80pq_aead_decrypt/2048/32       4998 ns         4998 ns       139790   23.3821k       396.879M/s
bench_ascon::ascon80pq_aead_decrypt/4096/32       9835 ns         9835 ns        71173   45.9562k       400.297M/s
bench_ascon::ascon_hash/64                         463 ns          463 ns      1513581   2.16595k        197.66M/s
bench_ascon::ascon_hash/128                        748 ns          747 ns       928940   3.49506k       204.135M/s
bench_ascon::ascon_hash/256                       1317 ns         1317 ns       529511   6.15863k         208.5M/s
bench_ascon::ascon_hash/512                       2454 ns         2454 ns       284860   11.4752k       211.441M/s
bench_ascon::ascon_hash/1024                      4734 ns         4733 ns       147775   22.1252k       212.769M/s
bench_ascon::ascon_hash/2048                      9280 ns         9280 ns        75276   43.4266k       213.765M/s
bench_ascon::ascon_hash/4096                     18394 ns        18393 ns        38062   85.9787k        214.04M/s
bench_ascon::ascon_hasha/64                        323 ns          323 ns      2164981    1.5067k       283.386M/s
bench_ascon::ascon_hasha/128                       513 ns          513 ns      1356028   2.39712k       297.392M/s
bench_ascon::ascon_hasha/256                       894 ns          894 ns       777701   4.17931k       307.174M/s
bench_ascon::ascon_hasha/512                      1655 ns         1655 ns       423023   7.73548k       313.546M/s
bench_ascon::ascon_hasha/1024                     3176 ns         3175 ns       219918   14.8487k       317.148M/s
bench_ascon::ascon_hasha/2048                     6222 ns         6222 ns       111964   29.0831k       318.815M/s
bench_ascon::ascon_hasha/4096                    12324 ns        12323 ns        56776   57.5715k       319.466M/s
bench_ascon::ascon_xof/64/32                       464 ns          464 ns      1512371   2.16436k       197.482M/s
bench_ascon::ascon_xof/128/32                      747 ns          747 ns       934031   3.49332k       204.194M/s
bench_ascon::ascon_xof/256/32                     1316 ns         1316 ns       531989   6.15727k       208.725M/s
bench_ascon::ascon_xof/512/32                     2456 ns         2455 ns       285576   11.4767k       211.282M/s
bench_ascon::ascon_xof/1024/32                    4729 ns         4729 ns       148193   22.1177k       212.962M/s
bench_ascon::ascon_xof/2048/32                    9287 ns         9287 ns        75429    43.415k       213.599M/s
bench_ascon::ascon_xof/4096/32                   18391 ns        18390 ns        38021   85.9706k       214.073M/s
bench_ascon::ascon_xof/64/64                       610 ns          610 ns      1145247   2.84639k       200.232M/s
bench_ascon::ascon_xof/128/64                      896 ns          896 ns       780647   4.17842k       204.358M/s
bench_ascon::ascon_xof/256/64                     1464 ns         1464 ns       478384   6.83459k       208.422M/s
bench_ascon::ascon_xof/512/64                     2604 ns         2604 ns       268887   12.1533k       210.966M/s
bench_ascon::ascon_xof/1024/64                    4878 ns         4878 ns       143495   22.7865k       212.703M/s
bench_ascon::ascon_xof/2048/64                    9451 ns         9450 ns        74338   44.1069k       213.142M/s
bench_ascon::ascon_xof/4096/64                   18540 ns        18538 ns        37769   86.6548k       214.004M/s
bench_ascon::ascon_xofa/64/32                      324 ns          324 ns      2161685   1.51414k       282.632M/s
bench_ascon::ascon_xofa/128/32                     517 ns          517 ns      1348132   2.41373k       295.253M/s
bench_ascon::ascon_xofa/256/32                     904 ns          904 ns       772967   4.22035k       303.962M/s
bench_ascon::ascon_xofa/512/32                    1674 ns         1674 ns       417165   7.81669k       309.909M/s
bench_ascon::ascon_xofa/1024/32                   3212 ns         3212 ns       217864   15.0145k       313.516M/s
bench_ascon::ascon_xofa/2048/32                   6299 ns         6299 ns       110189   29.4071k       314.931M/s
bench_ascon::ascon_xofa/4096/32                  12459 ns        12459 ns        55942   58.2211k        315.99M/s
bench_ascon::ascon_xofa/64/64                      423 ns          423 ns      1657885    1.9709k       288.774M/s
bench_ascon::ascon_xofa/128/64                     615 ns          615 ns      1136182   2.87321k       297.628M/s
bench_ascon::ascon_xofa/256/64                     999 ns          999 ns       700624    4.6703k       305.499M/s
bench_ascon::ascon_xofa/512/64                    1770 ns         1770 ns       394741   8.27081k        310.29M/s
bench_ascon::ascon_xofa/1024/64                   3311 ns         3311 ns       211374   15.4632k       313.419M/s
bench_ascon::ascon_xofa/2048/64                   6395 ns         6395 ns       109290   29.8602k       314.966M/s
bench_ascon::ascon_xofa/4096/64                  12551 ns        12550 ns        55433   58.6727k       316.115M/s
```

### On 12th Gen Intel(R) Core(TM) i7-1260P ( Compiled with Clang )

```bash
2023-06-27T16:21:55+04:00
Running ./benchmarks/perf.out
Run on (16 X 2245.82 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.66, 0.47, 0.41
***WARNING*** There are 88 benchmarks with threads and 1 performance counters were requested. Beware counters will reflect the combined usage across all threads.
------------------------------------------------------------------------------------------------------------------
Benchmark                                            Time             CPU   Iterations     CYCLES bytes_per_second
------------------------------------------------------------------------------------------------------------------
bench_ascon::ascon_permutation<1>                 2.85 ns         2.85 ns    244990790    13.3366         13.06G/s
bench_ascon::ascon_permutation<6>                 16.9 ns         16.9 ns     41322872    79.1811       2.19983G/s
bench_ascon::ascon_permutation<8>                 23.0 ns         23.0 ns     30319363    107.774        1.6171G/s
bench_ascon::ascon_permutation<12>                34.6 ns         34.6 ns     20232446    161.925       1102.76M/s
bench_ascon::ascon128_aead_encrypt/64/32           306 ns          306 ns      2273587   1.43085k       299.156M/s
bench_ascon::ascon128_aead_encrypt/128/32          451 ns          451 ns      1557326   2.10728k       338.056M/s
bench_ascon::ascon128_aead_encrypt/256/32          736 ns          737 ns       949219   3.43973k       372.919M/s
bench_ascon::ascon128_aead_encrypt/512/32         1315 ns         1315 ns       532702   6.13833k       394.441M/s
bench_ascon::ascon128_aead_encrypt/1024/32        2467 ns         2468 ns       284489   11.5192k       408.129M/s
bench_ascon::ascon128_aead_encrypt/2048/32        4755 ns         4755 ns       146705   22.2155k       417.192M/s
bench_ascon::ascon128_aead_encrypt/4096/32        9359 ns         9360 ns        74575   43.6971k       420.594M/s
bench_ascon::ascon128_aead_decrypt/64/32           306 ns          306 ns      2290939   1.43069k       299.053M/s
bench_ascon::ascon128_aead_decrypt/128/32          445 ns          445 ns      1573792   2.08103k       342.859M/s
bench_ascon::ascon128_aead_decrypt/256/32          726 ns          726 ns       961374   3.38906k       378.515M/s
bench_ascon::ascon128_aead_decrypt/512/32         1286 ns         1286 ns       542109    6.0034k       403.457M/s
bench_ascon::ascon128_aead_decrypt/1024/32        2414 ns         2414 ns       290310   11.2751k       417.186M/s
bench_ascon::ascon128_aead_decrypt/2048/32        4673 ns         4672 ns       150479   21.3644k       424.553M/s
bench_ascon::ascon128_aead_decrypt/4096/32        9128 ns         9128 ns        76265   42.7151k       431.274M/s
bench_ascon::ascon128a_aead_encrypt/64/32          239 ns          239 ns      2924991   1.11981k       382.462M/s
bench_ascon::ascon128a_aead_encrypt/128/32         334 ns          334 ns      2098343   1.55955k       457.204M/s
bench_ascon::ascon128a_aead_encrypt/256/32         522 ns          522 ns      1341704    2.4399k       525.879M/s
bench_ascon::ascon128a_aead_encrypt/512/32         904 ns          904 ns       772685   4.23326k       573.604M/s
bench_ascon::ascon128a_aead_encrypt/1024/32       1657 ns         1658 ns       422477   7.75307k       607.585M/s
bench_ascon::ascon128a_aead_encrypt/2048/32       3162 ns         3162 ns       221499   14.7989k       627.243M/s
bench_ascon::ascon128a_aead_encrypt/4096/32       6171 ns         6171 ns       113406   28.8992k       637.934M/s
bench_ascon::ascon128a_aead_decrypt/64/32          245 ns          245 ns      2849100   1.14786k        372.97M/s
bench_ascon::ascon128a_aead_decrypt/128/32         339 ns          339 ns      2060097   1.58547k       450.546M/s
bench_ascon::ascon128a_aead_decrypt/256/32         527 ns          527 ns      1324100   2.46835k       520.855M/s
bench_ascon::ascon128a_aead_decrypt/512/32         909 ns          909 ns       768949   4.25393k       570.483M/s
bench_ascon::ascon128a_aead_decrypt/1024/32       1666 ns         1666 ns       419857    7.8004k       604.471M/s
bench_ascon::ascon128a_aead_decrypt/2048/32       3176 ns         3176 ns       220151    14.843k       624.575M/s
bench_ascon::ascon128a_aead_decrypt/4096/32       6199 ns         6200 ns       112900   28.9921k       634.978M/s
bench_ascon::ascon80pq_aead_encrypt/64/32          304 ns          304 ns      2290175   1.42331k       300.766M/s
bench_ascon::ascon80pq_aead_encrypt/128/32         447 ns          447 ns      1565051    2.0894k       341.254M/s
bench_ascon::ascon80pq_aead_encrypt/256/32         730 ns          730 ns       958743   3.40978k       376.289M/s
bench_ascon::ascon80pq_aead_encrypt/512/32        1301 ns         1301 ns       538401   6.07477k       398.737M/s
bench_ascon::ascon80pq_aead_encrypt/1024/32       2447 ns         2447 ns       284581   11.4423k       411.552M/s
bench_ascon::ascon80pq_aead_encrypt/2048/32       4746 ns         4747 ns       147998   22.1791k       417.903M/s
bench_ascon::ascon80pq_aead_encrypt/4096/32       9313 ns         9315 ns        76019   43.4936k       422.649M/s
bench_ascon::ascon80pq_aead_decrypt/64/32          313 ns          313 ns      2239038   1.46236k       292.327M/s
bench_ascon::ascon80pq_aead_decrypt/128/32         456 ns          456 ns      1531863   2.13294k       334.559M/s
bench_ascon::ascon80pq_aead_decrypt/256/32         743 ns          743 ns       943827   3.47591k       369.726M/s
bench_ascon::ascon80pq_aead_decrypt/512/32        1325 ns         1325 ns       536604   6.19588k       391.574M/s
bench_ascon::ascon80pq_aead_decrypt/1024/32       2483 ns         2483 ns       280529   11.6094k        405.53M/s
bench_ascon::ascon80pq_aead_decrypt/2048/32       4775 ns         4775 ns       145833   22.3327k       415.384M/s
bench_ascon::ascon80pq_aead_decrypt/4096/32       9401 ns         9402 ns        73609   43.9758k       418.729M/s
bench_ascon::ascon_hash/64                         453 ns          453 ns      1549296   2.11449k       202.294M/s
bench_ascon::ascon_hash/128                        731 ns          731 ns       955114   3.41192k       208.796M/s
bench_ascon::ascon_hash/256                       1287 ns         1287 ns       539416   6.01986k       213.353M/s
bench_ascon::ascon_hash/512                       2398 ns         2399 ns       291506   11.2141k       216.292M/s
bench_ascon::ascon_hash/1024                      4615 ns         4616 ns       151437   21.5982k       218.178M/s
bench_ascon::ascon_hash/2048                      9064 ns         9065 ns        77106   42.3839k       218.825M/s
bench_ascon::ascon_hash/4096                     17959 ns        17960 ns        38993   83.9274k       219.192M/s
bench_ascon::ascon_hasha/64                        314 ns          314 ns      2222685   1.46872k       291.624M/s
bench_ascon::ascon_hasha/128                       501 ns          501 ns      1397556   2.33726k       304.797M/s
bench_ascon::ascon_hasha/256                       875 ns          875 ns       799022   4.08336k       313.864M/s
bench_ascon::ascon_hasha/512                      1617 ns         1617 ns       433060   7.55773k       320.822M/s
bench_ascon::ascon_hasha/1024                     3103 ns         3103 ns       225149   14.5063k       324.519M/s
bench_ascon::ascon_hasha/2048                     6083 ns         6084 ns       114619   28.4058k       326.052M/s
bench_ascon::ascon_hasha/4096                    12022 ns        12023 ns        58184   56.2151k       327.425M/s
bench_ascon::ascon_xof/64/32                       452 ns          452 ns      1549037   2.11425k       202.651M/s
bench_ascon::ascon_xof/128/32                      729 ns          729 ns       958174    3.4124k       209.183M/s
bench_ascon::ascon_xof/256/32                     1286 ns         1286 ns       544263   6.01959k       213.539M/s
bench_ascon::ascon_xof/512/32                     2397 ns         2397 ns       292385   11.2107k       216.394M/s
bench_ascon::ascon_xof/1024/32                    4619 ns         4620 ns       151437   21.5977k       218.003M/s
bench_ascon::ascon_xof/2048/32                    9063 ns         9063 ns        77080   42.3984k       218.866M/s
bench_ascon::ascon_xof/4096/32                   17929 ns        17930 ns        39017    83.954k       219.558M/s
bench_ascon::ascon_xof/64/64                       592 ns          592 ns      1180453   2.77043k       206.174M/s
bench_ascon::ascon_xof/128/64                      870 ns          870 ns       799808   4.06852k       210.362M/s
bench_ascon::ascon_xof/256/64                     1429 ns         1429 ns       489868   6.67675k       213.534M/s
bench_ascon::ascon_xof/512/64                     2537 ns         2537 ns       275785   11.8677k       216.532M/s
bench_ascon::ascon_xof/1024/64                    4756 ns         4757 ns       147043   22.2548k       218.128M/s
bench_ascon::ascon_xof/2048/64                    9204 ns         9205 ns        76102   43.0578k       218.816M/s
bench_ascon::ascon_xof/4096/64                   18111 ns        18112 ns        38625   84.6073k       219.041M/s
bench_ascon::ascon_xofa/64/32                      314 ns          314 ns      2227304   1.46943k       291.515M/s
bench_ascon::ascon_xofa/128/32                     499 ns          499 ns      1402199   2.33656k       305.613M/s
bench_ascon::ascon_xofa/256/32                     874 ns          874 ns       801403   4.08964k       314.182M/s
bench_ascon::ascon_xofa/512/32                    1618 ns         1618 ns       432832   7.56198k       320.633M/s
bench_ascon::ascon_xofa/1024/32                   3105 ns         3105 ns       225490   14.5047k       324.318M/s
bench_ascon::ascon_xofa/2048/32                   6074 ns         6075 ns       114743    28.399k       326.551M/s
bench_ascon::ascon_xofa/4096/32                  12023 ns        12024 ns        58308   56.2018k       327.406M/s
bench_ascon::ascon_xofa/64/64                      409 ns          409 ns      1712690   1.91221k       298.423M/s
bench_ascon::ascon_xofa/128/64                     595 ns          595 ns      1170546    2.7805k       307.933M/s
bench_ascon::ascon_xofa/256/64                     969 ns          969 ns       721369   4.52811k       314.843M/s
bench_ascon::ascon_xofa/512/64                    1714 ns         1714 ns       408769   7.99947k       320.452M/s
bench_ascon::ascon_xofa/1024/64                   3202 ns         3202 ns       218803   14.9406k       324.055M/s
bench_ascon::ascon_xofa/2048/64                   6182 ns         6182 ns       112360   28.8298k       325.818M/s
bench_ascon::ascon_xofa/4096/64                  12131 ns        12132 ns        57698   56.6581k       327.002M/s
```

## Usage

`ascon` is a zero-dependency, header-only C++ library, which is pretty easy to get started with.

- Include proper header file(s) ( living in `include` directory ) in your header/ source file.
- Use functions/ constants living under proper namespace of interest.
- When compiling, let your compiler know where it can find header files i.e. inside `include` and `subtle/include`, by using `-I` flag.

Scheme | Header | Namespace | Example
:-- | :-: | :-: | --:
Ascon-128 AEAD | `include/aead/ascon128.hpp` | `ascon128_aead` | [example/ascon128_aead.cpp](./example/ascon128_aead.cpp)
Ascon-128a AEAD | `include/aead/ascon128a.hpp` | `ascon128a_aead`  | [example/ascon128a_aead.cpp](./example/ascon128a_aead.cpp)
Ascon-80pq AEAD | `include/aead/ascon80pq.hpp` | `ascon80pq_aead`  | [example/ascon80pq_aead.cpp](./example/ascon80pq_aead.cpp)
Ascon Hash | `include/hashing/ascon_hash.hpp` | `ascon_hash` | [example/ascon_hash.cpp](./example/ascon_hash.cpp)
Ascon HashA | `include/hashing/ascon_hasha.hpp` | `ascon_hasha` | [example/ascon_hasha.cpp](./example/ascon_hasha.cpp)
Ascon XOF | `include/hashing/ascon_xof.hpp` | `ascon_xof` | [example/ascon_xof.cpp](./example/ascon_xof.cpp)
Ascon XOFA | `include/hashing/ascon_xofa.hpp` | `ascon_xofa` | [example/ascon_xofa.cpp](./example/ascon_xofa.cpp)

I maintain some examples demonstrating usage of Ascon AEAD, Hash and XOF API.

```bash
$ g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include example/ascon128_aead.cpp && ./a.out
Ascon-128 AEAD

Key       :	06a819d82123676245b7b88e864b01ac
Nonce     :	aaf550e27747555336e6e1efe29618dc
Data      :	a738688dfb1d2fcfab22502e11fe2559ffca02a26c60780103c88d25c611fa83
Text      :	22bbe3e728cc9355298c614a503471b69c27a193db9331e41ba42791b63d12e8b53547daa720aa8ecef3262edd52bfd871f5425f2fc3e1c7cbc0b20a69ccc1d4
Encrypted :	f5a716b9f709329a75deceeb0a72e4dbed86b89679beb99d26e1e47ff8f26f984785ac3f80677570240efb10e0bf5e93bde8c2662599052fa67026783fe2a061
Decrypted :	22bbe3e728cc9355298c614a503471b69c27a193db9331e41ba42791b63d12e8b53547daa720aa8ecef3262edd52bfd871f5425f2fc3e1c7cbc0b20a69ccc1d4

# ----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include example/ascon128a_aead.cpp && ./a.out
Ascon-128a AEAD

Key       :	88119fff6f0673cfc8d0269bac8ca328
Nonce     :	0c4b7bda5d47fda1b24b06b7292dd125
Data      :	49abcffb323076de7b068b5cba32344064a9462833a32ce2f8296947d16fb708
Text      :	2b2e331614af85f38500a3fbe182ec4c00bd0b5a200b852f582a63249363892043c040f0950dec14038cb82a91fd057a0edb81b691fe726be9a1fa3848b38e3d
Encrypted :	d71d984670a27cb8eb033d0c10be866966315d7ad60b048fc7f5f9a90fc02534f7c807baf6f32255bd94d7872a12e47dd3bf99439da8634d996ffe1e8cf08dcf
Decrypted :	2b2e331614af85f38500a3fbe182ec4c00bd0b5a200b852f582a63249363892043c040f0950dec14038cb82a91fd057a0edb81b691fe726be9a1fa3848b38e3d

# -----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include example/ascon80pq_aead.cpp && ./a.out
Ascon-80pq AEAD

Key       :	93afc9866d8fafb4d4895a97147da2639e652407
Nonce     :	6962c11757edcfd96ac6e3312bb22615
Data      :	8c132efaa2b27795f0da45846af44f44a8fa2d98df99e301639baa0f59c57035
Text      :	6d27382a7c6184fe52ea354574bfc8da49cbd7cb830183820d3e47368489428d89c4954a42ffb4f602b0cd1a9c678a25b8cc93d8b4ec39b56ea1b8157fc44864
Encrypted :	00fe776e96d074e556f84a47bc826f7be113436bda07198b3237f1f7d261ae60847609341d7c5b0c317244d9c0e3cb662e29440a43fc614d3a2a6ca488426225
Decrypted :	6d27382a7c6184fe52ea354574bfc8da49cbd7cb830183820d3e47368489428d89c4954a42ffb4f602b0cd1a9c678a25b8cc93d8b4ec39b56ea1b8157fc44864

# -----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include example/ascon_hash.cpp && ./a.out
Ascon Hash

Message :	a2309f40cae3efc99941641caf1c2cddf6fcd52a031ff199dfe5f185bb5142e91539b0d6777ad7fe8c2300d42015b623517f31b5db0a94d7e3c8cb521f03aabb
Digest  :	b467a2107aa34754a8679dfbac795660a5a2be927f2b0216a8fad50202d17249

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include example/ascon_hasha.cpp && ./a.out
Ascon HashA

Message :	b11a401ec0ad387fdc890962e86158432ba31e50b8810e3360b4c6143a73f6f82364f6bd895938b7f0babdab065c17c7e0e7196c4a15eb345eb174f4f1da2de5
Digest  :	aa7463f3284c6b5d84aaf0c56a18ae79a2fbaf0e095111a0e65824e24892e419

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include example/ascon_xof.cpp && ./a.out
Ascon XOF

Message :	5265ce4d5d0b3a0d89c757e4b14049a4da449be528e9bb7606363717c16bf1f751ff64c4214aebe385ed4629b7eb14ff1a3f0ca6754ce6e54210efd33d117d41
Digest  :	65e2631e1478b8cec2fcbc8efbd954aefc4b20649d48818f06e95d355e4bda2b4d830ff05cd88f92a0d312c08e9c9959dcc8bb0e68c9ac0c0164becda6cd5acc

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include example/ascon_xofa.cpp && ./a.out
Ascon XOFA

Message :	6970b5465e902633d16179a2c6f68cb8ad52e853bda99cf72b9bb33bbb23d0df6b22b67e7e4dbe53e04abaa63d69ee84b0e8e87a3cdd94c9da105622ffa50755
Digest  :	52644d6ba60bd3eca3aa2dabfe69ae397ddcdd0f0abd5151bf1d0e23cb4da41b3ab75634e26bae4b19f78e95fbdd54961b35cb5c7ef3ec7639816f0833ffaea7
```
