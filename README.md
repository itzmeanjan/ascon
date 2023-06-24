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

> **Note** Ascon-{Hash, HashA, XOF, XOFA} supports both oneshot and incremental hashing. If all message bytes are not ready to be absorbed into hash state in a single go, one opts for using ( compile-time decision ) incremental hashing API where arbitrary number of absorptions of arbitrary many bytes is allowed before state is finalized and ready to be squeezed.

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
cmake version 3.22.1
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
- Assess whether this implementation of Ascon is conformant with specification, using **K**nown **A**nswer **T**ests, which can be found in the reference implementation repository i.e. https://github.com/ascon/ascon-c.git.

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
- Ascon-Hash
- Ascon-HashA
- Ascon-XOF
- Ascon-XOFA
- Ascon-128 ( encrypt/ decrypt )
- Ascon-128a ( encrypt/ decrypt )
- Ascon-80pq ( encrypt/ decrypt )

> **Note** Benchmark recipe expects presence of `google-benchmark` header and library in well known $PATH ( so that it can be found by the compiler ).

> **Warning** Ensure that you've disabled CPU frequency scaling, when benchmarking routines, following [this](https://github.com/google/benchmark/blob/main/docs/reducing_variance.md) guide.

> **Note** `make perf` - was issued when collecting following benchmarks. Notice, CPU cycle count column. Read https://github.com/google/benchmark/blob/main/docs/perf_counters.md in case you're interested in getting performance measurements, other than just CPU cycles.

### On 12th Gen Intel(R) Core(TM) i7-1260P ( Compiled with GCC )

```bash
2023-06-24T15:28:31+04:00
Running ./bench/perf.out
Run on (16 X 4582.69 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.73, 0.62, 0.55
----------------------------------------------------------------------------------------------------
Benchmark                              Time             CPU   Iterations     CYCLES bytes_per_second
----------------------------------------------------------------------------------------------------
bench_ascon::permutation<1>         3.27 ns         3.27 ns    216282873    15.1918       11.3879G/s
bench_ascon::permutation<6>         18.3 ns         18.3 ns     38298282    84.8514       2.03537G/s
bench_ascon::permutation<8>         23.9 ns         23.9 ns     29311203    111.514       1.56162G/s
bench_ascon::permutation<12>        35.6 ns         35.6 ns     19596055    166.679       1070.86M/s
bench_ascon::enc_128/64/32           316 ns          316 ns      2216112   1.47803k       289.718M/s
bench_ascon::enc_128/128/32          468 ns          468 ns      1496108   2.18697k       326.299M/s
bench_ascon::enc_128/256/32          772 ns          772 ns       906764   3.60551k       355.875M/s
bench_ascon::enc_128/512/32         1377 ns         1377 ns       508323    6.4423k       376.672M/s
bench_ascon::enc_128/1024/32        2593 ns         2593 ns       269989   12.1154k       388.386M/s
bench_ascon::enc_128/2048/32        5025 ns         5025 ns       138899   23.4666k       394.744M/s
bench_ascon::enc_128/4096/32        9898 ns         9898 ns        70746    46.176k        397.75M/s
bench_ascon::dec_128/64/32           325 ns          325 ns      2157312   1.51641k       282.002M/s
bench_ascon::dec_128/128/32          475 ns          475 ns      1473245    2.2207k       321.307M/s
bench_ascon::dec_128/256/32          777 ns          777 ns       898221   3.63325k       353.656M/s
bench_ascon::dec_128/512/32         1382 ns         1382 ns       506364   6.46434k       375.515M/s
bench_ascon::dec_128/1024/32        2585 ns         2585 ns       270222   12.0992k       389.572M/s
bench_ascon::dec_128/2048/32        5010 ns         5010 ns       139068   23.4428k       395.951M/s
bench_ascon::dec_128/4096/32        9855 ns         9854 ns        70964    46.094k        399.49M/s
bench_ascon::enc_128a/64/32          248 ns          248 ns      2815609   1.16182k       368.905M/s
bench_ascon::enc_128a/128/32         351 ns          351 ns      1996411   1.64083k       434.978M/s
bench_ascon::enc_128a/256/32         553 ns          553 ns      1263713   2.58933k       496.427M/s
bench_ascon::enc_128a/512/32         959 ns          959 ns       725202   4.48734k       540.755M/s
bench_ascon::enc_128a/1024/32       1758 ns         1758 ns       395528   8.21999k       572.881M/s
bench_ascon::enc_128a/2048/32       3369 ns         3369 ns       209851   15.7356k       588.818M/s
bench_ascon::enc_128a/4096/32       6546 ns         6546 ns       107732   30.6186k       601.446M/s
bench_ascon::dec_128a/64/32          251 ns          251 ns      2778725   1.17446k       364.418M/s
bench_ascon::dec_128a/128/32         348 ns          348 ns      2014132    1.6271k        438.23M/s
bench_ascon::dec_128a/256/32         542 ns          542 ns      1285437   2.53509k       506.607M/s
bench_ascon::dec_128a/512/32         935 ns          935 ns       747083   4.36804k       555.094M/s
bench_ascon::dec_128a/1024/32       1710 ns         1710 ns       408818   8.00301k       588.923M/s
bench_ascon::dec_128a/2048/32       3271 ns         3271 ns       214385   15.3042k       606.389M/s
bench_ascon::dec_128a/4096/32       6389 ns         6389 ns       109071   29.8963k       616.146M/s
bench_ascon::enc_80pq/64/32          318 ns          318 ns      2196836   1.48985k       287.483M/s
bench_ascon::enc_80pq/128/32         470 ns          470 ns      1488651   2.20148k       324.335M/s
bench_ascon::enc_80pq/256/32         775 ns          775 ns       902398   3.62507k       354.263M/s
bench_ascon::enc_80pq/512/32        1383 ns         1383 ns       503204   6.47224k       375.063M/s
bench_ascon::enc_80pq/1024/32       2601 ns         2601 ns       268971   12.1648k       387.263M/s
bench_ascon::enc_80pq/2048/32       5018 ns         5018 ns       138531   23.4555k       395.316M/s
bench_ascon::enc_80pq/4096/32       9925 ns         9925 ns        70474   46.3502k       396.672M/s
bench_ascon::dec_80pq/64/32          326 ns          326 ns      2141556   1.52486k       280.476M/s
bench_ascon::dec_80pq/128/32         478 ns          478 ns      1464000   2.23353k       319.366M/s
bench_ascon::dec_80pq/256/32         781 ns          781 ns       894043   3.64884k       351.866M/s
bench_ascon::dec_80pq/512/32        1387 ns         1387 ns       503739   6.48338k        373.96M/s
bench_ascon::dec_80pq/1024/32       2615 ns         2615 ns       267270   12.2104k       385.103M/s
bench_ascon::dec_80pq/2048/32       5059 ns         5059 ns       137187   23.6542k       392.109M/s
bench_ascon::dec_80pq/4096/32       9910 ns         9909 ns        70396   46.3017k       397.275M/s
bench_ascon::hash/64                 464 ns          464 ns      1504763   2.17134k       197.175M/s
bench_ascon::hash/128                751 ns          751 ns       929275   3.51185k       203.132M/s
bench_ascon::hash/256               1325 ns         1325 ns       526619   6.19685k       207.228M/s
bench_ascon::hash/512               2471 ns         2471 ns       283201   11.5544k       209.935M/s
bench_ascon::hash/1024              4758 ns         4758 ns       147064   22.2676k       211.669M/s
bench_ascon::hash/2048              9359 ns         9359 ns        74573   43.6979k       211.955M/s
bench_ascon::hash/4096             18509 ns        18509 ns        37723    86.558k       212.697M/s
bench_ascon::hasha/64                322 ns          322 ns      2177665   1.50346k       284.539M/s
bench_ascon::hasha/128               513 ns          513 ns      1359949    2.3979k       297.348M/s
bench_ascon::hasha/256               892 ns          892 ns       783986   4.17073k        307.77M/s
bench_ascon::hasha/512              1654 ns         1654 ns       422735   7.73228k       313.694M/s
bench_ascon::hasha/1024             3179 ns         3179 ns       220128   14.8658k        316.81M/s
bench_ascon::hasha/2048             6230 ns         6230 ns       112187   29.1374k       318.408M/s
bench_ascon::hasha/4096            12355 ns        12355 ns        56604   57.7851k       318.646M/s
bench_ascon::xof/64/32               463 ns          463 ns      1511657   2.16412k       197.946M/s
bench_ascon::xof/128/32              745 ns          745 ns       938859   3.48356k       204.869M/s
bench_ascon::xof/256/32             1312 ns         1312 ns       532868   6.14062k       209.292M/s
bench_ascon::xof/512/32             2441 ns         2441 ns       286592   11.4181k       212.566M/s
bench_ascon::xof/1024/32            4699 ns         4699 ns       148877   21.9803k       214.318M/s
bench_ascon::xof/2048/32            9213 ns         9213 ns        75854   43.0798k        215.32M/s
bench_ascon::xof/4096/32           18222 ns        18221 ns        38393   85.2823k       216.057M/s
bench_ascon::xof/64/64               614 ns          614 ns      1139353   2.87194k       198.686M/s
bench_ascon::xof/128/64              898 ns          898 ns       780886   4.19162k       203.974M/s
bench_ascon::xof/256/64             1459 ns         1459 ns       478649   6.81872k       209.222M/s
bench_ascon::xof/512/64             2592 ns         2592 ns       269882   12.0999k       211.911M/s
bench_ascon::xof/1024/64            4845 ns         4845 ns       144351    22.654k       214.156M/s
bench_ascon::xof/2048/64            9356 ns         9356 ns        74756   43.7712k       215.273M/s
bench_ascon::xof/4096/64           18427 ns        18427 ns        37991   86.0185k       215.301M/s
bench_ascon::xofa/64/32              320 ns          320 ns      2180404   1.49817k        285.68M/s
bench_ascon::xofa/128/32             509 ns          509 ns      1370932   2.38034k        299.72M/s
bench_ascon::xofa/256/32             886 ns          886 ns       788565   4.14519k       310.032M/s
bench_ascon::xofa/512/32            1642 ns         1642 ns       426768   7.67627k        315.98M/s
bench_ascon::xofa/1024/32           3151 ns         3151 ns       221808   14.7434k       319.558M/s
bench_ascon::xofa/2048/32           6178 ns         6177 ns       113102   28.8912k       321.108M/s
bench_ascon::xofa/4096/32          12222 ns        12222 ns        56879   57.1956k       322.103M/s
bench_ascon::xofa/64/64              418 ns          418 ns      1679147   1.95282k       292.006M/s
bench_ascon::xofa/128/64             608 ns          608 ns      1147804   2.84323k       301.047M/s
bench_ascon::xofa/256/64             984 ns          984 ns       712112   4.60082k       310.266M/s
bench_ascon::xofa/512/64            1738 ns         1738 ns       402655   8.13023k       316.083M/s
bench_ascon::xofa/1024/64           3250 ns         3250 ns       215405   15.1925k       319.294M/s
bench_ascon::xofa/2048/64           6278 ns         6278 ns       111414   29.3704k       320.833M/s
bench_ascon::xofa/4096/64          12323 ns        12323 ns        56664   57.6646k       321.935M/s
```

### On 12th Gen Intel(R) Core(TM) i7-1260P ( Compiled with Clang )

```bash
2023-06-24T15:36:54+04:00
Running ./bench/perf.out
Run on (16 X 4170.68 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.54, 0.53, 0.54
----------------------------------------------------------------------------------------------------
Benchmark                              Time             CPU   Iterations     CYCLES bytes_per_second
----------------------------------------------------------------------------------------------------
bench_ascon::permutation<1>         2.93 ns         2.93 ns    238284605    13.7065       12.7093G/s
bench_ascon::permutation<6>         16.9 ns         16.9 ns     41383766    79.1271       2.20204G/s
bench_ascon::permutation<8>         23.3 ns         23.3 ns     30071118    108.962       1.59757G/s
bench_ascon::permutation<12>        34.7 ns         34.7 ns     20185265    162.339        1098.9M/s
bench_ascon::enc_128/64/32           303 ns          303 ns      2323939   1.41341k       302.358M/s
bench_ascon::enc_128/128/32          442 ns          442 ns      1584304   2.06739k       345.064M/s
bench_ascon::enc_128/256/32          718 ns          718 ns       981037   3.35274k       382.636M/s
bench_ascon::enc_128/512/32         1272 ns         1272 ns       551058   5.94321k       407.744M/s
bench_ascon::enc_128/1024/32        2381 ns         2380 ns       294267   11.1296k       423.076M/s
bench_ascon::enc_128/2048/32        4595 ns         4594 ns       152291   21.4827k       431.767M/s
bench_ascon::enc_128/4096/32        9048 ns         9047 ns        77396   42.2695k       435.144M/s
bench_ascon::dec_128/64/32           302 ns          302 ns      2334946   1.40934k       303.383M/s
bench_ascon::dec_128/128/32          438 ns          438 ns      1601737   2.04394k       348.493M/s
bench_ascon::dec_128/256/32          708 ns          708 ns       987077   3.31031k       387.844M/s
bench_ascon::dec_128/512/32         1253 ns         1253 ns       559373   5.84658k       414.146M/s
bench_ascon::dec_128/1024/32        2341 ns         2341 ns       297992   10.9496k       430.249M/s
bench_ascon::dec_128/2048/32        4517 ns         4516 ns       155146   21.1278k       439.236M/s
bench_ascon::dec_128/4096/32        8907 ns         8907 ns        77385    41.667k       442.011M/s
bench_ascon::enc_128a/64/32          239 ns          239 ns      2917445   1.11964k       382.474M/s
bench_ascon::enc_128a/128/32         333 ns          333 ns      2098137   1.56086k        457.61M/s
bench_ascon::enc_128a/256/32         521 ns          521 ns      1341729   2.44006k        526.97M/s
bench_ascon::enc_128a/512/32         904 ns          904 ns       769848   4.22987k       573.866M/s
bench_ascon::enc_128a/1024/32       1657 ns         1657 ns       422273   7.74901k       607.949M/s
bench_ascon::enc_128a/2048/32       3162 ns         3161 ns       221716   14.7894k       627.456M/s
bench_ascon::enc_128a/4096/32       6176 ns         6175 ns       113195   28.8838k       637.482M/s
bench_ascon::dec_128a/64/32          242 ns          242 ns      2882859   1.13307k       377.789M/s
bench_ascon::dec_128a/128/32         336 ns          336 ns      2082020   1.57372k       453.489M/s
bench_ascon::dec_128a/256/32         525 ns          525 ns      1329397   2.45743k       522.786M/s
bench_ascon::dec_128a/512/32         910 ns          910 ns       765284   4.25546k       570.133M/s
bench_ascon::dec_128a/1024/32       1665 ns         1665 ns       419920   7.79499k       604.783M/s
bench_ascon::dec_128a/2048/32       3180 ns         3180 ns       220116   14.8722k       623.799M/s
bench_ascon::dec_128a/4096/32       6212 ns         6212 ns       112174   29.0644k       633.762M/s
bench_ascon::enc_80pq/64/32          304 ns          304 ns      2311668   1.42107k        301.14M/s
bench_ascon::enc_80pq/128/32         441 ns          441 ns      1587063   2.06162k       345.879M/s
bench_ascon::enc_80pq/256/32         720 ns          719 ns       965128   3.36029k       381.751M/s
bench_ascon::enc_80pq/512/32        1276 ns         1276 ns       549019   5.96375k       406.711M/s
bench_ascon::enc_80pq/1024/32       2392 ns         2392 ns       292984   11.1842k       421.082M/s
bench_ascon::enc_80pq/2048/32       4620 ns         4620 ns       151493   21.5929k       429.379M/s
bench_ascon::enc_80pq/4096/32       9089 ns         9088 ns        77107   42.4734k       433.183M/s
bench_ascon::dec_80pq/64/32          302 ns          302 ns      2327642   1.41122k       303.301M/s
bench_ascon::dec_80pq/128/32         436 ns          436 ns      1606016   2.03963k       349.777M/s
bench_ascon::dec_80pq/256/32         707 ns          707 ns       989515   3.30613k       388.573M/s
bench_ascon::dec_80pq/512/32        1248 ns         1248 ns       559431   5.83602k       415.639M/s
bench_ascon::dec_80pq/1024/32       2339 ns         2339 ns       299165    10.927k       430.554M/s
bench_ascon::dec_80pq/2048/32       4507 ns         4507 ns       155232   21.0722k        440.17M/s
bench_ascon::dec_80pq/4096/32       8890 ns         8890 ns        78695    41.562k       442.851M/s
bench_ascon::hash/64                 451 ns          451 ns      1554773   2.10395k       203.069M/s
bench_ascon::hash/128                728 ns          728 ns       957517   3.39978k       209.549M/s
bench_ascon::hash/256               1284 ns         1284 ns       544697   5.99943k       213.909M/s
bench_ascon::hash/512               2396 ns         2396 ns       292622   11.1808k       216.549M/s
bench_ascon::hash/1024              4609 ns         4609 ns       151591   21.5495k       218.514M/s
bench_ascon::hash/2048              9053 ns         9052 ns        77097    42.289k       219.145M/s
bench_ascon::hash/4096             17925 ns        17924 ns        39051   83.7464k       219.639M/s
bench_ascon::hasha/64                312 ns          312 ns      2236344    1.4593k       293.298M/s
bench_ascon::hasha/128               498 ns          498 ns      1405096   2.32553k       306.663M/s
bench_ascon::hasha/256               867 ns          867 ns       809889   4.04626k       316.708M/s
bench_ascon::hasha/512              1604 ns         1604 ns       436803   7.49185k        323.46M/s
bench_ascon::hasha/1024             3077 ns         3076 ns       227238   14.3821k       327.355M/s
bench_ascon::hasha/2048             6035 ns         6035 ns       116243    28.201k       328.705M/s
bench_ascon::hasha/4096            11979 ns        11978 ns        58427   56.0192k       328.672M/s
bench_ascon::xof/64/32               454 ns          454 ns      1542768   2.11836k       201.838M/s
bench_ascon::xof/128/32              730 ns          730 ns       954015   3.41492k       208.992M/s
bench_ascon::xof/256/32             1285 ns         1285 ns       543401   6.01038k       213.705M/s
bench_ascon::xof/512/32             2393 ns         2393 ns       293059   11.1906k       216.819M/s
bench_ascon::xof/1024/32            4613 ns         4613 ns       151796   21.5532k       218.314M/s
bench_ascon::xof/2048/32            9047 ns         9046 ns        77464   42.3124k        219.28M/s
bench_ascon::xof/4096/32           17924 ns        17922 ns        39106   83.7854k       219.663M/s
bench_ascon::xof/64/64               594 ns          594 ns      1167297   2.78056k       205.373M/s
bench_ascon::xof/128/64              871 ns          871 ns       800651   4.07565k       210.224M/s
bench_ascon::xof/256/64             1427 ns         1427 ns       490400   6.66929k       213.807M/s
bench_ascon::xof/512/64             2536 ns         2535 ns       276543   11.8481k       216.651M/s
bench_ascon::xof/1024/64            4754 ns         4754 ns       146834   22.2202k       218.269M/s
bench_ascon::xof/2048/64            9184 ns         9184 ns        76082   42.9656k       219.322M/s
bench_ascon::xof/4096/64           18060 ns        18059 ns        38712   84.4333k       219.682M/s
bench_ascon::xofa/64/32              316 ns          316 ns      2215940    1.4776k       289.852M/s
bench_ascon::xofa/128/32             501 ns          501 ns      1394484   2.34385k       304.404M/s
bench_ascon::xofa/256/32             873 ns          873 ns       803567   4.07916k       314.677M/s
bench_ascon::xofa/512/32            1612 ns         1612 ns       433589    7.5407k         321.8M/s
bench_ascon::xofa/1024/32           3093 ns         3093 ns       226307   14.4656k       325.599M/s
bench_ascon::xofa/2048/32           6057 ns         6057 ns       114654   28.3228k       327.505M/s
bench_ascon::xofa/4096/32          11990 ns        11990 ns        58445   56.0628k       328.349M/s
bench_ascon::xofa/64/64              410 ns          410 ns      1703838   1.92249k       297.438M/s
bench_ascon::xofa/128/64             597 ns          597 ns      1170934   2.79441k       306.555M/s
bench_ascon::xofa/256/64             967 ns          967 ns       724519   4.52362k       315.592M/s
bench_ascon::xofa/512/64            1707 ns         1707 ns       409783   7.98668k       321.735M/s
bench_ascon::xofa/1024/64           3189 ns         3189 ns       219629   14.9089k       325.419M/s
bench_ascon::xofa/2048/64           6139 ns         6138 ns       113619   28.7625k       328.123M/s
bench_ascon::xofa/4096/64          12075 ns        12074 ns        57898   56.4991k       328.581M/s
```

## Usage

`ascon` is a header-only C++ library, which is pretty easy to get started with. Just include the header file

- For AEAD : `include/aead.hpp`
- For Hashing : `include/hash.hpp` 

and use functions/ structs/ constants living inside `ascon::` namespace. Finally when compiling the program, let your compiler know where it can find the header files using `-I` flag.

I maintain some examples demonstrating usage of Ascon AEAD, Hash and XOF API.

Scheme | Header | Example
:-- | :-: | --:
Ascon-128 AEAD | `include/aead.hpp` | [example/ascon_128.cpp](./example/ascon_128.cpp)
Ascon-128a AEAD | `include/aead.hpp` | [example/ascon_128a.cpp](./example/ascon_128a.cpp)
Ascon-80pq AEAD | `include/aead.hpp` | [example/ascon_80pq.cpp](./example/ascon_80pq.cpp)
Ascon Hash | `include/ascon_hash.hpp` | [example/ascon_hash.cpp](./example/ascon_hash.cpp)
Ascon HashA | `include/ascon_hasha.hpp` | [example/ascon_hasha.cpp](./example/ascon_hasha.cpp)
Ascon XOF | `include/ascon_xof.hpp` | [example/ascon_xof.cpp](./example/ascon_xof.cpp)
Ascon XOFA | `include/ascon_xofa.hpp` | [example/ascon_xofa.cpp](./example/ascon_xofa.cpp)

```bash
$ g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include example/ascon_128.cpp && ./a.out
Ascon-128 AEAD

Key       :	06a819d82123676245b7b88e864b01ac
Nonce     :	aaf550e27747555336e6e1efe29618dc
Data      :	a738688dfb1d2fcfab22502e11fe2559ffca02a26c60780103c88d25c611fa83
Text      :	22bbe3e728cc9355298c614a503471b69c27a193db9331e41ba42791b63d12e8b53547daa720aa8ecef3262edd52bfd871f5425f2fc3e1c7cbc0b20a69ccc1d4
Encrypted :	f5a716b9f709329a75deceeb0a72e4dbed86b89679beb99d26e1e47ff8f26f984785ac3f80677570240efb10e0bf5e93bde8c2662599052fa67026783fe2a061
Decrypted :	22bbe3e728cc9355298c614a503471b69c27a193db9331e41ba42791b63d12e8b53547daa720aa8ecef3262edd52bfd871f5425f2fc3e1c7cbc0b20a69ccc1d4

# ----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include example/ascon_128a.cpp && ./a.out
Ascon-128a AEAD

Key       :	88119fff6f0673cfc8d0269bac8ca328
Nonce     :	0c4b7bda5d47fda1b24b06b7292dd125
Data      :	49abcffb323076de7b068b5cba32344064a9462833a32ce2f8296947d16fb708
Text      :	2b2e331614af85f38500a3fbe182ec4c00bd0b5a200b852f582a63249363892043c040f0950dec14038cb82a91fd057a0edb81b691fe726be9a1fa3848b38e3d
Encrypted :	d71d984670a27cb8eb033d0c10be866966315d7ad60b048fc7f5f9a90fc02534f7c807baf6f32255bd94d7872a12e47dd3bf99439da8634d996ffe1e8cf08dcf
Decrypted :	2b2e331614af85f38500a3fbe182ec4c00bd0b5a200b852f582a63249363892043c040f0950dec14038cb82a91fd057a0edb81b691fe726be9a1fa3848b38e3d

# -----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include example/ascon_80pq.cpp && ./a.out
Ascon-80pq AEAD

Key       :	93afc9866d8fafb4d4895a97147da2639e652407
Nonce     :	6962c11757edcfd96ac6e3312bb22615
Data      :	8c132efaa2b27795f0da45846af44f44a8fa2d98df99e301639baa0f59c57035
Text      :	6d27382a7c6184fe52ea354574bfc8da49cbd7cb830183820d3e47368489428d89c4954a42ffb4f602b0cd1a9c678a25b8cc93d8b4ec39b56ea1b8157fc44864
Encrypted :	00fe776e96d074e556f84a47bc826f7be113436bda07198b3237f1f7d261ae60847609341d7c5b0c317244d9c0e3cb662e29440a43fc614d3a2a6ca488426225
Decrypted :	6d27382a7c6184fe52ea354574bfc8da49cbd7cb830183820d3e47368489428d89c4954a42ffb4f602b0cd1a9c678a25b8cc93d8b4ec39b56ea1b8157fc44864

# -----------------

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
```
