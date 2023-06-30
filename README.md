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
2023-06-30T11:47:55+04:00
Running ./benchmarks/perf.out
Run on (16 X 4404.47 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.91, 0.74, 0.59
***WARNING*** There are 133 benchmarks with threads and 1 performance counters were requested. Beware counters will reflect the combined usage across all threads.
------------------------------------------------------------------------------------------------------------------
Benchmark                                            Time             CPU   Iterations     CYCLES bytes_per_second
------------------------------------------------------------------------------------------------------------------
bench_ascon::ascon_permutation<1>                 3.21 ns         3.21 ns    217485268    14.9581       11.6076G/s
bench_ascon::ascon_permutation<6>                 18.2 ns         18.2 ns     38359962    85.0548       2.04312G/s
bench_ascon::ascon_permutation<8>                 23.9 ns         23.9 ns     29419369    111.437       1.56046G/s
bench_ascon::ascon_permutation<12>                35.6 ns         35.6 ns     19602162    166.672       1070.88M/s
bench_ascon::ascon128_aead_encrypt/64/32           329 ns          329 ns      2125546   1.54038k       416.854M/s
bench_ascon::ascon128_aead_encrypt/128/32          479 ns          479 ns      1461610   2.23901k       414.515M/s
bench_ascon::ascon128_aead_encrypt/256/32          780 ns          780 ns       898240   3.65216k       410.599M/s
bench_ascon::ascon128_aead_encrypt/512/32         1380 ns         1380 ns       505944    6.4612k       409.172M/s
bench_ascon::ascon128_aead_encrypt/1024/32        2585 ns         2585 ns       271198   12.0968k       407.281M/s
bench_ascon::ascon128_aead_encrypt/2048/32        4999 ns         4999 ns       139733   23.3681k       405.935M/s
bench_ascon::ascon128_aead_encrypt/4096/32        9843 ns         9843 ns        70961   45.9025k       404.613M/s
bench_ascon::ascon128_aead_decrypt/64/32           342 ns          342 ns      2061624   1.58405k       401.565M/s
bench_ascon::ascon128_aead_decrypt/128/32          493 ns          493 ns      1416382   2.28824k       402.575M/s
bench_ascon::ascon128_aead_decrypt/256/32          793 ns          793 ns       880449   3.70478k       404.051M/s
bench_ascon::ascon128_aead_decrypt/512/32         1398 ns         1398 ns       499264   6.53735k        403.93M/s
bench_ascon::ascon128_aead_decrypt/1024/32        2610 ns         2610 ns       267890   12.2068k       403.442M/s
bench_ascon::ascon128_aead_decrypt/2048/32        5039 ns         5039 ns       138790    23.567k       402.719M/s
bench_ascon::ascon128_aead_decrypt/4096/32        9908 ns         9908 ns        70720   46.2718k       401.947M/s
bench_ascon::ascon128a_aead_encrypt/64/32          253 ns          253 ns      2761011   1.18035k       541.895M/s
bench_ascon::ascon128a_aead_encrypt/128/32         352 ns          352 ns      1915757   1.64062k       562.964M/s
bench_ascon::ascon128a_aead_encrypt/256/32         548 ns          548 ns      1274141   2.55248k        584.57M/s
bench_ascon::ascon128a_aead_encrypt/512/32         940 ns          940 ns       744714   4.37897k       600.667M/s
bench_ascon::ascon128a_aead_encrypt/1024/32       1720 ns         1721 ns       407320   8.02222k       611.938M/s
bench_ascon::ascon128a_aead_encrypt/2048/32       3285 ns         3285 ns       212852   15.3095k       617.847M/s
bench_ascon::ascon128a_aead_encrypt/4096/32       6406 ns         6406 ns       108256   29.8678k       621.687M/s
bench_ascon::ascon128a_aead_decrypt/64/32          262 ns          262 ns      2660949   1.22614k       523.966M/s
bench_ascon::ascon128a_aead_decrypt/128/32         359 ns          359 ns      1948795   1.67924k       552.821M/s
bench_ascon::ascon128a_aead_decrypt/256/32         556 ns          556 ns      1261755   2.59868k        576.69M/s
bench_ascon::ascon128a_aead_decrypt/512/32         945 ns          945 ns       741383   4.42085k       597.418M/s
bench_ascon::ascon128a_aead_decrypt/1024/32       1724 ns         1724 ns       406035   8.06746k       610.546M/s
bench_ascon::ascon128a_aead_decrypt/2048/32       3291 ns         3291 ns       212567   15.3836k       616.605M/s
bench_ascon::ascon128a_aead_decrypt/4096/32       6426 ns         6426 ns       108783   30.0151k       619.734M/s
bench_ascon::ascon80pq_aead_encrypt/64/32          332 ns          332 ns      2110351   1.54798k       424.855M/s
bench_ascon::ascon80pq_aead_encrypt/128/32         485 ns          485 ns      1444522   2.25987k       416.767M/s
bench_ascon::ascon80pq_aead_encrypt/256/32         789 ns          789 ns       887711   3.67773k        411.13M/s
bench_ascon::ascon80pq_aead_encrypt/512/32        1400 ns         1400 ns       499490   6.52463k       405.919M/s
bench_ascon::ascon80pq_aead_encrypt/1024/32       2620 ns         2619 ns       266815   12.2069k       403.389M/s
bench_ascon::ascon80pq_aead_encrypt/2048/32       5063 ns         5063 ns       137338   23.5869k       401.592M/s
bench_ascon::ascon80pq_aead_encrypt/4096/32       9931 ns         9931 ns        70472   46.3394k       401.388M/s
bench_ascon::ascon80pq_aead_decrypt/64/32          340 ns          340 ns      2058138   1.58772k        415.24M/s
bench_ascon::ascon80pq_aead_decrypt/128/32         490 ns          490 ns      1427664   2.29162k       412.704M/s
bench_ascon::ascon80pq_aead_decrypt/256/32         791 ns          791 ns       880829   3.69712k       409.901M/s
bench_ascon::ascon80pq_aead_decrypt/512/32        1394 ns         1394 ns       498614   6.51614k       407.732M/s
bench_ascon::ascon80pq_aead_decrypt/1024/32       2596 ns         2596 ns       270017   12.1335k        407.04M/s
bench_ascon::ascon80pq_aead_decrypt/2048/32       5014 ns         5015 ns       139494   23.4423k       405.465M/s
bench_ascon::ascon80pq_aead_decrypt/4096/32       9860 ns         9860 ns        71009   46.0134k         404.3M/s
bench_ascon::ascon_hash/64                         463 ns          463 ns      1508886   2.16477k        197.61M/s
bench_ascon::ascon_hash/128                        749 ns          749 ns       935922   3.49579k       203.714M/s
bench_ascon::ascon_hash/256                       1320 ns         1320 ns       530634   6.16386k       208.072M/s
bench_ascon::ascon_hash/512                       2456 ns         2456 ns       283799   11.4816k       211.253M/s
bench_ascon::ascon_hash/1024                      4726 ns         4726 ns       148098   22.1158k        213.09M/s
bench_ascon::ascon_hash/2048                      9287 ns         9287 ns        75218      43.4k       213.598M/s
bench_ascon::ascon_hash/4096                     18356 ns        18357 ns        38132   85.9384k       214.459M/s
bench_ascon::ascon_hasha/64                        323 ns          323 ns      2173037   1.50889k       283.555M/s
bench_ascon::ascon_hasha/128                       514 ns          514 ns      1348432   2.39759k       296.752M/s
bench_ascon::ascon_hasha/256                       895 ns          895 ns       780762   4.18093k       306.973M/s
bench_ascon::ascon_hasha/512                      1656 ns         1656 ns       421635   7.73721k        313.35M/s
bench_ascon::ascon_hasha/1024                     3185 ns         3185 ns       220622   14.8508k       316.227M/s
bench_ascon::ascon_hasha/2048                     6226 ns         6226 ns       111817   29.0887k       318.632M/s
bench_ascon::ascon_hasha/4096                    12337 ns        12337 ns        56696   57.5687k       319.102M/s
bench_ascon::ascon_xof/64/32                       464 ns          464 ns      1512120   2.16707k       197.468M/s
bench_ascon::ascon_xof/128/32                      749 ns          749 ns       926405    3.4963k       203.765M/s
bench_ascon::ascon_xof/256/32                     1321 ns         1321 ns       529939    6.1698k       207.979M/s
bench_ascon::ascon_xof/512/32                     2462 ns         2462 ns       284266   11.4857k       210.757M/s
bench_ascon::ascon_xof/1024/32                    4743 ns         4743 ns       147866   22.1207k        212.32M/s
bench_ascon::ascon_xof/2048/32                    9306 ns         9306 ns        74982   43.4187k       213.156M/s
bench_ascon::ascon_xof/4096/32                   18397 ns        18397 ns        37982   85.9739k       213.985M/s
bench_ascon::ascon_xof/64/64                       610 ns          610 ns      1143696   2.85084k       200.087M/s
bench_ascon::ascon_xof/128/64                      895 ns          895 ns       779356   4.17894k       204.641M/s
bench_ascon::ascon_xof/256/64                     1465 ns         1465 ns       477693   6.84569k       208.326M/s
bench_ascon::ascon_xof/512/64                     2601 ns         2601 ns       269148   12.1638k       211.191M/s
bench_ascon::ascon_xof/1024/64                    4879 ns         4879 ns       143549   22.7989k       212.659M/s
bench_ascon::ascon_xof/2048/64                    9439 ns         9439 ns        73860   44.0961k       213.384M/s
bench_ascon::ascon_xof/4096/64                   18517 ns        18516 ns        37740   86.6514k       214.257M/s
bench_ascon::ascon_xofa/64/32                      324 ns          324 ns      2155388   1.51898k       282.251M/s
bench_ascon::ascon_xofa/128/32                     517 ns          517 ns      1355721   2.41919k       294.938M/s
bench_ascon::ascon_xofa/256/32                     903 ns          903 ns       773512   4.22499k       304.303M/s
bench_ascon::ascon_xofa/512/32                    1671 ns         1671 ns       417608   7.82146k       310.477M/s
bench_ascon::ascon_xofa/1024/32                   3208 ns         3208 ns       217943   15.0162k       313.894M/s
bench_ascon::ascon_xofa/2048/32                   6283 ns         6283 ns       111280    29.413k       315.701M/s
bench_ascon::ascon_xofa/4096/32                  12452 ns        12452 ns        56288   58.2138k        316.15M/s
bench_ascon::ascon_xofa/64/64                      424 ns          424 ns      1651389   1.97911k       288.162M/s
bench_ascon::ascon_xofa/128/64                     616 ns          616 ns      1131682   2.88135k        297.12M/s
bench_ascon::ascon_xofa/256/64                    1002 ns         1002 ns       699282   4.67808k       304.672M/s
bench_ascon::ascon_xofa/512/64                    1770 ns         1770 ns       395853   8.27366k       310.365M/s
bench_ascon::ascon_xofa/1024/64                   3308 ns         3308 ns       211090   15.4705k       313.706M/s
bench_ascon::ascon_xofa/2048/64                   6387 ns         6387 ns       109353    29.866k       315.333M/s
bench_ascon::ascon_xofa/4096/64                  12529 ns        12529 ns        55690   58.6638k       316.652M/s
bench_ascon::ascon_prf/64/16                       184 ns          184 ns      3803545     859.24       498.024M/s
bench_ascon::ascon_prf/128/16                      257 ns          257 ns      2721928   1.19893k       594.369M/s
bench_ascon::ascon_prf/256/16                      402 ns          402 ns      1738965   1.87935k       683.129M/s
bench_ascon::ascon_prf/512/16                      694 ns          694 ns      1006695    3.2394k       747.742M/s
bench_ascon::ascon_prf/1024/16                    1279 ns         1279 ns       546919   5.97014k       787.683M/s
bench_ascon::ascon_prf/2048/16                    2443 ns         2443 ns       286661   11.4121k       812.101M/s
bench_ascon::ascon_prf/4096/16                    4772 ns         4772 ns       146570   22.2961k       825.048M/s
bench_ascon::ascon_prf/64/32                       220 ns          220 ns      3186245    1025.58       486.421M/s
bench_ascon::ascon_prf/128/32                      292 ns          292 ns      2390646   1.36569k       574.213M/s
bench_ascon::ascon_prf/256/32                      438 ns          438 ns      1598603   2.04551k       661.839M/s
bench_ascon::ascon_prf/512/32                      729 ns          729 ns       957913   3.40626k       732.138M/s
bench_ascon::ascon_prf/1024/32                    1314 ns         1314 ns       532780   6.13751k       777.844M/s
bench_ascon::ascon_prf/2048/32                    2482 ns         2482 ns       282481   11.5789k       805.339M/s
bench_ascon::ascon_prf/4096/32                    4805 ns         4805 ns       145479   22.4643k       822.438M/s
bench_ascon::ascon_prf/64/64                       291 ns          291 ns      2406757   1.36053k       471.389M/s
bench_ascon::ascon_prf/128/64                      363 ns          363 ns      1920865   1.70029k       546.149M/s
bench_ascon::ascon_prf/256/64                      509 ns          509 ns      1376006   2.38024k       629.874M/s
bench_ascon::ascon_prf/512/64                      800 ns          800 ns       875186   3.74081k       705.768M/s
bench_ascon::ascon_prf/1024/64                    1386 ns         1386 ns       506107   6.47067k       759.848M/s
bench_ascon::ascon_prf/2048/64                    2552 ns         2552 ns       273865   11.9142k       795.228M/s
bench_ascon::ascon_prf/4096/64                    4874 ns         4874 ns       143438   22.7989k       817.033M/s
bench_ascon::ascon_mac_authenticate/64             184 ns          184 ns      3809402    857.529       498.423M/s
bench_ascon::ascon_mac_authenticate/128            257 ns          257 ns      2734077   1.19837k       594.398M/s
bench_ascon::ascon_mac_authenticate/256            402 ns          402 ns      1742074   1.87709k       683.881M/s
bench_ascon::ascon_mac_authenticate/512            692 ns          692 ns      1011481   3.23544k       749.392M/s
bench_ascon::ascon_mac_authenticate/1024          1274 ns         1274 ns       548532   5.96081k       790.615M/s
bench_ascon::ascon_mac_authenticate/2048          2436 ns         2436 ns       287170   11.3971k        814.33M/s
bench_ascon::ascon_mac_authenticate/4096          4766 ns         4766 ns       147120   22.2674k       826.036M/s
bench_ascon::ascon_mac_verify/64                   184 ns          184 ns      3789979    861.018       579.585M/s
bench_ascon::ascon_mac_verify/128                  257 ns          257 ns      2723674   1.20123k       653.015M/s
bench_ascon::ascon_mac_verify/256                  403 ns          403 ns      1739089    1.8813k       720.099M/s
bench_ascon::ascon_mac_verify/512                  695 ns          695 ns      1007397   3.24217k       768.252M/s
bench_ascon::ascon_mac_verify/1024                1279 ns         1279 ns       546308   5.97631k       799.417M/s
bench_ascon::ascon_mac_verify/2048                2447 ns         2447 ns       286651   11.4201k       816.938M/s
bench_ascon::ascon_mac_verify/4096                4764 ns         4764 ns       146631   22.3061k       829.537M/s
bench_ascon::ascon_prfs_authenticate/1            47.0 ns         47.0 ns     14840124    220.093       668.925M/s
bench_ascon::ascon_prfs_authenticate/2            46.8 ns         46.8 ns     14927313    219.019        692.74M/s
bench_ascon::ascon_prfs_authenticate/4            46.5 ns         46.5 ns     15086734    217.455        738.69M/s
bench_ascon::ascon_prfs_authenticate/8            37.0 ns         37.0 ns     18897953    172.913       1031.07M/s
bench_ascon::ascon_prfs_authenticate/16           37.3 ns         37.3 ns     18674312    174.478       1.19727G/s
bench_ascon::ascon_prfs_verify/1                  51.2 ns         51.2 ns     13610209    239.182       913.178M/s
bench_ascon::ascon_prfs_verify/2                  50.8 ns         50.8 ns     13693333    237.453       938.136M/s
bench_ascon::ascon_prfs_verify/4                  50.4 ns         50.4 ns     13424227    235.501       983.734M/s
bench_ascon::ascon_prfs_verify/8                  45.6 ns         45.6 ns     15361933    213.426       1.14293G/s
bench_ascon::ascon_prfs_verify/16                 45.6 ns         45.6 ns     15352309     213.47       1.30594G/s
```

### On 12th Gen Intel(R) Core(TM) i7-1260P ( Compiled with Clang )

```bash
2023-06-30T11:45:03+04:00
Running ./benchmarks/perf.out
Run on (16 X 524.741 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.86, 0.55, 0.51
***WARNING*** There are 133 benchmarks with threads and 1 performance counters were requested. Beware counters will reflect the combined usage across all threads.
------------------------------------------------------------------------------------------------------------------
Benchmark                                            Time             CPU   Iterations     CYCLES bytes_per_second
------------------------------------------------------------------------------------------------------------------
bench_ascon::ascon_permutation<1>                 2.85 ns         2.85 ns    247099654    13.3172       13.0924G/s
bench_ascon::ascon_permutation<6>                 16.9 ns         16.9 ns     41360238    79.2411       2.20209G/s
bench_ascon::ascon_permutation<8>                 23.1 ns         23.1 ns     30313749    107.998       1.61495G/s
bench_ascon::ascon_permutation<12>                34.6 ns         34.6 ns     20241834    161.906        1103.4M/s
bench_ascon::ascon128_aead_encrypt/64/32           321 ns          321 ns      2187711   1.50135k       427.854M/s
bench_ascon::ascon128_aead_encrypt/128/32          461 ns          461 ns      1522726   2.15722k       430.198M/s
bench_ascon::ascon128_aead_encrypt/256/32          738 ns          738 ns       941256   3.45158k       434.484M/s
bench_ascon::ascon128_aead_encrypt/512/32         1294 ns         1294 ns       541129   6.05888k        436.25M/s
bench_ascon::ascon128_aead_encrypt/1024/32        2406 ns         2406 ns       290834   11.2674k       437.659M/s
bench_ascon::ascon128_aead_encrypt/2048/32        4627 ns         4627 ns       151171   21.6719k       438.579M/s
bench_ascon::ascon128_aead_encrypt/4096/32        9091 ns         9091 ns        76720   42.5743k       438.053M/s
bench_ascon::ascon128_aead_decrypt/64/32           327 ns          327 ns      2153121   1.51825k       420.492M/s
bench_ascon::ascon128_aead_decrypt/128/32          465 ns          465 ns      1506197   2.17243k       426.994M/s
bench_ascon::ascon128_aead_decrypt/256/32          742 ns          742 ns       948052    3.4711k       431.975M/s
bench_ascon::ascon128_aead_decrypt/512/32         1293 ns         1293 ns       542854   6.05054k       436.553M/s
bench_ascon::ascon128_aead_decrypt/1024/32        2403 ns         2403 ns       291300   11.2425k       438.117M/s
bench_ascon::ascon128_aead_decrypt/2048/32        4613 ns         4614 ns       150776   21.5645k       439.862M/s
bench_ascon::ascon128_aead_decrypt/4096/32        9105 ns         9106 ns        76494   42.5716k       437.377M/s
bench_ascon::ascon128a_aead_encrypt/64/32          258 ns          258 ns      2716584   1.20461k       533.213M/s
bench_ascon::ascon128a_aead_encrypt/128/32         357 ns          357 ns      1956579   1.67029k       555.384M/s
bench_ascon::ascon128a_aead_encrypt/256/32         559 ns          559 ns      1246840    2.6152k       573.385M/s
bench_ascon::ascon128a_aead_encrypt/512/32         958 ns          958 ns       731293   4.47695k       589.352M/s
bench_ascon::ascon128a_aead_encrypt/1024/32       1756 ns         1756 ns       398751   8.20583k       599.423M/s
bench_ascon::ascon128a_aead_encrypt/2048/32       3351 ns         3351 ns       209033   15.6551k         605.6M/s
bench_ascon::ascon128a_aead_encrypt/4096/32       6543 ns         6543 ns       106969   30.5682k       608.644M/s
bench_ascon::ascon128a_aead_decrypt/64/32          263 ns          263 ns      2656339   1.23105k       521.278M/s
bench_ascon::ascon128a_aead_decrypt/128/32         362 ns          362 ns      1930948   1.69301k       547.622M/s
bench_ascon::ascon128a_aead_decrypt/256/32         565 ns          565 ns      1240548   2.64133k       566.963M/s
bench_ascon::ascon128a_aead_decrypt/512/32         962 ns          962 ns       727397   4.50156k           587M/s
bench_ascon::ascon128a_aead_decrypt/1024/32       1759 ns         1759 ns       397787   8.22899k       598.547M/s
bench_ascon::ascon128a_aead_decrypt/2048/32       3357 ns         3357 ns       208161   15.7044k       604.537M/s
bench_ascon::ascon128a_aead_decrypt/4096/32       6551 ns         6551 ns       106941   30.6299k       607.917M/s
bench_ascon::ascon80pq_aead_encrypt/64/32          323 ns          323 ns      2165692   1.51308k       436.364M/s
bench_ascon::ascon80pq_aead_encrypt/128/32         464 ns          464 ns      1500521   2.17174k       435.285M/s
bench_ascon::ascon80pq_aead_encrypt/256/32         743 ns          743 ns       937770   3.47047k       436.638M/s
bench_ascon::ascon80pq_aead_encrypt/512/32        1296 ns         1296 ns       539620    6.0566k        438.69M/s
bench_ascon::ascon80pq_aead_encrypt/1024/32       2397 ns         2397 ns       293397   11.2013k       440.784M/s
bench_ascon::ascon80pq_aead_encrypt/2048/32       4602 ns         4603 ns       151788    21.501k       441.761M/s
bench_ascon::ascon80pq_aead_encrypt/4096/32       9011 ns         9012 ns        77047   42.1623k       442.344M/s
bench_ascon::ascon80pq_aead_decrypt/64/32          328 ns          328 ns      2133998   1.53446k       430.366M/s
bench_ascon::ascon80pq_aead_decrypt/128/32         468 ns          468 ns      1492700   2.18656k       432.244M/s
bench_ascon::ascon80pq_aead_decrypt/256/32         747 ns          747 ns       933353     3.489k       434.123M/s
bench_ascon::ascon80pq_aead_decrypt/512/32        1307 ns         1307 ns       535323   6.10262k       434.809M/s
bench_ascon::ascon80pq_aead_decrypt/1024/32       2428 ns         2428 ns       288260   11.3401k       435.231M/s
bench_ascon::ascon80pq_aead_decrypt/2048/32       4652 ns         4652 ns       150374   21.7565k       437.041M/s
bench_ascon::ascon80pq_aead_decrypt/4096/32       9173 ns         9174 ns        76951    42.883k       434.538M/s
bench_ascon::ascon_hash/64                         451 ns          451 ns      1548103   2.11325k       202.791M/s
bench_ascon::ascon_hash/128                        729 ns          729 ns       952041   3.41077k       209.223M/s
bench_ascon::ascon_hash/256                       1289 ns         1289 ns       543960   6.01928k       213.098M/s
bench_ascon::ascon_hash/512                       2396 ns         2396 ns       292152   11.2119k       216.519M/s
bench_ascon::ascon_hash/1024                      4631 ns         4631 ns       151737   21.5976k       217.462M/s
bench_ascon::ascon_hash/2048                      9063 ns         9064 ns        77259   42.3806k        218.86M/s
bench_ascon::ascon_hash/4096                     17958 ns        17959 ns        39020   83.9276k       219.213M/s
bench_ascon::ascon_hasha/64                        314 ns          314 ns      2227046   1.46865k       291.208M/s
bench_ascon::ascon_hasha/128                       500 ns          500 ns      1394748   2.33725k       305.227M/s
bench_ascon::ascon_hasha/256                       873 ns          873 ns       795411   4.08544k       314.658M/s
bench_ascon::ascon_hasha/512                      1616 ns         1616 ns       433294   7.55507k       320.992M/s
bench_ascon::ascon_hasha/1024                     3104 ns         3104 ns       225540   14.4955k       324.481M/s
bench_ascon::ascon_hasha/2048                     6075 ns         6076 ns       115282   28.3825k        326.48M/s
bench_ascon::ascon_hasha/4096                    12007 ns        12007 ns        58237   56.1939k       327.862M/s
bench_ascon::ascon_xof/64/32                       452 ns          452 ns      1549048   2.11426k       202.733M/s
bench_ascon::ascon_xof/128/32                      731 ns          731 ns       958643   3.41238k       208.742M/s
bench_ascon::ascon_xof/256/32                     1293 ns         1293 ns       540605   6.02551k       212.479M/s
bench_ascon::ascon_xof/512/32                     2402 ns         2402 ns       291319   11.2182k       215.984M/s
bench_ascon::ascon_xof/1024/32                    4623 ns         4624 ns       151474   21.6013k       217.813M/s
bench_ascon::ascon_xof/2048/32                    9084 ns         9084 ns        77068    42.389k       218.364M/s
bench_ascon::ascon_xof/4096/32                   17972 ns        17973 ns        38829   83.9449k       219.042M/s
bench_ascon::ascon_xof/64/64                       593 ns          593 ns      1168752    2.7706k       205.759M/s
bench_ascon::ascon_xof/128/64                      871 ns          871 ns       804947   4.06871k       210.128M/s
bench_ascon::ascon_xof/256/64                     1430 ns         1430 ns       487395   6.68305k       213.342M/s
bench_ascon::ascon_xof/512/64                     2542 ns         2542 ns       275553   11.8738k       216.055M/s
bench_ascon::ascon_xof/1024/64                    4764 ns         4764 ns       147287   22.2577k       217.786M/s
bench_ascon::ascon_xof/2048/64                    9212 ns         9212 ns        75931   43.0534k       218.645M/s
bench_ascon::ascon_xof/4096/64                   18120 ns        18121 ns        38639   84.6156k       218.935M/s
bench_ascon::ascon_xofa/64/32                      314 ns          314 ns      2228031   1.46952k       291.149M/s
bench_ascon::ascon_xofa/128/32                     500 ns          500 ns      1397655   2.33656k       304.918M/s
bench_ascon::ascon_xofa/256/32                     875 ns          875 ns       796731   4.09088k       313.777M/s
bench_ascon::ascon_xofa/512/32                    1619 ns         1619 ns       429101   7.56292k       320.396M/s
bench_ascon::ascon_xofa/1024/32                   3105 ns         3105 ns       224942   14.5069k       324.359M/s
bench_ascon::ascon_xofa/2048/32                   6075 ns         6076 ns       114979   28.4026k       326.486M/s
bench_ascon::ascon_xofa/4096/32                  12020 ns        12021 ns        58218   56.2184k       327.496M/s
bench_ascon::ascon_xofa/64/64                      409 ns          409 ns      1709537   1.91218k       298.387M/s
bench_ascon::ascon_xofa/128/64                     595 ns          595 ns      1175982   2.78056k       307.962M/s
bench_ascon::ascon_xofa/256/64                     968 ns          968 ns       722659   4.52986k       315.131M/s
bench_ascon::ascon_xofa/512/64                    1711 ns         1711 ns       408828   7.99937k       321.073M/s
bench_ascon::ascon_xofa/1024/64                   3195 ns         3195 ns       219321   14.9411k       324.735M/s
bench_ascon::ascon_xofa/2048/64                   6162 ns         6163 ns       113269   28.8249k       326.835M/s
bench_ascon::ascon_xofa/4096/64                  12117 ns        12117 ns        57598   56.6268k       327.403M/s
bench_ascon::ascon_prf/64/16                       271 ns          271 ns      2583278   1.26501k       338.368M/s
bench_ascon::ascon_prf/128/16                      423 ns          424 ns      1654524   1.98036k       360.292M/s
bench_ascon::ascon_prf/256/16                      729 ns          729 ns       953774   3.41117k       376.721M/s
bench_ascon::ascon_prf/512/16                     1339 ns         1339 ns       520651   6.26242k       387.457M/s
bench_ascon::ascon_prf/1024/16                    2562 ns         2562 ns       273220   11.9852k       393.093M/s
bench_ascon::ascon_prf/2048/16                    5014 ns         5014 ns       139252   23.4305k       395.592M/s
bench_ascon::ascon_prf/4096/16                    9896 ns         9897 ns        70635   46.3205k       397.781M/s
bench_ascon::ascon_prf/64/32                       306 ns          306 ns      2284930   1.43067k       349.231M/s
bench_ascon::ascon_prf/128/32                      459 ns          459 ns      1525866   2.14567k       366.043M/s
bench_ascon::ascon_prf/256/32                      765 ns          765 ns       915462   3.57654k       378.967M/s
bench_ascon::ascon_prf/512/32                     1373 ns         1373 ns       509563   6.42761k       388.848M/s
bench_ascon::ascon_prf/1024/32                    2602 ns         2603 ns       268664   12.1511k       392.824M/s
bench_ascon::ascon_prf/2048/32                    5043 ns         5043 ns       137898   23.5963k        396.35M/s
bench_ascon::ascon_prf/4096/32                    9941 ns         9941 ns        70133   46.4878k       397.544M/s
bench_ascon::ascon_prf/64/64                       377 ns          377 ns      1862168   1.75995k       364.666M/s
bench_ascon::ascon_prf/128/64                      530 ns          530 ns      1319491   2.47522k       374.459M/s
bench_ascon::ascon_prf/256/64                      835 ns          835 ns       836638   3.90722k       383.601M/s
bench_ascon::ascon_prf/512/64                     1445 ns         1445 ns       482626   6.75686k       390.669M/s
bench_ascon::ascon_prf/1024/64                    2669 ns         2669 ns       262406   12.4797k       394.452M/s
bench_ascon::ascon_prf/2048/64                    5132 ns         5132 ns       136114    23.925k       395.409M/s
bench_ascon::ascon_prf/4096/64                   10046 ns        10046 ns        69813   46.8158k       396.437M/s
bench_ascon::ascon_mac_authenticate/64             271 ns          271 ns      2581701   1.26413k       337.772M/s
bench_ascon::ascon_mac_authenticate/128            424 ns          424 ns      1650231   1.97971k       359.923M/s
bench_ascon::ascon_mac_authenticate/256            730 ns          730 ns       957166   3.41051k       376.237M/s
bench_ascon::ascon_mac_authenticate/512           1342 ns         1342 ns       519974   6.26263k       386.582M/s
bench_ascon::ascon_mac_authenticate/1024          2564 ns         2564 ns       272891    11.986k       392.701M/s
bench_ascon::ascon_mac_authenticate/2048          5015 ns         5015 ns       139347   23.4611k       395.503M/s
bench_ascon::ascon_mac_authenticate/4096          9910 ns         9910 ns        70722   46.3526k       397.256M/s
bench_ascon::ascon_mac_verify/64                   271 ns          271 ns      2580421   1.26555k       394.711M/s
bench_ascon::ascon_mac_verify/128                  424 ns          424 ns      1650906   1.98103k        396.02M/s
bench_ascon::ascon_mac_verify/256                  729 ns          729 ns       954347   3.41159k        397.49M/s
bench_ascon::ascon_mac_verify/512                 1340 ns         1340 ns       521923   6.26404k       398.628M/s
bench_ascon::ascon_mac_verify/1024                2564 ns         2564 ns       273091    11.987k       398.786M/s
bench_ascon::ascon_mac_verify/2048                5010 ns         5010 ns       139745   23.4324k       398.987M/s
bench_ascon::ascon_mac_verify/4096                9905 ns         9905 ns        70736   46.3237k       398.987M/s
bench_ascon::ascon_prfs_authenticate/1            45.1 ns         45.1 ns     15520918    210.995       697.183M/s
bench_ascon::ascon_prfs_authenticate/2            45.1 ns         45.1 ns     15506284    211.019           719M/s
bench_ascon::ascon_prfs_authenticate/4            45.1 ns         45.1 ns     15499648    211.168       761.204M/s
bench_ascon::ascon_prfs_authenticate/8            35.4 ns         35.4 ns     19755866    165.875       1076.84M/s
bench_ascon::ascon_prfs_authenticate/16           35.5 ns         35.5 ns     19670459    166.155       1.25965G/s
bench_ascon::ascon_prfs_verify/1                  52.2 ns         52.2 ns     13300060    244.643       894.594M/s
bench_ascon::ascon_prfs_verify/2                  52.2 ns         52.2 ns     13391962    244.035       913.722M/s
bench_ascon::ascon_prfs_verify/4                  52.0 ns         52.0 ns     13418738    243.239       954.072M/s
bench_ascon::ascon_prfs_verify/8                  40.2 ns         40.2 ns     17430260    187.857       1.29757G/s
bench_ascon::ascon_prfs_verify/16                 40.3 ns         40.3 ns     17391696    188.446       1.48045G/s
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
