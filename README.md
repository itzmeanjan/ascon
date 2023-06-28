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
2023-06-28T18:37:47+04:00
Running ./benchmarks/perf.out
Run on (16 X 748.528 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.31, 0.46, 0.47
***WARNING*** There are 88 benchmarks with threads and 1 performance counters were requested. Beware counters will reflect the combined usage across all threads.
------------------------------------------------------------------------------------------------------------------
Benchmark                                            Time             CPU   Iterations     CYCLES bytes_per_second
------------------------------------------------------------------------------------------------------------------
bench_ascon::ascon_permutation<1>                 3.30 ns         3.30 ns    209265853    15.4199       11.2911G/s
bench_ascon::ascon_permutation<6>                 21.2 ns         21.1 ns     38590942    84.9286       1.76874G/s
bench_ascon::ascon_permutation<8>                 24.0 ns         24.0 ns     29205245    111.697       1.55503G/s
bench_ascon::ascon_permutation<12>                35.7 ns         35.7 ns     19617087    166.753       1069.85M/s
bench_ascon::ascon128_aead_encrypt/64/32           329 ns          329 ns      2130715   1.53746k       278.569M/s
bench_ascon::ascon128_aead_encrypt/128/32          479 ns          479 ns      1463059   2.23856k       318.645M/s
bench_ascon::ascon128_aead_encrypt/256/32          782 ns          782 ns       892240   3.65307k       351.439M/s
bench_ascon::ascon128_aead_encrypt/512/32         1386 ns         1384 ns       506519   6.46115k       374.914M/s
bench_ascon::ascon128_aead_encrypt/1024/32        2590 ns         2587 ns       270565   12.0971k       389.298M/s
bench_ascon::ascon128_aead_encrypt/2048/32        5002 ns         5002 ns       140097   23.3638k        396.56M/s
bench_ascon::ascon128_aead_encrypt/4096/32        9825 ns         9826 ns        71169    45.899k       400.664M/s
bench_ascon::ascon128_aead_decrypt/64/32           337 ns          337 ns      2075465   1.57507k       271.314M/s
bench_ascon::ascon128_aead_decrypt/128/32          488 ns          489 ns      1431410   2.27916k       312.355M/s
bench_ascon::ascon128_aead_decrypt/256/32          788 ns          788 ns       887833   3.67743k        348.66M/s
bench_ascon::ascon128_aead_decrypt/512/32         1393 ns         1393 ns       502065   6.50589k       372.442M/s
bench_ascon::ascon128_aead_decrypt/1024/32        2599 ns         2599 ns       268224   12.1429k       387.494M/s
bench_ascon::ascon128_aead_decrypt/2048/32        5010 ns         5011 ns       139430   23.3981k       395.891M/s
bench_ascon::ascon128_aead_decrypt/4096/32        9864 ns         9864 ns        70540   46.0962k       399.099M/s
bench_ascon::ascon128a_aead_encrypt/64/32          252 ns          252 ns      2770854   1.17931k       362.921M/s
bench_ascon::ascon128a_aead_encrypt/128/32         351 ns          351 ns      1995929    1.6409k       434.802M/s
bench_ascon::ascon128a_aead_encrypt/256/32         550 ns          550 ns      1270854   2.57286k       499.047M/s
bench_ascon::ascon128a_aead_encrypt/512/32         943 ns          943 ns       742319   4.41044k        550.01M/s
bench_ascon::ascon128a_aead_encrypt/1024/32       1726 ns         1726 ns       404756   8.07572k       583.478M/s
bench_ascon::ascon128a_aead_encrypt/2048/32       3299 ns         3299 ns       211635    15.406k       601.232M/s
bench_ascon::ascon128a_aead_encrypt/4096/32       6459 ns         6459 ns       107996   30.1657k       609.515M/s
bench_ascon::ascon128a_aead_decrypt/64/32          262 ns          262 ns      2675470   1.22079k       349.873M/s
bench_ascon::ascon128a_aead_decrypt/128/32         359 ns          359 ns      1952344    1.6759k       424.965M/s
bench_ascon::ascon128a_aead_decrypt/256/32         555 ns          555 ns      1257857   2.59385k       494.679M/s
bench_ascon::ascon128a_aead_decrypt/512/32         943 ns          943 ns       739158   4.40649k       550.338M/s
bench_ascon::ascon128a_aead_decrypt/1024/32       1720 ns         1720 ns       407240   8.04157k       585.409M/s
bench_ascon::ascon128a_aead_decrypt/2048/32       3278 ns         3278 ns       213809   15.3244k       605.069M/s
bench_ascon::ascon128a_aead_decrypt/4096/32       6399 ns         6399 ns       109292   29.8603k       615.207M/s
bench_ascon::ascon80pq_aead_encrypt/64/32          331 ns          331 ns      2108358   1.54314k       276.773M/s
bench_ascon::ascon80pq_aead_encrypt/128/32         482 ns          482 ns      1452205   2.25376k       316.635M/s
bench_ascon::ascon80pq_aead_encrypt/256/32         787 ns          787 ns       888684   3.67473k       348.894M/s
bench_ascon::ascon80pq_aead_encrypt/512/32        1394 ns         1394 ns       498284   6.51729k       372.219M/s
bench_ascon::ascon80pq_aead_encrypt/1024/32       2609 ns         2609 ns       267599   12.2035k       385.959M/s
bench_ascon::ascon80pq_aead_encrypt/2048/32       5047 ns         5047 ns       138273   23.5793k       393.044M/s
bench_ascon::ascon80pq_aead_encrypt/4096/32       9897 ns         9897 ns        70600   46.3265k       397.774M/s
bench_ascon::ascon80pq_aead_decrypt/64/32          341 ns          341 ns      2056426   1.59296k       268.412M/s
bench_ascon::ascon80pq_aead_decrypt/128/32         491 ns          491 ns      1423225    2.2986k       310.765M/s
bench_ascon::ascon80pq_aead_decrypt/256/32         796 ns          796 ns       879974   3.71433k       345.241M/s
bench_ascon::ascon80pq_aead_decrypt/512/32        1399 ns         1399 ns       499939   6.54346k       370.782M/s
bench_ascon::ascon80pq_aead_decrypt/1024/32       2610 ns         2610 ns       268172   12.2077k       385.835M/s
bench_ascon::ascon80pq_aead_decrypt/2048/32       5036 ns         5037 ns       138659   23.5481k       393.833M/s
bench_ascon::ascon80pq_aead_decrypt/4096/32       9892 ns         9892 ns        70909   46.2067k       397.966M/s
bench_ascon::ascon_hash/64                         464 ns          464 ns      1507515   2.16618k       197.327M/s
bench_ascon::ascon_hash/128                        747 ns          747 ns       935030   3.49586k        204.19M/s
bench_ascon::ascon_hash/256                       1320 ns         1320 ns       528630   6.16136k       208.033M/s
bench_ascon::ascon_hash/512                       2461 ns         2461 ns       284297   11.4786k       210.806M/s
bench_ascon::ascon_hash/1024                      4728 ns         4728 ns       148016   22.1132k       212.993M/s
bench_ascon::ascon_hash/2048                      9275 ns         9275 ns        75502   43.4058k       213.864M/s
bench_ascon::ascon_hash/4096                     18377 ns        18378 ns        38056    85.966k        214.21M/s
bench_ascon::ascon_hasha/64                        322 ns          322 ns      2167828   1.50829k       284.025M/s
bench_ascon::ascon_hasha/128                       512 ns          512 ns      1356473   2.39766k       297.917M/s
bench_ascon::ascon_hasha/256                       895 ns          895 ns       783424   4.18081k       306.795M/s
bench_ascon::ascon_hasha/512                      1656 ns         1656 ns       421737   7.73784k       313.303M/s
bench_ascon::ascon_hasha/1024                     3178 ns         3178 ns       219384   14.8521k       316.923M/s
bench_ascon::ascon_hasha/2048                     6238 ns         6239 ns       112134   29.0915k       317.967M/s
bench_ascon::ascon_hasha/4096                    12311 ns        12311 ns        56704   57.5662k       319.764M/s
bench_ascon::ascon_xof/64/32                       463 ns          463 ns      1512677   2.16201k       197.547M/s
bench_ascon::ascon_xof/128/32                      748 ns          748 ns       933961   3.49233k       204.082M/s
bench_ascon::ascon_xof/256/32                     1318 ns         1318 ns       531401   6.16048k       208.419M/s
bench_ascon::ascon_xof/512/32                     2461 ns         2461 ns       284469   11.4795k       210.821M/s
bench_ascon::ascon_xof/1024/32                    4732 ns         4732 ns       147986   22.1131k       212.839M/s
bench_ascon::ascon_xof/2048/32                    9290 ns         9290 ns        75267   43.4138k       213.529M/s
bench_ascon::ascon_xof/4096/32                   18422 ns        18423 ns        37882   85.9766k       213.686M/s
bench_ascon::ascon_xof/64/64                       609 ns          609 ns      1152785   2.84214k       200.402M/s
bench_ascon::ascon_xof/128/64                      894 ns          894 ns       782804   4.17494k       204.855M/s
bench_ascon::ascon_xof/256/64                     1463 ns         1463 ns       477373    6.8374k       208.613M/s
bench_ascon::ascon_xof/512/64                     2600 ns         2600 ns       268288   12.1539k       211.241M/s
bench_ascon::ascon_xof/1024/64                    4879 ns         4880 ns       143428   22.7872k        212.64M/s
bench_ascon::ascon_xof/2048/64                    9451 ns         9452 ns        74152   44.0864k       213.102M/s
bench_ascon::ascon_xof/4096/64                   18543 ns        18543 ns        37625   86.6463k       213.945M/s
bench_ascon::ascon_xofa/64/32                      324 ns          324 ns      2160976   1.51355k       282.787M/s
bench_ascon::ascon_xofa/128/32                     516 ns          516 ns      1349746   2.41345k         295.8M/s
bench_ascon::ascon_xofa/256/32                     904 ns          904 ns       770767   4.22086k       303.916M/s
bench_ascon::ascon_xofa/512/32                    1672 ns         1672 ns       416661   7.81119k       310.244M/s
bench_ascon::ascon_xofa/1024/32                   3212 ns         3212 ns       218105   15.0086k       313.545M/s
bench_ascon::ascon_xofa/2048/32                   6307 ns         6308 ns       110947    29.397k        314.48M/s
bench_ascon::ascon_xofa/4096/32                  12473 ns        12474 ns        56135    58.203k       315.601M/s
bench_ascon::ascon_xofa/64/64                      421 ns          421 ns      1660744   1.96802k       289.738M/s
bench_ascon::ascon_xofa/128/64                     614 ns          614 ns      1133091   2.87129k       298.075M/s
bench_ascon::ascon_xofa/256/64                     998 ns          998 ns       699561   4.66352k       305.795M/s
bench_ascon::ascon_xofa/512/64                    1766 ns         1767 ns       396421   8.25696k        310.96M/s
bench_ascon::ascon_xofa/1024/64                   3306 ns         3306 ns       211937   15.4554k       313.886M/s
bench_ascon::ascon_xofa/2048/64                   6385 ns         6385 ns       109244   29.8505k       315.436M/s
bench_ascon::ascon_xofa/4096/64                  12554 ns        12554 ns        55597   58.6589k       316.018M/s
```

### On 12th Gen Intel(R) Core(TM) i7-1260P ( Compiled with Clang )

```bash
2023-06-28T18:40:49+04:00
Running ./benchmarks/perf.out
Run on (16 X 3719.67 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.37, 0.50, 0.49
***WARNING*** There are 88 benchmarks with threads and 1 performance counters were requested. Beware counters will reflect the combined usage across all threads.
------------------------------------------------------------------------------------------------------------------
Benchmark                                            Time             CPU   Iterations     CYCLES bytes_per_second
------------------------------------------------------------------------------------------------------------------
bench_ascon::ascon_permutation<1>                 2.91 ns         2.91 ns    241272843    13.4897       12.7818G/s
bench_ascon::ascon_permutation<6>                 17.0 ns         17.0 ns     41232506    79.2334       2.19478G/s
bench_ascon::ascon_permutation<8>                 23.2 ns         23.2 ns     29857652    108.366         1.606G/s
bench_ascon::ascon_permutation<12>                34.6 ns         34.6 ns     20223885    161.914       1102.84M/s
bench_ascon::ascon128_aead_encrypt/64/32           323 ns          323 ns      2169526   1.51223k       283.289M/s
bench_ascon::ascon128_aead_encrypt/128/32          462 ns          462 ns      1519121   2.15733k       330.024M/s
bench_ascon::ascon128_aead_encrypt/256/32          739 ns          739 ns       938840   3.44119k       371.453M/s
bench_ascon::ascon128_aead_encrypt/512/32         1294 ns         1294 ns       539515    6.0583k        400.93M/s
bench_ascon::ascon128_aead_encrypt/1024/32        2405 ns         2405 ns       290579   11.2618k       418.689M/s
bench_ascon::ascon128_aead_encrypt/2048/32        4695 ns         4695 ns       150958   21.7284k       422.498M/s
bench_ascon::ascon128_aead_encrypt/4096/32        9239 ns         9238 ns        76897   42.6437k       426.156M/s
bench_ascon::ascon128_aead_decrypt/64/32           327 ns          327 ns      2138406    1.5312k       279.927M/s
bench_ascon::ascon128_aead_decrypt/128/32          466 ns          466 ns      1503765   2.17928k       327.687M/s
bench_ascon::ascon128_aead_decrypt/256/32          740 ns          740 ns       941129   3.46458k       371.001M/s
bench_ascon::ascon128_aead_decrypt/512/32         1295 ns         1295 ns       542187   6.05414k       400.718M/s
bench_ascon::ascon128_aead_decrypt/1024/32        2435 ns         2435 ns       287396   11.3786k       413.545M/s
bench_ascon::ascon128_aead_decrypt/2048/32        4664 ns         4664 ns       149556   21.7874k       425.337M/s
bench_ascon::ascon128_aead_decrypt/4096/32        9147 ns         9147 ns        76072   42.7547k         430.4M/s
bench_ascon::ascon128a_aead_encrypt/64/32          258 ns          258 ns      2718991   1.20393k       355.315M/s
bench_ascon::ascon128a_aead_encrypt/128/32         357 ns          357 ns      1955892   1.66971k       427.062M/s
bench_ascon::ascon128a_aead_encrypt/256/32         560 ns          560 ns      1246868   2.61715k       490.771M/s
bench_ascon::ascon128a_aead_encrypt/512/32         958 ns          958 ns       731357   4.48161k        541.32M/s
bench_ascon::ascon128a_aead_encrypt/1024/32       1756 ns         1756 ns       397775   8.21275k       573.448M/s
bench_ascon::ascon128a_aead_encrypt/2048/32       3353 ns         3353 ns       208865   15.6728k       591.624M/s
bench_ascon::ascon128a_aead_encrypt/4096/32       6549 ns         6549 ns       106795   30.6159k       601.111M/s
bench_ascon::ascon128a_aead_decrypt/64/32          263 ns          263 ns      2657789   1.23136k       347.555M/s
bench_ascon::ascon128a_aead_decrypt/128/32         362 ns          362 ns      1932129    1.6929k       421.064M/s
bench_ascon::ascon128a_aead_decrypt/256/32         566 ns          566 ns      1235071   2.64282k       485.112M/s
bench_ascon::ascon128a_aead_decrypt/512/32         964 ns          963 ns       726237   4.50319k       538.453M/s
bench_ascon::ascon128a_aead_decrypt/1024/32       1763 ns         1763 ns       397024   8.23986k       571.138M/s
bench_ascon::ascon128a_aead_decrypt/2048/32       3355 ns         3355 ns       208788   15.6724k       591.278M/s
bench_ascon::ascon128a_aead_decrypt/4096/32       6556 ns         6556 ns       106624   30.6029k       600.484M/s
bench_ascon::ascon80pq_aead_encrypt/64/32          323 ns          323 ns      2157938   1.50977k        283.32M/s
bench_ascon::ascon80pq_aead_encrypt/128/32         463 ns          463 ns      1506918   2.16009k       329.765M/s
bench_ascon::ascon80pq_aead_encrypt/256/32         740 ns          740 ns       945280   3.46144k       371.369M/s
bench_ascon::ascon80pq_aead_encrypt/512/32        1292 ns         1292 ns       541571   6.04068k       401.555M/s
bench_ascon::ascon80pq_aead_encrypt/1024/32       2396 ns         2396 ns       293033   11.1976k       420.386M/s
bench_ascon::ascon80pq_aead_encrypt/2048/32       4600 ns         4600 ns       152036   21.5107k       431.235M/s
bench_ascon::ascon80pq_aead_encrypt/4096/32       9016 ns         9016 ns        77568   42.2031k       436.662M/s
bench_ascon::ascon80pq_aead_decrypt/64/32          326 ns          326 ns      2142808   1.52702k       280.628M/s
bench_ascon::ascon80pq_aead_decrypt/128/32         466 ns          466 ns      1504268   2.18028k       327.613M/s
bench_ascon::ascon80pq_aead_decrypt/256/32         743 ns          743 ns       940211   3.47885k       369.609M/s
bench_ascon::ascon80pq_aead_decrypt/512/32        1297 ns         1297 ns       538455   6.06979k       400.097M/s
bench_ascon::ascon80pq_aead_decrypt/1024/32       2414 ns         2414 ns       289715   11.2888k       417.213M/s
bench_ascon::ascon80pq_aead_decrypt/2048/32       4647 ns         4647 ns       150831   21.6877k       426.891M/s
bench_ascon::ascon80pq_aead_decrypt/4096/32       9100 ns         9099 ns        76742   42.5024k        432.65M/s
bench_ascon::ascon_hash/64                         452 ns          452 ns      1550611   2.11279k       202.672M/s
bench_ascon::ascon_hash/128                        729 ns          729 ns       957476   3.41091k        209.19M/s
bench_ascon::ascon_hash/256                       1288 ns         1288 ns       543849   6.01886k       213.213M/s
bench_ascon::ascon_hash/512                       2398 ns         2398 ns       291814   11.2125k       216.352M/s
bench_ascon::ascon_hash/1024                      4623 ns         4623 ns       151425   21.5036k       217.825M/s
bench_ascon::ascon_hash/2048                      9059 ns         9059 ns        76924   42.3894k       218.961M/s
bench_ascon::ascon_hash/4096                     17940 ns        17939 ns        38915     83.97k       219.452M/s
bench_ascon::ascon_hasha/64                        314 ns          314 ns      2227535   1.46935k         291.9M/s
bench_ascon::ascon_hasha/128                       500 ns          500 ns      1398426   2.33783k       305.416M/s
bench_ascon::ascon_hasha/256                       874 ns          874 ns       799637   4.08801k       314.161M/s
bench_ascon::ascon_hasha/512                      1626 ns         1626 ns       432900   7.56285k       319.083M/s
bench_ascon::ascon_hasha/1024                     3100 ns         3100 ns       225918   14.5121k       324.881M/s
bench_ascon::ascon_hasha/2048                     6071 ns         6070 ns       115373   28.4156k       326.768M/s
bench_ascon::ascon_hasha/4096                    12013 ns        12014 ns        58271    56.213k       327.689M/s
bench_ascon::ascon_xof/64/32                       452 ns          452 ns      1549974   2.11461k       202.659M/s
bench_ascon::ascon_xof/128/32                      730 ns          730 ns       958803    3.4127k       209.062M/s
bench_ascon::ascon_xof/256/32                     1291 ns         1291 ns       542125   6.02888k       212.822M/s
bench_ascon::ascon_xof/512/32                     2404 ns         2404 ns       291007   11.2218k       215.831M/s
bench_ascon::ascon_xof/1024/32                    4623 ns         4623 ns       151276   21.6068k       217.841M/s
bench_ascon::ascon_xof/2048/32                    9068 ns         9068 ns        77206   42.3979k       218.762M/s
bench_ascon::ascon_xof/4096/32                   17960 ns        17959 ns        38958   83.9694k       219.203M/s
bench_ascon::ascon_xof/64/64                       592 ns          592 ns      1180335   2.77123k       206.056M/s
bench_ascon::ascon_xof/128/64                      870 ns          870 ns       805718    4.0697k       210.494M/s
bench_ascon::ascon_xof/256/64                     1430 ns         1430 ns       489704   6.68707k       213.403M/s
bench_ascon::ascon_xof/512/64                     2540 ns         2540 ns       274883   11.8787k        216.23M/s
bench_ascon::ascon_xof/1024/64                    4763 ns         4763 ns       146932   22.2644k       217.859M/s
bench_ascon::ascon_xof/2048/64                    9201 ns         9201 ns        76088   43.0592k       218.909M/s
bench_ascon::ascon_xof/4096/64                   18077 ns        18077 ns        38704   84.6238k       219.463M/s
bench_ascon::ascon_xofa/64/32                      314 ns          314 ns      2229133   1.46969k       291.488M/s
bench_ascon::ascon_xofa/128/32                     499 ns          499 ns      1397770   2.33665k       305.699M/s
bench_ascon::ascon_xofa/256/32                     875 ns          875 ns       800826   4.09222k       313.976M/s
bench_ascon::ascon_xofa/512/32                    1615 ns         1615 ns       431704   7.56394k       321.277M/s
bench_ascon::ascon_xofa/1024/32                   3100 ns         3100 ns       225998   14.5129k       324.875M/s
bench_ascon::ascon_xofa/2048/32                   6075 ns         6074 ns       115127   28.4081k       326.601M/s
bench_ascon::ascon_xofa/4096/32                  12014 ns        12013 ns        58173   56.2371k       327.718M/s
bench_ascon::ascon_xofa/64/64                      409 ns          409 ns      1713149   1.91257k       298.716M/s
bench_ascon::ascon_xofa/128/64                     594 ns          594 ns      1177979   2.78135k        308.02M/s
bench_ascon::ascon_xofa/256/64                     969 ns          969 ns       722567   4.52995k        315.03M/s
bench_ascon::ascon_xofa/512/64                    1713 ns         1713 ns       406159    7.9997k       320.655M/s
bench_ascon::ascon_xofa/1024/64                   3195 ns         3195 ns       219235   14.9407k       324.783M/s
bench_ascon::ascon_xofa/2048/64                   6173 ns         6173 ns       113310   28.8297k       326.305M/s
bench_ascon::ascon_xofa/4096/64                  12124 ns        12123 ns        57816   56.6443k       327.248M/s
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
