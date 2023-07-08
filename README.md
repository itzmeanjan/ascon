> **Warning** **This implementation attempts to provide you with constant-timeness though it is not yet audited. If you consider using it in production, be careful !**

# ascon
Accelerated Ascon Cipher Suite: Light Weight Cryptography

## Overview

`ascon` cipher suite is selected by NIST as winner of **L**ight **W**eight **C**ryptography standardization effort and it's being standardized right now. Find more details @ https://www.nist.gov/news-events/news/2023/02/nist-selects-lightweight-cryptography-algorithms-protect-small-devices.

Following functionalities, from Ascon light weight cryptography suite, are implemented in this zero-dependency, header-only C++ library.

Scheme | What does it do ? | Comments
:-- | :-: | --:
Ascon-128 AEAD | Given 16B key, 16B nonce, N -bytes associated data and M -bytes plain text, encryption routine can be used for computing 16B authentication tag and M -bytes cipher text. While decryption algorithm can be used for decrypting cipher text, producing equal length plain text, given key, nonce, associated data ( if any ) and authentication tag. It only releases plain text if tag can be verified, in constant-time. | Primary AEAD candidate.
Ascon-128A AEAD | Same as above. | Secondary AEAD candidate, though executes faster due to higher RATE.
Ascon-80pq AEAD | Same as above, only difference is that it uses 20 -bytes secret key. | Post-quantum AEAD candidate, because it has key length of 160 -bits.
Ascon-Hash | Given N -bytes input message, hasher can be used for producing 32 -bytes digest. | Primary hash function candidate.
Ascon-HashA | Same as above. | Secondary hash function candidate, faster because it has smaller number of permutation rounds.
Ascon-XOF | Given N -bytes input message, hasher can be used for squeezing arbitrart many digest bytes. | Primary extendable output function candidate.
Ascon-XOFA | Same as above. | Secondary extendable output function candidate, faster because it has smaller number of permutation rounds.
Ascon-PRF | Given 16 -bytes key and N -bytes input message, this routine can be used for squeezing arbitrary many tag bytes. | Pseudo-random function for arbitrary length messages, proposed in https://ia.cr/2021/1574.
Ascon-MAC | Given 16 -bytes key and N -bytes input message, this routine can be used for computing 16 -bytes tag, during authentication phase. While during verification, received tag can be verified by locally computing 16 -bytes tag and comparing it constant-time. | Messaege authentication code function proposed in https://ia.cr/2021/1574.
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
# assuming you've already cloned `ascon`
git submodule update --init
```

- For benchmarking this library implementation, you need to have `google-benchmark` header and library installed --- ensure it's globally installed; follow [this](https://github.com/google/benchmark/#installation) guide.
- If you are on a machine running GNU/Linux kernel and you want to obtain following (see list below), for Ascon based constructions, you should consider building google-benchmark library with libPFM support, following [this](https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7) step-by-step guide. Find more about libPFM @ https://perfmon2.sourceforge.net.
    1) CPU cycle count.
    2) Retired instruction count.
    3) Cycles/ byte ( aka cpb ).
    4) Retired instructions/ cycle ( aka ipc ).

## Testing

For ensuring that Ascon cipher suite is implemented correctly and it's conformant with the specification.

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
[test] Ascon-PRF
[test] Ascon-MAC
[test] Ascon-PRFShort
```

## Benchmarking

For benchmarking routines of Ascon lightweight cipher suite, using `google-benchmark` library, while targeting CPU systems, with variable length input data, one may issue

```bash
make benchmark # If you haven't built google-benchmark library with libPFM support.
make perf      # If you have built google-benchmark library with libPFM support.
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

> **Note** `make perf` - was issued when collecting following benchmarks. Notice, columns such as *cycles*, *cycles/ byte*, *instructions* and *instructions/ cycle*. Follow [this](https://github.com/google/benchmark/blob/main/docs/perf_counters.md) for more details.

### On 12th Gen Intel(R) Core(TM) i7-1260P ( Compiled with GCC )

```bash
2023-07-07T22:49:23+04:00
Running ./benchmarks/perf.out
Run on (16 X 4615.79 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.39, 0.67, 0.63
***WARNING*** There are 133 benchmarks with threads and 2 performance counters were requested. Beware counters will reflect the combined usage across all threads.
----------------------------------------------------------------------------------------------------------------------------------------------------------------
Benchmark                                            Time             CPU   Iterations     CYCLES CYCLES/ BYTE INSTRUCTIONS INSTRUCTIONS/ CYCLE bytes_per_second
----------------------------------------------------------------------------------------------------------------------------------------------------------------
bench_ascon::ascon_permutation<1>                 3.20 ns         3.20 ns    218816922    14.9778     0.374444           56             3.73888       11.6286G/s
bench_ascon::ascon_permutation<6>                 18.1 ns         18.1 ns     38433810    84.9823      2.12456          262               3.083       2.05273G/s
bench_ascon::ascon_permutation<8>                 23.9 ns         23.9 ns     29282639    111.702      2.79254          375             3.35716       1.55858G/s
bench_ascon::ascon_permutation<12>                35.7 ns         35.8 ns     19629371    167.037      4.17594          555             3.32261       1066.99M/s
bench_ascon::ascon128_aead_encrypt/64/32           345 ns          345 ns      2031929   1.60593k      16.7284        4.86k             3.02628       265.077M/s
bench_ascon::ascon128_aead_encrypt/128/32          504 ns          504 ns      1383903   2.35378k      14.7111       6.996k             2.97224       302.785M/s
bench_ascon::ascon128_aead_encrypt/256/32          815 ns          815 ns       861482   3.80511k      13.2122      11.268k             2.96128       336.828M/s
bench_ascon::ascon128_aead_encrypt/512/32         1423 ns         1424 ns       494001   6.63486k      12.1964      19.812k             2.98605       364.364M/s
bench_ascon::ascon128_aead_encrypt/1024/32        2620 ns         2620 ns       267068   12.2173k      11.5694        36.9k              3.0203       384.344M/s
bench_ascon::ascon128_aead_encrypt/2048/32        4967 ns         4968 ns       140790   23.1964k      11.1521      71.076k             3.06409        399.28M/s
bench_ascon::ascon128_aead_encrypt/4096/32        9752 ns         9755 ns        71674   45.5386k      11.0316     139.428k             3.06175       403.581M/s
bench_ascon::ascon128_aead_decrypt/64/32           341 ns          341 ns      2058767   1.59074k      16.5702       4.994k             3.13942       268.551M/s
bench_ascon::ascon128_aead_decrypt/128/32          492 ns          492 ns      1420668   2.29711k      14.3569        7.06k             3.07343       309.849M/s
bench_ascon::ascon128_aead_decrypt/256/32          797 ns          797 ns       876183   3.72137k      12.9214      11.192k              3.0075       344.477M/s
bench_ascon::ascon128_aead_decrypt/512/32         1405 ns         1405 ns       496682   6.57127k      12.0795      19.456k             2.96077       369.124M/s
bench_ascon::ascon128_aead_decrypt/1024/32        2620 ns         2620 ns       267370   12.2374k      11.5884      35.984k             2.94051       384.366M/s
bench_ascon::ascon128_aead_decrypt/2048/32        5057 ns         5058 ns       137817   23.6617k      11.3758       69.04k              2.9178       392.156M/s
bench_ascon::ascon128_aead_decrypt/4096/32        9937 ns         9939 ns        70658   46.3439k      11.2267     135.152k             2.91629       396.095M/s
bench_ascon::ascon128a_aead_encrypt/64/32          251 ns          251 ns      2790841   1.17255k      12.2141       4.045k             3.44975        364.66M/s
bench_ascon::ascon128a_aead_encrypt/128/32         350 ns          350 ns      1999337   1.63072k       10.192       5.661k             3.47147       436.074M/s
bench_ascon::ascon128a_aead_encrypt/256/32         548 ns          548 ns      1275016   2.56019k      8.88953       8.893k             3.47358       500.807M/s
bench_ascon::ascon128a_aead_encrypt/512/32         939 ns          939 ns       742761   4.39348k      8.07625      15.357k             3.49541       552.241M/s
bench_ascon::ascon128a_aead_encrypt/1024/32       1720 ns         1721 ns       407189   8.05173k      7.62474      28.285k             3.51291       585.328M/s
bench_ascon::ascon128a_aead_encrypt/2048/32       3292 ns         3293 ns       212578   15.3893k       7.3987      54.141k             3.51809       602.464M/s
bench_ascon::ascon128a_aead_encrypt/4096/32       6450 ns         6451 ns       107642   30.0387k      7.27681     105.853k             3.52389       610.278M/s
bench_ascon::ascon128a_aead_decrypt/64/32          280 ns          280 ns      2500044   1.30864k      13.6316       4.418k             3.37603       326.905M/s
bench_ascon::ascon128a_aead_decrypt/128/32         380 ns          380 ns      1838332   1.77767k      11.1104       6.048k              3.4022       401.382M/s
bench_ascon::ascon128a_aead_decrypt/256/32         569 ns          569 ns      1222853   2.66231k      9.24412       9.308k             3.49622       482.501M/s
bench_ascon::ascon128a_aead_decrypt/512/32         961 ns          962 ns       729184   4.48923k      8.25227      15.828k             3.52577       539.559M/s
bench_ascon::ascon128a_aead_decrypt/1024/32       1745 ns         1746 ns       400415   8.14259k      7.71079      28.868k             3.54531       576.917M/s
bench_ascon::ascon128a_aead_decrypt/2048/32       3301 ns         3302 ns       212053   15.4399k      7.42302      54.948k             3.55884       600.754M/s
bench_ascon::ascon128a_aead_decrypt/4096/32       6422 ns         6423 ns       108839   30.0751k      7.28562     107.108k             3.56136       612.874M/s
bench_ascon::ascon80pq_aead_encrypt/64/32          344 ns          344 ns      2032583   1.60889k      16.7593       4.878k              3.0319       266.303M/s
bench_ascon::ascon80pq_aead_encrypt/128/32         506 ns          506 ns      1376481   2.36217k      14.7636       7.014k             2.96931       301.617M/s
bench_ascon::ascon80pq_aead_encrypt/256/32         817 ns          817 ns       850423    3.8148k      13.2458      11.286k             2.95848       336.115M/s
bench_ascon::ascon80pq_aead_encrypt/512/32        1425 ns         1425 ns       491723   6.65412k      12.2318       19.83k             2.98011       363.993M/s
bench_ascon::ascon80pq_aead_encrypt/1024/32       2625 ns         2625 ns       265937    12.253k      11.6033      36.918k             3.01297       383.585M/s
bench_ascon::ascon80pq_aead_encrypt/2048/32       5009 ns         5010 ns       100000   23.3535k      11.2276      71.094k             3.04426       395.961M/s
bench_ascon::ascon80pq_aead_encrypt/4096/32       9789 ns         9790 ns        70667   45.7387k      11.0801     139.446k             3.04876       402.104M/s
bench_ascon::ascon80pq_aead_decrypt/64/32          342 ns          342 ns      2048954    1.5997k      16.6635       5.018k             3.13684       267.378M/s
bench_ascon::ascon80pq_aead_decrypt/128/32         493 ns          493 ns      1422139   2.30619k      14.4137       7.084k             3.07173       309.533M/s
bench_ascon::ascon80pq_aead_decrypt/256/32         797 ns          797 ns       878640    3.7249k      12.9337      11.216k             3.01109       344.644M/s
bench_ascon::ascon80pq_aead_decrypt/512/32        1405 ns         1405 ns       497324   6.56554k       12.069       19.48k             2.96701       369.201M/s
bench_ascon::ascon80pq_aead_decrypt/1024/32       2621 ns         2622 ns       267284   12.2229k      11.5747      36.008k             2.94594       384.099M/s
bench_ascon::ascon80pq_aead_decrypt/2048/32       5060 ns         5061 ns       138070   23.5898k      11.3412      69.064k             2.92771       391.975M/s
bench_ascon::ascon80pq_aead_decrypt/4096/32       9911 ns         9913 ns        70534   46.2924k      11.2142     135.176k             2.92005       397.124M/s
bench_ascon::ascon_hash/64                         464 ns          464 ns      1507356   2.16544k      22.5566       7.061k             3.26077       197.456M/s
bench_ascon::ascon_hash/128                        749 ns          749 ns       932386   3.49583k      21.8489      11.309k               3.235       203.722M/s
bench_ascon::ascon_hash/256                       1319 ns         1319 ns       530770   6.16184k      21.3953      19.805k             3.21414       208.182M/s
bench_ascon::ascon_hash/512                       2463 ns         2464 ns       284980   11.4787k      21.1006      36.797k             3.20566       210.594M/s
bench_ascon::ascon_hash/1024                      4740 ns         4740 ns       147730   22.1127k        20.94      70.781k             3.20092       212.452M/s
bench_ascon::ascon_hash/2048                      9305 ns         9306 ns        74873   43.4128k      20.8715     138.749k             3.19604       213.151M/s
bench_ascon::ascon_hash/4096                     18388 ns        18391 ns        37930   85.9538k      20.8221     274.685k             3.19573       214.061M/s
bench_ascon::ascon_hasha/64                        323 ns          323 ns      2167584   1.50831k      15.7116        5.02k             3.32822        283.66M/s
bench_ascon::ascon_hasha/128                       513 ns          513 ns      1360133    2.3984k        14.99       7.892k             3.29053       297.383M/s
bench_ascon::ascon_hasha/256                       895 ns          895 ns       778242    4.1803k      14.5149      13.636k             3.26197       306.895M/s
bench_ascon::ascon_hasha/512                      1659 ns         1659 ns       421790   7.73813k      14.2245      25.124k             3.24678       312.762M/s
bench_ascon::ascon_hasha/1024                     3186 ns         3186 ns       219863   14.8511k      14.0636        48.1k             3.23881       316.086M/s
bench_ascon::ascon_hasha/2048                     6230 ns         6231 ns       112103   29.0863k      13.9838      94.052k             3.23356       318.352M/s
bench_ascon::ascon_hasha/4096                    12327 ns        12328 ns        56685   57.5601k      13.9438     185.956k             3.23064       319.324M/s
bench_ascon::ascon_xof/64/32                       463 ns          463 ns      1512213   2.16356k      22.5371       7.144k             3.30197       197.607M/s
bench_ascon::ascon_xof/128/32                      747 ns          747 ns       934376   3.49287k      21.8304      11.392k              3.2615       204.146M/s
bench_ascon::ascon_xof/256/32                     1319 ns         1319 ns       529757    6.1634k      21.4007      19.888k             3.22679        208.27M/s
bench_ascon::ascon_xof/512/32                     2456 ns         2456 ns       285065   11.4801k      21.1032       36.88k              3.2125       211.237M/s
bench_ascon::ascon_xof/1024/32                    4734 ns         4734 ns       147936    22.115k      20.9422      70.864k             3.20434       212.711M/s
bench_ascon::ascon_xof/2048/32                    9287 ns         9289 ns        75351   43.4094k      20.8699     138.832k              3.1982       213.559M/s
bench_ascon::ascon_xof/4096/32                   18356 ns        18359 ns        37993    85.949k       20.821     274.768k             3.19687       214.436M/s
bench_ascon::ascon_xof/64/64                       608 ns          608 ns      1151628   2.84125k      22.1972        9.42k             3.31545       200.898M/s
bench_ascon::ascon_xof/128/64                      892 ns          892 ns       784516   4.17335k      21.7362      13.668k             3.27507       205.178M/s
bench_ascon::ascon_xof/256/64                     1462 ns         1462 ns       478730   6.83649k       21.364      22.164k             3.24202       208.734M/s
bench_ascon::ascon_xof/512/64                     2603 ns         2603 ns       269182   12.1529k      21.0989      39.156k             3.22194       211.011M/s
bench_ascon::ascon_xof/1024/64                    4874 ns         4875 ns       143428    22.787k      20.9439       73.14k             3.20973       212.836M/s
bench_ascon::ascon_xof/2048/64                    9432 ns         9433 ns        73924    44.082k      20.8721     141.108k             3.20104       213.525M/s
bench_ascon::ascon_xof/4096/64                   18532 ns        18535 ns        37759   86.6225k      20.8227     277.044k             3.19829       214.047M/s
bench_ascon::ascon_xofa/64/32                      325 ns          325 ns      2159023   1.51527k      15.7841       5.096k              3.3631       281.777M/s
bench_ascon::ascon_xofa/128/32                     518 ns          518 ns      1355374   2.41513k      15.0946       7.984k             3.30582       294.646M/s
bench_ascon::ascon_xofa/256/32                     903 ns          903 ns       774085   4.21401k       14.632       13.76k              3.2653       304.287M/s
bench_ascon::ascon_xofa/512/32                    1673 ns         1673 ns       417877   7.81374k      14.3635      25.312k             3.23942       310.036M/s
bench_ascon::ascon_xofa/1024/32                   3213 ns         3213 ns       217705   15.0067k      14.2109      48.416k             3.22629       313.402M/s
bench_ascon::ascon_xofa/2048/32                   6295 ns         6296 ns       110257   29.4078k      14.1384      94.624k             3.21765       315.073M/s
bench_ascon::ascon_xofa/4096/32                  12449 ns        12450 ns        56137   58.2292k      14.1059      187.04k             3.21213       316.197M/s
bench_ascon::ascon_xofa/64/64                      422 ns          422 ns      1655036   1.97215k      15.4074       6.684k             3.38919       289.331M/s
bench_ascon::ascon_xofa/128/64                     614 ns          615 ns      1132331   2.87411k      14.9693       9.572k             3.33042        297.96M/s
bench_ascon::ascon_xofa/256/64                    1001 ns         1001 ns       700309    4.6683k      14.5885      15.348k              3.2877       304.949M/s
bench_ascon::ascon_xofa/512/64                    1768 ns         1768 ns       394466   8.26645k      14.3515        26.9k             3.25412       310.732M/s
bench_ascon::ascon_xofa/1024/64                   3310 ns         3310 ns       211513   15.4625k      14.2119      50.004k             3.23388       313.472M/s
bench_ascon::ascon_xofa/2048/64                   6384 ns         6385 ns       109434   29.8573k       14.137      96.212k             3.22239       315.458M/s
bench_ascon::ascon_xofa/4096/64                  12564 ns        12566 ns        55713   58.6799k      14.1058     188.628k             3.21452        315.72M/s
bench_ascon::ascon_prf/64/16                       190 ns          191 ns      3669770    890.545      11.1318       2.972k             3.33728       400.463M/s
bench_ascon::ascon_prf/128/16                      268 ns          268 ns      2614275   1.25072k      8.68557       4.158k             3.32448       513.243M/s
bench_ascon::ascon_prf/256/16                      415 ns          415 ns      1683580   1.93809k      7.12533        6.53k              3.3693       625.012M/s
bench_ascon::ascon_prf/512/16                      713 ns          713 ns       978131   3.33488k      6.31607      11.274k             3.38063       705.907M/s
bench_ascon::ascon_prf/1024/16                    1327 ns         1327 ns       527226   6.19682k      5.95848      20.762k             3.35043       747.227M/s
bench_ascon::ascon_prf/2048/16                    2541 ns         2541 ns       275621   11.8627k      5.74745      39.738k             3.34982       774.588M/s
bench_ascon::ascon_prf/4096/16                    4964 ns         4965 ns       140961   23.1745k      5.63583       77.69k             3.35239       789.866M/s
bench_ascon::ascon_prf/64/32                       226 ns          226 ns      3094460    1056.36      11.0037       3.552k             3.36249       404.636M/s
bench_ascon::ascon_prf/128/32                      304 ns          304 ns      2302204   1.41774k      8.86086       4.738k             3.34194       502.384M/s
bench_ascon::ascon_prf/256/32                      451 ns          452 ns      1549816   2.10507k      7.30927        7.11k             3.37756       608.312M/s
bench_ascon::ascon_prf/512/32                      749 ns          749 ns       932856   3.49797k       6.4301      11.854k             3.38882        692.74M/s
bench_ascon::ascon_prf/1024/32                    1363 ns         1363 ns       512091   6.36511k      6.02756      21.342k             3.35297       738.715M/s
bench_ascon::ascon_prf/2048/32                    2573 ns         2573 ns       271879   12.0252k      5.78136      40.318k             3.35278       770.993M/s
bench_ascon::ascon_prf/4096/32                    4999 ns         4999 ns       139937   23.3594k      5.65876       78.27k             3.35069       787.445M/s
bench_ascon::ascon_prf/64/64                       297 ns          297 ns      2354332   1.39015k      10.8605       4.712k             3.38957       410.495M/s
bench_ascon::ascon_prf/128/64                      375 ns          375 ns      1869240   1.75145k      9.12213       5.898k              3.3675       488.591M/s
bench_ascon::ascon_prf/256/64                      522 ns          522 ns      1338452   2.43827k       7.6196        8.27k             3.39174        584.36M/s
bench_ascon::ascon_prf/512/64                      820 ns          820 ns       853433   3.83304k      6.65458      13.014k             3.39522       669.621M/s
bench_ascon::ascon_prf/1024/64                    1432 ns         1432 ns       487280     6.699k      6.15716      22.502k             3.35901       724.453M/s
bench_ascon::ascon_prf/2048/64                    2644 ns         2644 ns       264604   12.3586k      5.85162      41.478k              3.3562       761.735M/s
bench_ascon::ascon_prf/4096/64                    5069 ns         5070 ns       137905   23.6922k      5.69524       79.43k             3.35258       782.535M/s
bench_ascon::ascon_mac_authenticate/64             193 ns          193 ns      3624707    901.559      11.2695       2.898k             3.21443       394.763M/s
bench_ascon::ascon_mac_authenticate/128            270 ns          271 ns      2586763   1.26233k      8.76621       4.084k             3.23528       507.686M/s
bench_ascon::ascon_mac_authenticate/256            417 ns          417 ns      1677098    1.9493k      7.16654       6.456k             3.31196       621.878M/s
bench_ascon::ascon_mac_authenticate/512            716 ns          717 ns       973131   3.34758k      6.34012        11.2k              3.3457       702.725M/s
bench_ascon::ascon_mac_authenticate/1024          1331 ns         1331 ns       525561   6.21164k      5.97273      20.688k             3.33052       745.093M/s
bench_ascon::ascon_mac_authenticate/2048          2539 ns         2539 ns       275697   11.8729k      5.75239      39.664k             3.34071       775.206M/s
bench_ascon::ascon_mac_authenticate/4096          4978 ns         4979 ns       141151   23.2006k      5.64217      77.616k             3.34543       787.663M/s
bench_ascon::ascon_mac_verify/64                   191 ns          191 ns      3666275    892.716      9.29912       2.884k             3.23059       479.882M/s
bench_ascon::ascon_mac_verify/128                  268 ns          268 ns      2615291   1.25351k      7.83445        4.07k             3.24688       569.109M/s
bench_ascon::ascon_mac_verify/256                  416 ns          416 ns      1683102   1.94392k      6.74972       6.442k             3.31393       660.867M/s
bench_ascon::ascon_mac_verify/512                  715 ns          715 ns       974045   3.34299k      6.14521      11.186k              3.3461       725.148M/s
bench_ascon::ascon_mac_verify/1024                1328 ns         1328 ns       525361   6.20798k      5.87877      20.674k             3.33023       758.463M/s
bench_ascon::ascon_mac_verify/2048                2540 ns         2540 ns       275497   11.8711k      5.70726       39.65k             3.34005       780.961M/s
bench_ascon::ascon_mac_verify/4096                4970 ns         4970 ns       140856   23.2169k      5.62425      77.602k             3.34248       792.073M/s
bench_ascon::ascon_prfs_authenticate/1            47.4 ns         47.4 ns     14819813     221.49      13.0288          599             2.70441       342.032M/s
bench_ascon::ascon_prfs_authenticate/2            47.1 ns         47.2 ns     14873565    220.178      12.2321          601              2.7296        364.05M/s
bench_ascon::ascon_prfs_authenticate/4            46.7 ns         46.7 ns     14966462    218.377      10.9189          598             2.73838       408.039M/s
bench_ascon::ascon_prfs_authenticate/8            37.2 ns         37.2 ns     18865175    173.822      7.24257          596              3.4288       614.945M/s
bench_ascon::ascon_prfs_authenticate/16           37.4 ns         37.4 ns     18748350    174.657      5.45802          597             3.41813       815.873M/s
bench_ascon::ascon_prfs_verify/1                  51.2 ns         51.2 ns     13650489    239.116      14.0657          753              3.1491       316.491M/s
bench_ascon::ascon_prfs_verify/2                  51.0 ns         51.0 ns     13766911    238.113      13.2285          755             3.17077       336.857M/s
bench_ascon::ascon_prfs_verify/4                  50.5 ns         50.5 ns     13842274    236.072      11.8036          752             3.18546       377.648M/s
bench_ascon::ascon_prfs_verify/8                  45.4 ns         45.4 ns     15406512    212.534      8.85558          750             3.52885       503.938M/s
bench_ascon::ascon_prfs_verify/16                 45.6 ns         45.6 ns     15306941    213.485      6.67141          751             3.51781       668.647M/s
```

### ARM Cortex-A72 ( Compiled with GCC )

```bash
2023-07-07T19:10:34+00:00
Running ./benchmarks/perf.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.21, 0.05, 0.02
***WARNING*** There are 133 benchmarks with threads and 2 performance counters were requested. Beware counters will reflect the combined usage across all threads.
----------------------------------------------------------------------------------------------------------------------------------------------------------------
Benchmark                                            Time             CPU   Iterations     CYCLES CYCLES/ BYTE INSTRUCTIONS INSTRUCTIONS/ CYCLE bytes_per_second
----------------------------------------------------------------------------------------------------------------------------------------------------------------
bench_ascon::ascon_permutation<1>                 9.14 ns         9.14 ns     76600590    21.0002     0.525006           45             2.14283       4.07734G/s
bench_ascon::ascon_permutation<6>                 40.9 ns         40.9 ns     17115606    94.0011      2.35003          215             2.28721       932.788M/s
bench_ascon::ascon_permutation<8>                 58.3 ns         58.3 ns     12003573    134.002      3.35005          308             2.29848       654.347M/s
bench_ascon::ascon_permutation<12>                86.1 ns         86.1 ns      8124998    198.003      4.95008          456             2.30299       442.841M/s
bench_ascon::ascon128_aead_encrypt/64/32           855 ns          855 ns       820521   1.96427k      20.4612        4.27k             2.17383       107.132M/s
bench_ascon::ascon128_aead_encrypt/128/32         1221 ns         1221 ns       573176   2.80659k      17.5412        6.03k             2.14851       124.962M/s
bench_ascon::ascon128_aead_encrypt/256/32         1931 ns         1931 ns       362660   4.43751k       15.408        9.55k             2.15211       142.267M/s
bench_ascon::ascon128_aead_encrypt/512/32         3384 ns         3384 ns       206883   7.77753k      14.2969       16.59k             2.13307       153.319M/s
bench_ascon::ascon128_aead_encrypt/1024/32        6257 ns         6257 ns       111836   14.3816k      13.6189       30.67k             2.13259       160.954M/s
bench_ascon::ascon128_aead_encrypt/2048/32       11989 ns        11988 ns        58387   27.5543k      13.2473       58.83k             2.13506       165.466M/s
bench_ascon::ascon128_aead_encrypt/4096/32       23454 ns        23453 ns        29846   53.9063k      13.0587      115.15k             2.13612       167.857M/s
bench_ascon::ascon128_aead_decrypt/64/32           872 ns          872 ns       801834   2.00415k      20.8765       4.427k             2.20892       104.997M/s
bench_ascon::ascon128_aead_decrypt/128/32         1182 ns         1182 ns       592104    2.7162k      16.9763       6.143k             2.26161       129.121M/s
bench_ascon::ascon128_aead_decrypt/256/32         1839 ns         1839 ns       380740   4.22744k      14.6786       9.575k             2.26496       149.333M/s
bench_ascon::ascon128_aead_decrypt/512/32         3142 ns         3142 ns       222731   7.22274k      13.2771      16.439k             2.27601       165.095M/s
bench_ascon::ascon128_aead_decrypt/1024/32        5770 ns         5770 ns       121299    13.262k      12.5587      30.167k              2.2747       174.538M/s
bench_ascon::ascon128_aead_decrypt/2048/32       10930 ns        10930 ns        64039   25.1207k      12.0773      57.623k             2.29384        181.49M/s
bench_ascon::ascon128_aead_decrypt/4096/32       21355 ns        21355 ns        32809   49.0824k      11.8901     112.535k             2.29278        184.35M/s
bench_ascon::ascon128a_aead_encrypt/64/32          717 ns          717 ns       976645   1.64707k       17.157        3.51k             2.13106        127.76M/s
bench_ascon::ascon128a_aead_encrypt/128/32        1011 ns         1011 ns       692500   2.32309k      14.5193        4.87k             2.09635       150.972M/s
bench_ascon::ascon128a_aead_encrypt/256/32        1576 ns         1576 ns       444196   3.62212k      12.5768        7.59k             2.09546       174.291M/s
bench_ascon::ascon128a_aead_encrypt/512/32        2692 ns         2692 ns       260023    6.1874k      11.3739       13.03k             2.10589       192.724M/s
bench_ascon::ascon128a_aead_encrypt/1024/32       4934 ns         4934 ns       141867   11.3414k        10.74       23.91k             2.10821         204.1M/s
bench_ascon::ascon128a_aead_encrypt/2048/32       9416 ns         9416 ns        74328   21.6439k      10.4057       45.67k             2.11007       210.659M/s
bench_ascon::ascon128a_aead_encrypt/4096/32      18421 ns        18421 ns        37998   42.3406k      10.2569       89.19k             2.10649        213.71M/s
bench_ascon::ascon128a_aead_decrypt/64/32          788 ns          788 ns       890011   1.81181k       18.873       3.851k              2.1255       116.147M/s
bench_ascon::ascon128a_aead_decrypt/128/32        1023 ns         1023 ns       684173   2.35052k      14.6907       5.239k             2.22887       149.211M/s
bench_ascon::ascon128a_aead_decrypt/256/32        1565 ns         1565 ns       446523   3.59786k      12.4926       8.015k             2.22772       175.463M/s
bench_ascon::ascon128a_aead_decrypt/512/32        2593 ns         2593 ns       269997   5.95924k      10.9545      13.567k             2.27663       200.101M/s
bench_ascon::ascon128a_aead_decrypt/1024/32       4740 ns         4740 ns       147668   10.8958k       10.318      24.671k             2.26427       212.448M/s
bench_ascon::ascon128a_aead_decrypt/2048/32       8880 ns         8880 ns        78821   20.4099k      9.81247      46.879k             2.29687       223.389M/s
bench_ascon::ascon128a_aead_decrypt/4096/32      17387 ns        17386 ns        40330   39.9596k      9.68014      91.295k             2.28468        226.43M/s
bench_ascon::ascon80pq_aead_encrypt/64/32          860 ns          860 ns       813663   1.97664k        20.59       4.283k             2.16681       106.461M/s
bench_ascon::ascon80pq_aead_encrypt/128/32        1230 ns         1230 ns       569048   2.82603k      17.6627       6.043k             2.13833       124.103M/s
bench_ascon::ascon80pq_aead_encrypt/256/32        1947 ns         1947 ns       359655   4.47585k      15.5411       9.563k             2.13658       141.046M/s
bench_ascon::ascon80pq_aead_encrypt/512/32        3415 ns         3414 ns       205052   7.84795k      14.4264      16.603k             2.11558       151.943M/s
bench_ascon::ascon80pq_aead_encrypt/1024/32       6313 ns         6313 ns       110872   14.5101k      13.7406      30.683k              2.1146       159.525M/s
bench_ascon::ascon80pq_aead_encrypt/2048/32      12102 ns        12102 ns        57837   27.8154k      13.3728      58.843k             2.11548       163.912M/s
bench_ascon::ascon80pq_aead_encrypt/4096/32      23712 ns        23712 ns        29521   54.4989k      13.2023     115.163k             2.11312       166.026M/s
bench_ascon::ascon80pq_aead_decrypt/64/32          878 ns          878 ns       798637   2.01712k      21.0116       4.437k             2.19968       104.324M/s
bench_ascon::ascon80pq_aead_decrypt/128/32        1183 ns         1183 ns       591634   2.71903k       16.994       6.153k             2.26294       128.988M/s
bench_ascon::ascon80pq_aead_decrypt/256/32        1841 ns         1841 ns       380501   4.23122k      14.6917       9.585k              2.2653         149.2M/s
bench_ascon::ascon80pq_aead_decrypt/512/32        3144 ns         3144 ns       222647   7.22629k      13.2836      16.449k             2.27627       165.016M/s
bench_ascon::ascon80pq_aead_decrypt/1024/32       5773 ns         5773 ns       121232   13.2687k       12.565      30.177k             2.27431       174.452M/s
bench_ascon::ascon80pq_aead_decrypt/2048/32      10931 ns        10931 ns        64030   25.1248k      12.0792      57.633k             2.29387       181.469M/s
bench_ascon::ascon80pq_aead_decrypt/4096/32      21357 ns        21357 ns        32764   49.0856k      11.8909     112.545k             2.29283       184.332M/s
bench_ascon::ascon_hash/64                        1225 ns         1225 ns       571646   2.81609k      29.3342       6.036k              2.1434       74.7272M/s
bench_ascon::ascon_hash/128                       1950 ns         1950 ns       359364    4.4812k      28.0075       9.684k             2.16103       78.2663M/s
bench_ascon::ascon_hash/256                       3396 ns         3396 ns       206138    7.8057k      27.1031       16.98k             2.17533       80.8777M/s
bench_ascon::ascon_hash/512                       6292 ns         6292 ns       111231   14.4615k      26.5836      31.572k             2.18318       82.4584M/s
bench_ascon::ascon_hash/1024                     12085 ns        12085 ns        57919   27.7785k      26.3054      60.756k             2.18716       83.3314M/s
bench_ascon::ascon_hash/2048                     23667 ns        23667 ns        29576   54.3987k      26.1532     119.124k             2.18983       83.8163M/s
bench_ascon::ascon_hash/4096                     46837 ns        46837 ns        14946   107.655k      26.0792      235.86k             2.19089       84.0529M/s
bench_ascon::ascon_hasha/64                        858 ns          858 ns       816131   1.97109k      20.5321        4.26k             2.16125       106.761M/s
bench_ascon::ascon_hasha/128                      1345 ns         1345 ns       520465   3.09114k      19.3196       6.724k             2.17525       113.458M/s
bench_ascon::ascon_hasha/256                      2319 ns         2319 ns       301787   5.33136k      18.5117      11.652k             2.18556       118.415M/s
bench_ascon::ascon_hasha/512                      4305 ns         4305 ns       162607   9.89447k      18.1884      21.508k             2.17374       120.519M/s
bench_ascon::ascon_hasha/1024                     8168 ns         8168 ns        85685    18.774k      17.7784       41.22k             2.19559       123.298M/s
bench_ascon::ascon_hasha/2048                    15968 ns        15967 ns        43834   36.6995k       17.644      80.644k             2.19741       124.232M/s
bench_ascon::ascon_hasha/4096                    31562 ns        31562 ns        22178   72.5447k      17.5738     159.492k             2.19853       124.733M/s
bench_ascon::ascon_xof/64/32                      1228 ns         1228 ns       570686   2.82258k      29.4019       6.131k             2.17212       74.5553M/s
bench_ascon::ascon_xof/128/32                     1953 ns         1953 ns       358887    4.4885k      28.0531       9.779k             2.17868       78.1398M/s
bench_ascon::ascon_xof/256/32                     3400 ns         3400 ns       205868   7.81473k      27.1345      17.075k             2.18498       80.7839M/s
bench_ascon::ascon_xof/512/32                     6314 ns         6314 ns       110768   14.5129k      26.6782      31.667k             2.18198       82.1666M/s
bench_ascon::ascon_xof/1024/32                   12087 ns        12087 ns        57908   27.7833k      26.3099      60.851k              2.1902       83.3178M/s
bench_ascon::ascon_xof/2048/32                   23669 ns        23669 ns        29573   54.4038k      26.1557     119.219k             2.19137       83.8086M/s
bench_ascon::ascon_xof/4096/32                   46839 ns        46838 ns        14945   107.656k      26.0796     235.955k             2.19174       84.0506M/s
bench_ascon::ascon_xof/64/64                      1601 ns         1601 ns       437315   3.67908k      28.7428       8.075k             2.19484       76.2644M/s
bench_ascon::ascon_xof/128/64                     2326 ns         2325 ns       301121   5.34489k       27.838      11.723k             2.19331        78.739M/s
bench_ascon::ascon_xof/256/64                     3773 ns         3773 ns       185551   8.67123k      27.0976      19.019k             2.19334       80.8941M/s
bench_ascon::ascon_xof/512/64                     6685 ns         6685 ns       104688   15.3664k      26.6778      33.611k              2.1873       82.1677M/s
bench_ascon::ascon_xof/1024/64                   12460 ns        12460 ns        56167   28.6397k      26.3233      62.795k             2.19259       83.2735M/s
bench_ascon::ascon_xof/2048/64                   24043 ns        24043 ns        29114   55.2644k      26.1668     121.163k             2.19243       83.7734M/s
bench_ascon::ascon_xof/4096/64                   47212 ns        47212 ns        14826   108.517k      26.0857     237.899k             2.19228       84.0312M/s
bench_ascon::ascon_xofa/64/32                      875 ns          875 ns       798672   2.01087k      20.9466       4.354k             2.16523        104.65M/s
bench_ascon::ascon_xofa/128/32                    1361 ns         1361 ns       514823   3.12737k       19.546       6.818k             2.18011       112.145M/s
bench_ascon::ascon_xofa/256/32                    2334 ns         2334 ns       299866   5.36525k      18.6294      11.746k             2.18927       117.667M/s
bench_ascon::ascon_xofa/512/32                    4285 ns         4285 ns       163422   9.84826k      18.1034      21.602k             2.19348       121.085M/s
bench_ascon::ascon_xofa/1024/32                   8181 ns         8181 ns        85560   18.8042k       17.807      41.314k             2.19706       123.102M/s
bench_ascon::ascon_xofa/2048/32                  15970 ns        15970 ns        43814   36.7074k      17.6478      80.738k              2.1995       124.209M/s
bench_ascon::ascon_xofa/4096/32                  31582 ns        31581 ns        22163   72.5892k      17.5846     159.586k             2.19848       124.655M/s
bench_ascon::ascon_xofa/64/64                     1132 ns         1132 ns       618549   2.60108k      20.3209       5.706k              2.1937       107.869M/s
bench_ascon::ascon_xofa/128/64                    1619 ns         1619 ns       432370   3.72111k      19.3808        8.17k             2.19558       113.105M/s
bench_ascon::ascon_xofa/256/64                    2594 ns         2594 ns       269896   5.96129k       18.629      13.098k             2.19717       117.667M/s
bench_ascon::ascon_xofa/512/64                    4543 ns         4543 ns       154087   10.4413k      18.1273      22.954k             2.19838       120.926M/s
bench_ascon::ascon_xofa/1024/64                   8443 ns         8442 ns        82903   19.4046k      17.8351      42.666k             2.19875       122.904M/s
bench_ascon::ascon_xofa/2048/64                  16238 ns        16237 ns        43108   37.3224k      17.6716       82.09k             2.19948       124.044M/s
bench_ascon::ascon_xofa/4096/64                  31836 ns        31835 ns        21989   73.1726k      17.5896     160.938k             2.19943       124.619M/s
bench_ascon::ascon_prf/64/16                       514 ns          514 ns      1356192   1.18141k      14.7677       2.536k             2.14658       148.436M/s
bench_ascon::ascon_prf/128/16                      730 ns          730 ns       957610   1.67853k      11.6565        3.57k             2.12686       188.053M/s
bench_ascon::ascon_prf/256/16                     1142 ns         1142 ns       609395   2.62518k      9.65141       5.638k             2.14766       227.119M/s
bench_ascon::ascon_prf/512/16                     1969 ns         1969 ns       355473   4.52615k      8.57225       9.774k             2.15945       255.711M/s
bench_ascon::ascon_prf/1024/16                    3626 ns         3626 ns       193049   8.33439k      8.01384      18.046k             2.16524       273.525M/s
bench_ascon::ascon_prf/2048/16                    6940 ns         6939 ns       100862   15.9506k        7.728       34.59k             2.16857        283.65M/s
bench_ascon::ascon_prf/4096/16                   13567 ns        13567 ns        51594   31.1837k      7.58359      67.678k              2.1703       289.048M/s
bench_ascon::ascon_prf/64/32                       603 ns          603 ns      1161102   1.38544k      14.4317       3.003k             2.16754        151.89M/s
bench_ascon::ascon_prf/128/32                      821 ns          821 ns       852612   1.88806k      11.8004       4.037k             2.13817        185.76M/s
bench_ascon::ascon_prf/256/32                     1234 ns         1234 ns       567052   2.83719k      9.85136       6.105k             2.15178       222.502M/s
bench_ascon::ascon_prf/512/32                     2063 ns         2063 ns       339426   4.74114k      8.71534      10.241k             2.16003       251.516M/s
bench_ascon::ascon_prf/1024/32                    3720 ns         3720 ns       188221   8.54929k      8.09592      18.513k             2.16544       270.751M/s
bench_ascon::ascon_prf/2048/32                    7033 ns         7033 ns        99519   16.1656k       7.7719      35.057k             2.16862       282.043M/s
bench_ascon::ascon_prf/4096/32                   13662 ns        13661 ns        51242   31.3991k      7.60636      68.145k             2.17029        288.17M/s
bench_ascon::ascon_prf/64/64                       797 ns          797 ns       879517   1.83109k      14.3054       3.937k             2.15008       153.233M/s
bench_ascon::ascon_prf/128/64                     1013 ns         1013 ns       689478   2.32948k      12.1327       4.971k             2.13395       180.673M/s
bench_ascon::ascon_prf/256/64                     1428 ns         1428 ns       490252   3.28129k       10.254       7.039k              2.1452       213.773M/s
bench_ascon::ascon_prf/512/64                     2256 ns         2256 ns       310230    5.1863k      9.00399      11.175k             2.15472       243.454M/s
bench_ascon::ascon_prf/1024/64                    3913 ns         3913 ns       178906    8.9944k      8.26691      19.447k             2.16212       265.144M/s
bench_ascon::ascon_prf/2048/64                    7228 ns         7228 ns        96817   16.6135k      7.86626      35.991k             2.16637       278.665M/s
bench_ascon::ascon_prf/4096/64                   13856 ns        13856 ns        50527   31.8464k      7.65537      69.079k             2.16913        286.33M/s
bench_ascon::ascon_mac_authenticate/64             512 ns          512 ns      1367784   1.17604k      14.7005       2.515k             2.13854        149.11M/s
bench_ascon::ascon_mac_authenticate/128            729 ns          729 ns       959769   1.67605k      11.6392       3.549k             2.11748       188.334M/s
bench_ascon::ascon_mac_authenticate/256           1143 ns         1143 ns       612049   2.62732k      9.65926       5.617k             2.13792       226.929M/s
bench_ascon::ascon_mac_authenticate/512           1972 ns         1972 ns       354995   4.53215k      8.58363       9.753k             2.15196       255.375M/s
bench_ascon::ascon_mac_authenticate/1024          3630 ns         3630 ns       192840   8.34327k      8.02238      18.025k             2.16042        273.24M/s
bench_ascon::ascon_mac_authenticate/2048          6942 ns         6942 ns       100812   15.9566k      7.73092      34.569k             2.16644       283.539M/s
bench_ascon::ascon_mac_authenticate/4096         13570 ns        13570 ns        51583   31.1899k       7.5851      67.657k             2.16919       288.982M/s
bench_ascon::ascon_mac_verify/64                   510 ns          510 ns      1372488   1.17204k      12.2087       2.518k              2.1484        179.55M/s
bench_ascon::ascon_mac_verify/128                  727 ns          727 ns       962740   1.67103k      10.4439       3.552k             2.12564       209.888M/s
bench_ascon::ascon_mac_verify/256                 1142 ns         1142 ns       613095   2.62407k      9.11137        5.62k             2.14171       240.581M/s
bench_ascon::ascon_mac_verify/512                 1970 ns         1970 ns       355318   4.52814k      8.32378       9.756k             2.15453       263.349M/s
bench_ascon::ascon_mac_verify/1024                3627 ns         3627 ns       193000   8.33628k       7.8942      18.028k              2.1626       277.674M/s
bench_ascon::ascon_mac_verify/2048                6940 ns         6940 ns       100840   15.9526k      7.66954      34.572k             2.16717       285.815M/s
bench_ascon::ascon_mac_verify/4096               13568 ns        13568 ns        51590   31.1857k      7.55467       67.66k             2.16959        290.15M/s
bench_ascon::ascon_prfs_authenticate/1             103 ns          103 ns      6786889    237.042      13.9437          521             2.19792        157.21M/s
bench_ascon::ascon_prfs_authenticate/2             103 ns          103 ns      6788210    237.005      13.1669          521             2.19827       166.484M/s
bench_ascon::ascon_prfs_authenticate/4             102 ns          102 ns      6844647    235.021       11.751          517             2.19981       186.541M/s
bench_ascon::ascon_prfs_authenticate/8             102 ns          102 ns      6874953    234.004      9.75018          516             2.20509       224.823M/s
bench_ascon::ascon_prfs_authenticate/16            101 ns          101 ns      6904505    233.005      7.28141          515             2.21025       301.042M/s
bench_ascon::ascon_prfs_verify/1                   131 ns          131 ns      5362520    300.009      17.6476          657             2.18993       124.209M/s
bench_ascon::ascon_prfs_verify/2                   131 ns          131 ns      5362733    300.009      16.6672          657             2.18993       131.516M/s
bench_ascon::ascon_prfs_verify/4                   131 ns          131 ns      5362697    300.009      15.0004          653              2.1766       146.129M/s
bench_ascon::ascon_prfs_verify/8                   130 ns          130 ns      5380420    299.008      12.4587          652             2.18054       175.945M/s
bench_ascon::ascon_prfs_verify/16                  128 ns          128 ns      5452659     295.06      9.22061          651             2.20633       237.724M/s
```

## Usage

`ascon` is a zero-dependency, header-only C++ library, which is pretty easy to get started with.

- Include proper header file(s) ( living in `include` directory ) in your header/ source file.
- Use functions/ constants living under proper namespace of interest.
- When compiling, let your compiler know where it can find header files i.e. inside `include` and `subtle/include`, by using `-I` flag.

Scheme | Header to include | Namespace of interest | Example
:-- | :-: | :-: | --:
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
