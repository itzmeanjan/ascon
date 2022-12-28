## Benchmarking Ascon Cipher Suite on CPU

For benchmarking Ascon cipher suite, using `google-benchmark` library, on target CPU system, with variable length input data, one may issue

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

### On ARM Neoverse-V1 aka AWS Graviton3 ( when compiled with `g++` )

```bash
2022-12-28T12:34:19+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.24, 0.06, 0.02
---------------------------------------------------------------------------------------
Benchmark                             Time             CPU   Iterations UserCounters...
---------------------------------------------------------------------------------------
bench_ascon::permutation<1>        6.23 ns         6.23 ns    112227709 bytes_per_second=5.97528G/s
bench_ascon::permutation<6>        27.2 ns         27.2 ns     25750738 bytes_per_second=1.37091G/s
bench_ascon::permutation<8>        37.5 ns         37.5 ns     18651681 bytes_per_second=1016.64M/s
bench_ascon::permutation<12>       55.2 ns         55.2 ns     12694398 bytes_per_second=691.529M/s
bench_ascon::hash/64                697 ns          697 ns      1003910 bytes_per_second=87.5997M/s
bench_ascon::hash_a/64              481 ns          481 ns      1455984 bytes_per_second=126.836M/s
bench_ascon::hash/128              1125 ns         1125 ns       622658 bytes_per_second=108.51M/s
bench_ascon::hash_a/128             760 ns          760 ns       922095 bytes_per_second=160.671M/s
bench_ascon::hash/256              1982 ns         1982 ns       352845 bytes_per_second=123.181M/s
bench_ascon::hash_a/256            1319 ns         1319 ns       530759 bytes_per_second=185.085M/s
bench_ascon::hash/512              3692 ns         3692 ns       189618 bytes_per_second=132.268M/s
bench_ascon::hash_a/512            2438 ns         2438 ns       287072 bytes_per_second=200.297M/s
bench_ascon::hash/1024             7128 ns         7128 ns        98083 bytes_per_second=137.003M/s
bench_ascon::hash_a/1024           4649 ns         4649 ns       150518 bytes_per_second=210.062M/s
bench_ascon::hash/2048            14003 ns        14003 ns        49960 bytes_per_second=139.478M/s
bench_ascon::hash_a/2048           9060 ns         9059 ns        77129 bytes_per_second=215.591M/s
bench_ascon::hash/4096            27706 ns        27705 ns        25237 bytes_per_second=140.994M/s
bench_ascon::hash_a/4096          17819 ns        17819 ns        39288 bytes_per_second=219.223M/s
bench_ascon::enc_128/64             533 ns          533 ns      1312835 bytes_per_second=228.816M/s
bench_ascon::dec_128/64             532 ns          532 ns      1315365 bytes_per_second=229.362M/s
bench_ascon::enc_128/128            739 ns          739 ns       947314 bytes_per_second=247.859M/s
bench_ascon::dec_128/128            734 ns          734 ns       953404 bytes_per_second=249.434M/s
bench_ascon::enc_128/256           1149 ns         1149 ns       609417 bytes_per_second=265.69M/s
bench_ascon::dec_128/256           1137 ns         1137 ns       615219 bytes_per_second=268.31M/s
bench_ascon::enc_128/512           1969 ns         1969 ns       355634 bytes_per_second=279.044M/s
bench_ascon::dec_128/512           1944 ns         1944 ns       360108 bytes_per_second=282.535M/s
bench_ascon::enc_128/1024          3609 ns         3609 ns       193984 bytes_per_second=287.526M/s
bench_ascon::dec_128/1024          3557 ns         3557 ns       196794 bytes_per_second=291.713M/s
bench_ascon::enc_128/2048          6889 ns         6889 ns       101600 bytes_per_second=292.393M/s
bench_ascon::dec_128/2048          6790 ns         6790 ns       103085 bytes_per_second=296.621M/s
bench_ascon::enc_128/4096         13451 ns        13451 ns        52039 bytes_per_second=294.946M/s
bench_ascon::dec_128/4096         13252 ns        13252 ns        52805 bytes_per_second=299.382M/s
bench_ascon::enc_128a/64            423 ns          423 ns      1653503 bytes_per_second=288.301M/s
bench_ascon::dec_128a/64            414 ns          414 ns      1689073 bytes_per_second=294.509M/s
bench_ascon::enc_128a/128           570 ns          570 ns      1227851 bytes_per_second=321.042M/s
bench_ascon::dec_128a/128           552 ns          552 ns      1266753 bytes_per_second=331.516M/s
bench_ascon::enc_128a/256           864 ns          864 ns       810135 bytes_per_second=353.401M/s
bench_ascon::dec_128a/256           828 ns          828 ns       844912 bytes_per_second=368.646M/s
bench_ascon::enc_128a/512          1451 ns         1451 ns       482411 bytes_per_second=378.552M/s
bench_ascon::dec_128a/512          1380 ns         1380 ns       507327 bytes_per_second=397.948M/s
bench_ascon::enc_128a/1024         2623 ns         2622 ns       266866 bytes_per_second=395.659M/s
bench_ascon::dec_128a/1024         2484 ns         2484 ns       281869 bytes_per_second=417.753M/s
bench_ascon::enc_128a/2048         4972 ns         4972 ns       140793 bytes_per_second=405.092M/s
bench_ascon::dec_128a/2048         4689 ns         4689 ns       149308 bytes_per_second=429.518M/s
bench_ascon::enc_128a/4096         9668 ns         9668 ns        72412 bytes_per_second=410.366M/s
bench_ascon::dec_128a/4096         9106 ns         9106 ns        76881 bytes_per_second=435.676M/s
bench_ascon::enc_80pq/64            532 ns          532 ns      1318236 bytes_per_second=229.439M/s
bench_ascon::dec_80pq/64            537 ns          537 ns      1304725 bytes_per_second=227.309M/s
bench_ascon::enc_80pq/128           736 ns          736 ns       953647 bytes_per_second=248.861M/s
bench_ascon::dec_80pq/128           739 ns          739 ns       948294 bytes_per_second=247.862M/s
bench_ascon::enc_80pq/256          1140 ns         1140 ns       613879 bytes_per_second=267.766M/s
bench_ascon::dec_80pq/256          1142 ns         1141 ns       614121 bytes_per_second=267.348M/s
bench_ascon::enc_80pq/512          1950 ns         1950 ns       359105 bytes_per_second=281.766M/s
bench_ascon::dec_80pq/512          1941 ns         1940 ns       360701 bytes_per_second=283.084M/s
bench_ascon::enc_80pq/1024         3570 ns         3570 ns       196092 bytes_per_second=290.662M/s
bench_ascon::dec_80pq/1024         3540 ns         3540 ns       198338 bytes_per_second=293.077M/s
bench_ascon::enc_80pq/2048         6806 ns         6806 ns       102842 bytes_per_second=295.938M/s
bench_ascon::dec_80pq/2048         6692 ns         6691 ns       104393 bytes_per_second=301.015M/s
bench_ascon::enc_80pq/4096        13297 ns        13297 ns        52640 bytes_per_second=298.36M/s
bench_ascon::dec_80pq/4096        13006 ns        13006 ns        53736 bytes_per_second=305.034M/s
```

### On ARM Neoverse-V1 aka AWS Graviton3 ( when compiled with `clang++` )

```bash
2022-12-28T12:36:13+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.40, 0.21, 0.08
---------------------------------------------------------------------------------------
Benchmark                             Time             CPU   Iterations UserCounters...
---------------------------------------------------------------------------------------
bench_ascon::permutation<1>        5.66 ns         5.66 ns    123698740 bytes_per_second=6.58596G/s
bench_ascon::permutation<6>        22.5 ns         22.5 ns     30966581 bytes_per_second=1.65313G/s
bench_ascon::permutation<8>        29.5 ns         29.5 ns     23709531 bytes_per_second=1.26161G/s
bench_ascon::permutation<12>       42.5 ns         42.5 ns     16464337 bytes_per_second=896.971M/s
bench_ascon::hash/64               1547 ns         1547 ns       452222 bytes_per_second=39.4643M/s
bench_ascon::hash_a/64             1095 ns         1095 ns       637761 bytes_per_second=55.7162M/s
bench_ascon::hash/128              2513 ns         2513 ns       278771 bytes_per_second=48.5818M/s
bench_ascon::hash_a/128            1768 ns         1768 ns       396537 bytes_per_second=69.0615M/s
bench_ascon::hash/256              4445 ns         4445 ns       157656 bytes_per_second=54.9276M/s
bench_ascon::hash_a/256            3100 ns         3100 ns       225805 bytes_per_second=78.7514M/s
bench_ascon::hash/512              8298 ns         8298 ns        84222 bytes_per_second=58.844M/s
bench_ascon::hash_a/512            5772 ns         5772 ns       121268 bytes_per_second=84.5936M/s
bench_ascon::hash/1024            16023 ns        16023 ns        43693 bytes_per_second=60.9482M/s
bench_ascon::hash_a/1024          11120 ns        11120 ns        62930 bytes_per_second=87.819M/s
bench_ascon::hash/2048            31411 ns        31410 ns        22218 bytes_per_second=62.1807M/s
bench_ascon::hash_a/2048          21823 ns        21823 ns        32077 bytes_per_second=89.5M/s
bench_ascon::hash/4096            62202 ns        62201 ns        11267 bytes_per_second=62.8008M/s
bench_ascon::hash_a/4096          43231 ns        43230 ns        16190 bytes_per_second=90.3599M/s
bench_ascon::enc_128/64             462 ns          462 ns      1515970 bytes_per_second=264.344M/s
bench_ascon::dec_128/64             461 ns          461 ns      1519262 bytes_per_second=264.965M/s
bench_ascon::enc_128/128            639 ns          639 ns      1096718 bytes_per_second=286.718M/s
bench_ascon::dec_128/128            637 ns          637 ns      1098383 bytes_per_second=287.303M/s
bench_ascon::enc_128/256            992 ns          992 ns       705911 bytes_per_second=307.651M/s
bench_ascon::dec_128/256            994 ns          994 ns       704052 bytes_per_second=306.938M/s
bench_ascon::enc_128/512           1702 ns         1702 ns       411343 bytes_per_second=322.77M/s
bench_ascon::dec_128/512           1700 ns         1700 ns       411682 bytes_per_second=323.157M/s
bench_ascon::enc_128/1024          3112 ns         3112 ns       224723 bytes_per_second=333.466M/s
bench_ascon::dec_128/1024          3114 ns         3114 ns       224796 bytes_per_second=333.242M/s
bench_ascon::enc_128/2048          5922 ns         5922 ns       118185 bytes_per_second=340.111M/s
bench_ascon::dec_128/2048          5942 ns         5942 ns       117791 bytes_per_second=338.955M/s
bench_ascon::enc_128/4096         11556 ns        11555 ns        60579 bytes_per_second=343.327M/s
bench_ascon::dec_128/4096         11627 ns        11627 ns        60295 bytes_per_second=341.213M/s
bench_ascon::enc_128a/64            358 ns          358 ns      1956779 bytes_per_second=340.98M/s
bench_ascon::dec_128a/64            353 ns          353 ns      1985210 bytes_per_second=346.125M/s
bench_ascon::enc_128a/128           476 ns          476 ns      1470399 bytes_per_second=384.316M/s
bench_ascon::dec_128a/128           472 ns          472 ns      1483050 bytes_per_second=387.764M/s
bench_ascon::enc_128a/256           713 ns          713 ns       982649 bytes_per_second=428.296M/s
bench_ascon::dec_128a/256           711 ns          711 ns       984469 bytes_per_second=429.249M/s
bench_ascon::enc_128a/512          1186 ns         1186 ns       589740 bytes_per_second=463.113M/s
bench_ascon::dec_128a/512          1188 ns         1188 ns       589166 bytes_per_second=462.352M/s
bench_ascon::enc_128a/1024         2139 ns         2139 ns       327672 bytes_per_second=485.182M/s
bench_ascon::dec_128a/1024         2145 ns         2145 ns       326379 bytes_per_second=483.651M/s
bench_ascon::enc_128a/2048         4030 ns         4030 ns       173704 bytes_per_second=499.831M/s
bench_ascon::dec_128a/2048         4052 ns         4052 ns       172716 bytes_per_second=497.062M/s
bench_ascon::enc_128a/4096         7816 ns         7816 ns        89255 bytes_per_second=507.578M/s
bench_ascon::dec_128a/4096         7887 ns         7886 ns        88738 bytes_per_second=503.048M/s
bench_ascon::enc_80pq/64            464 ns          464 ns      1508455 bytes_per_second=263.028M/s
bench_ascon::dec_80pq/64            463 ns          463 ns      1510414 bytes_per_second=263.733M/s
bench_ascon::enc_80pq/128           640 ns          640 ns      1093694 bytes_per_second=285.997M/s
bench_ascon::dec_80pq/128           641 ns          641 ns      1092500 bytes_per_second=285.79M/s
bench_ascon::enc_80pq/256           993 ns          993 ns       704657 bytes_per_second=307.188M/s
bench_ascon::dec_80pq/256           997 ns          997 ns       702102 bytes_per_second=306.086M/s
bench_ascon::enc_80pq/512          1702 ns         1702 ns       411462 bytes_per_second=322.728M/s
bench_ascon::dec_80pq/512          1704 ns         1704 ns       410727 bytes_per_second=322.366M/s
bench_ascon::enc_80pq/1024         3110 ns         3110 ns       225110 bytes_per_second=333.664M/s
bench_ascon::dec_80pq/1024         3123 ns         3123 ns       224346 bytes_per_second=332.289M/s
bench_ascon::enc_80pq/2048         5927 ns         5927 ns       118085 bytes_per_second=339.834M/s
bench_ascon::dec_80pq/2048         5950 ns         5950 ns       117618 bytes_per_second=338.541M/s
bench_ascon::enc_80pq/4096        11557 ns        11556 ns        60567 bytes_per_second=343.295M/s
bench_ascon::dec_80pq/4096        11628 ns        11627 ns        60231 bytes_per_second=341.206M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-12-28T16:21:11+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.85, 2.11, 2.25
---------------------------------------------------------------------------------------
Benchmark                             Time             CPU   Iterations UserCounters...
---------------------------------------------------------------------------------------
bench_ascon::permutation<1>        4.66 ns         4.60 ns    152229179 bytes_per_second=8.09811G/s
bench_ascon::permutation<6>        25.4 ns         25.2 ns     27854156 bytes_per_second=1.48099G/s
bench_ascon::permutation<8>        33.2 ns         32.9 ns     21340292 bytes_per_second=1.13299G/s
bench_ascon::permutation<12>       49.5 ns         48.9 ns     14293911 bytes_per_second=780.175M/s
bench_ascon::hash/64                592 ns          585 ns      1195172 bytes_per_second=104.362M/s
bench_ascon::hash_a/64              407 ns          403 ns      1734924 bytes_per_second=151.599M/s
bench_ascon::hash/128               997 ns          983 ns       708058 bytes_per_second=124.185M/s
bench_ascon::hash_a/128             675 ns          667 ns      1042318 bytes_per_second=182.888M/s
bench_ascon::hash/256              1774 ns         1753 ns       394998 bytes_per_second=139.287M/s
bench_ascon::hash_a/256            1191 ns         1179 ns       582906 bytes_per_second=207.092M/s
bench_ascon::hash/512              3337 ns         3300 ns       211972 bytes_per_second=147.949M/s
bench_ascon::hash_a/512            2237 ns         2214 ns       316293 bytes_per_second=220.51M/s
bench_ascon::hash/1024             6477 ns         6408 ns       107034 bytes_per_second=152.408M/s
bench_ascon::hash_a/1024           4328 ns         4279 ns       156038 bytes_per_second=228.226M/s
bench_ascon::hash/2048            12740 ns        12597 ns        55126 bytes_per_second=155.045M/s
bench_ascon::hash_a/2048           8505 ns         8415 ns        81433 bytes_per_second=232.107M/s
bench_ascon::hash/4096            25498 ns        25228 ns        27698 bytes_per_second=154.84M/s
bench_ascon::hash_a/4096          16880 ns        16701 ns        41252 bytes_per_second=233.888M/s
bench_ascon::enc_128/64             535 ns          529 ns      1299039 bytes_per_second=230.663M/s
bench_ascon::dec_128/64             536 ns          530 ns      1301744 bytes_per_second=230.419M/s
bench_ascon::enc_128/128            732 ns          724 ns       942736 bytes_per_second=253.016M/s
bench_ascon::dec_128/128            742 ns          733 ns       947880 bytes_per_second=249.64M/s
bench_ascon::enc_128/256           1140 ns         1128 ns       622233 bytes_per_second=270.654M/s
bench_ascon::dec_128/256           1145 ns         1132 ns       604073 bytes_per_second=269.585M/s
bench_ascon::enc_128/512           1947 ns         1927 ns       361909 bytes_per_second=285.058M/s
bench_ascon::dec_128/512           1961 ns         1939 ns       357267 bytes_per_second=283.256M/s
bench_ascon::enc_128/1024          3566 ns         3528 ns       197944 bytes_per_second=294.122M/s
bench_ascon::dec_128/1024          3591 ns         3551 ns       197815 bytes_per_second=292.226M/s
bench_ascon::enc_128/2048          6839 ns         6763 ns       100962 bytes_per_second=297.8M/s
bench_ascon::dec_128/2048          6857 ns         6773 ns       100213 bytes_per_second=297.403M/s
bench_ascon::enc_128/4096         13427 ns        13292 ns        52173 bytes_per_second=298.468M/s
bench_ascon::dec_128/4096         13358 ns        13200 ns        52656 bytes_per_second=300.544M/s
bench_ascon::enc_128a/64            404 ns          400 ns      1740454 bytes_per_second=305.219M/s
bench_ascon::dec_128a/64            396 ns          392 ns      1782082 bytes_per_second=311.228M/s
bench_ascon::enc_128a/128           538 ns          532 ns      1283156 bytes_per_second=344.337M/s
bench_ascon::dec_128a/128           526 ns          520 ns      1329156 bytes_per_second=351.833M/s
bench_ascon::enc_128a/256           805 ns          796 ns       857801 bytes_per_second=383.316M/s
bench_ascon::dec_128a/256           790 ns          781 ns       877116 bytes_per_second=390.677M/s
bench_ascon::enc_128a/512          1336 ns         1321 ns       526609 bytes_per_second=415.685M/s
bench_ascon::dec_128a/512          1305 ns         1291 ns       540921 bytes_per_second=425.503M/s
bench_ascon::enc_128a/1024         2396 ns         2367 ns       294014 bytes_per_second=438.342M/s
bench_ascon::dec_128a/1024         2358 ns         2334 ns       297154 bytes_per_second=444.482M/s
bench_ascon::enc_128a/2048         4516 ns         4468 ns       156249 bytes_per_second=450.789M/s
bench_ascon::dec_128a/2048         4436 ns         4383 ns       159278 bytes_per_second=459.54M/s
bench_ascon::enc_128a/4096         8744 ns         8653 ns        78796 bytes_per_second=458.508M/s
bench_ascon::dec_128a/4096         8639 ns         8542 ns        79881 bytes_per_second=464.456M/s
bench_ascon::enc_80pq/64            534 ns          527 ns      1338816 bytes_per_second=231.414M/s
bench_ascon::dec_80pq/64            533 ns          527 ns      1312828 bytes_per_second=231.54M/s
bench_ascon::enc_80pq/128           734 ns          726 ns       936442 bytes_per_second=252.303M/s
bench_ascon::dec_80pq/128           739 ns          730 ns       946893 bytes_per_second=250.828M/s
bench_ascon::enc_80pq/256          1135 ns         1123 ns       611952 bytes_per_second=271.843M/s
bench_ascon::dec_80pq/256          1140 ns         1127 ns       619941 bytes_per_second=270.839M/s
bench_ascon::enc_80pq/512          1939 ns         1916 ns       360162 bytes_per_second=286.634M/s
bench_ascon::dec_80pq/512          1958 ns         1938 ns       357232 bytes_per_second=283.424M/s
bench_ascon::enc_80pq/1024         3550 ns         3512 ns       198419 bytes_per_second=295.425M/s
bench_ascon::dec_80pq/1024         3561 ns         3520 ns       196019 bytes_per_second=294.736M/s
bench_ascon::enc_80pq/2048         6796 ns         6727 ns       101464 bytes_per_second=299.419M/s
bench_ascon::dec_80pq/2048         6826 ns         6750 ns       102121 bytes_per_second=298.382M/s
bench_ascon::enc_80pq/4096        13209 ns        13066 ns        52953 bytes_per_second=303.64M/s
bench_ascon::dec_80pq/4096        13268 ns        13120 ns        52929 bytes_per_second=302.389M/s
```
