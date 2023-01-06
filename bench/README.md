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

### On AMD EPYC 7R32 ( when compiled with GCC )

```bash
2023-01-06T12:45:05+00:00
Running ./bench/a.out
Run on (48 X 2799.92 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x24)
  L1 Instruction 32 KiB (x24)
  L2 Unified 512 KiB (x24)
  L3 Unified 16384 KiB (x6)
Load Average: 0.36, 0.62, 1.16
----------------------------------------------------------------------------------------
Benchmark                              Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------------------
bench_ascon::permutation<1>         8.60 ns         8.60 ns     81474280 bytes_per_second=4.33271G/s
bench_ascon::permutation<6>         28.9 ns         28.9 ns     24279098 bytes_per_second=1.29053G/s
bench_ascon::permutation<8>         37.6 ns         37.6 ns     18610477 bytes_per_second=1014.81M/s
bench_ascon::permutation<12>        53.5 ns         53.5 ns     13118848 bytes_per_second=712.418M/s
bench_ascon::hash/64                 597 ns          597 ns      1169493 bytes_per_second=102.283M/s
bench_ascon::hash_a/64               416 ns          416 ns      1683535 bytes_per_second=146.728M/s
bench_ascon::hash/128                999 ns          999 ns       698274 bytes_per_second=122.174M/s
bench_ascon::hash_a/128              692 ns          692 ns      1012058 bytes_per_second=176.419M/s
bench_ascon::hash/256               1805 ns         1805 ns       386763 bytes_per_second=135.238M/s
bench_ascon::hash_a/256             1227 ns         1227 ns       570098 bytes_per_second=199.034M/s
bench_ascon::hash/512               3398 ns         3398 ns       205937 bytes_per_second=143.707M/s
bench_ascon::hash_a/512             2290 ns         2290 ns       305878 bytes_per_second=213.241M/s
bench_ascon::hash/1024              6593 ns         6593 ns       106555 bytes_per_second=148.122M/s
bench_ascon::hash_a/1024            4427 ns         4427 ns       157989 bytes_per_second=220.582M/s
bench_ascon::hash/2048             13000 ns        13000 ns        53832 bytes_per_second=150.243M/s
bench_ascon::hash_a/2048            8715 ns         8715 ns        80634 bytes_per_second=224.099M/s
bench_ascon::hash/4096             26769 ns        26768 ns        27249 bytes_per_second=145.927M/s
bench_ascon::hash_a/4096           17289 ns        17289 ns        40598 bytes_per_second=225.932M/s
bench_ascon::enc_128/64/32           422 ns          422 ns      1662098 bytes_per_second=216.978M/s
bench_ascon::dec_128/64/32           422 ns          422 ns      1662463 bytes_per_second=216.801M/s
bench_ascon::enc_128/128/32          618 ns          618 ns      1136288 bytes_per_second=246.899M/s
bench_ascon::dec_128/128/32          611 ns          611 ns      1145947 bytes_per_second=249.55M/s
bench_ascon::enc_128/256/32         1012 ns         1012 ns       691497 bytes_per_second=271.289M/s
bench_ascon::dec_128/256/32          999 ns          999 ns       700843 bytes_per_second=274.845M/s
bench_ascon::enc_128/512/32         1800 ns         1800 ns       389610 bytes_per_second=288.299M/s
bench_ascon::dec_128/512/32         1766 ns         1766 ns       395220 bytes_per_second=293.766M/s
bench_ascon::enc_128/1024/32        3374 ns         3374 ns       207468 bytes_per_second=298.515M/s
bench_ascon::dec_128/1024/32        3301 ns         3301 ns       212399 bytes_per_second=305.054M/s
bench_ascon::enc_128/2048/32        6517 ns         6517 ns       107647 bytes_per_second=304.386M/s
bench_ascon::dec_128/2048/32        6385 ns         6385 ns       109949 bytes_per_second=310.651M/s
bench_ascon::enc_128/4096/32       12787 ns        12786 ns        54723 bytes_per_second=307.892M/s
bench_ascon::dec_128/4096/32       12557 ns        12557 ns        55819 bytes_per_second=313.511M/s
bench_ascon::enc_128a/64/32          350 ns          350 ns      1998572 bytes_per_second=261.609M/s
bench_ascon::dec_128a/64/32          352 ns          352 ns      1987233 bytes_per_second=260.199M/s
bench_ascon::enc_128a/128/32         483 ns          483 ns      1445412 bytes_per_second=316.184M/s
bench_ascon::dec_128a/128/32         481 ns          481 ns      1455241 bytes_per_second=317.395M/s
bench_ascon::enc_128a/256/32         750 ns          750 ns       927467 bytes_per_second=366.392M/s
bench_ascon::dec_128a/256/32         745 ns          745 ns       937581 bytes_per_second=368.545M/s
bench_ascon::enc_128a/512/32        1274 ns         1274 ns       548670 bytes_per_second=407.319M/s
bench_ascon::dec_128a/512/32        1256 ns         1256 ns       555886 bytes_per_second=412.906M/s
bench_ascon::enc_128a/1024/32       2312 ns         2312 ns       301752 bytes_per_second=435.675M/s
bench_ascon::dec_128a/1024/32       2293 ns         2293 ns       305671 bytes_per_second=439.178M/s
bench_ascon::enc_128a/2048/32       4430 ns         4430 ns       158497 bytes_per_second=447.786M/s
bench_ascon::dec_128a/2048/32       4360 ns         4361 ns       160308 bytes_per_second=454.908M/s
bench_ascon::enc_128a/4096/32       8592 ns         8593 ns        81604 bytes_per_second=458.161M/s
bench_ascon::dec_128a/4096/32       8492 ns         8492 ns        82501 bytes_per_second=463.608M/s
bench_ascon::enc_80pq/64/32          421 ns          421 ns      1665809 bytes_per_second=217.285M/s
bench_ascon::dec_80pq/64/32          422 ns          422 ns      1658797 bytes_per_second=216.852M/s
bench_ascon::enc_80pq/128/32         615 ns          615 ns      1138395 bytes_per_second=247.988M/s
bench_ascon::dec_80pq/128/32         614 ns          614 ns      1140481 bytes_per_second=248.372M/s
bench_ascon::enc_80pq/256/32        1007 ns         1007 ns       696733 bytes_per_second=272.876M/s
bench_ascon::dec_80pq/256/32        1001 ns         1001 ns       697849 bytes_per_second=274.463M/s
bench_ascon::enc_80pq/512/32        1787 ns         1787 ns       392269 bytes_per_second=290.278M/s
bench_ascon::dec_80pq/512/32        1770 ns         1770 ns       395393 bytes_per_second=293.122M/s
bench_ascon::enc_80pq/1024/32       3345 ns         3345 ns       209186 bytes_per_second=301.102M/s
bench_ascon::dec_80pq/1024/32       3315 ns         3315 ns       209933 bytes_per_second=303.813M/s
bench_ascon::enc_80pq/2048/32       6474 ns         6475 ns       107923 bytes_per_second=306.376M/s
bench_ascon::dec_80pq/2048/32       6398 ns         6398 ns       109134 bytes_per_second=310.021M/s
bench_ascon::enc_80pq/4096/32      12708 ns        12708 ns        54975 bytes_per_second=309.78M/s
bench_ascon::dec_80pq/4096/32      12568 ns        12567 ns        55772 bytes_per_second=313.252M/s
```

### On AMD EPYC 7R32 ( when compiled with Clang )

```bash
2023-01-06T12:43:29+00:00
Running ./bench/a.out
Run on (48 X 2799.92 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x24)
  L1 Instruction 32 KiB (x24)
  L2 Unified 512 KiB (x24)
  L3 Unified 16384 KiB (x6)
Load Average: 0.23, 0.64, 1.23
----------------------------------------------------------------------------------------
Benchmark                              Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------------------
bench_ascon::permutation<1>         4.40 ns         4.40 ns    159352082 bytes_per_second=8.47111G/s
bench_ascon::permutation<6>         25.5 ns         25.5 ns     27403718 bytes_per_second=1.45909G/s
bench_ascon::permutation<8>         32.1 ns         32.1 ns     21773161 bytes_per_second=1.16025G/s
bench_ascon::permutation<12>        47.8 ns         47.8 ns     14532660 bytes_per_second=798.157M/s
bench_ascon::hash/64                 575 ns          575 ns      1216446 bytes_per_second=106.205M/s
bench_ascon::hash_a/64               391 ns          391 ns      1785286 bytes_per_second=155.929M/s
bench_ascon::hash/128                963 ns          963 ns       745224 bytes_per_second=126.813M/s
bench_ascon::hash_a/128              656 ns          656 ns      1068772 bytes_per_second=186.092M/s
bench_ascon::hash/256               1694 ns         1694 ns       411248 bytes_per_second=144.149M/s
bench_ascon::hash_a/256             1160 ns         1160 ns       603398 bytes_per_second=210.531M/s
bench_ascon::hash/512               3181 ns         3181 ns       219739 bytes_per_second=153.486M/s
bench_ascon::hash_a/512             2146 ns         2146 ns       325981 bytes_per_second=227.479M/s
bench_ascon::hash/1024              6155 ns         6155 ns       113271 bytes_per_second=158.654M/s
bench_ascon::hash_a/1024            4146 ns         4146 ns       168549 bytes_per_second=235.53M/s
bench_ascon::hash/2048             12120 ns        12120 ns        57864 bytes_per_second=161.149M/s
bench_ascon::hash_a/2048            8146 ns         8146 ns        85962 bytes_per_second=239.76M/s
bench_ascon::hash/4096             24022 ns        24022 ns        29172 bytes_per_second=162.61M/s
bench_ascon::hash_a/4096           16171 ns        16171 ns        43107 bytes_per_second=241.555M/s
bench_ascon::enc_128/64/32           466 ns          466 ns      1505212 bytes_per_second=196.28M/s
bench_ascon::dec_128/64/32           455 ns          455 ns      1537945 bytes_per_second=201.337M/s
bench_ascon::enc_128/128/32          694 ns          694 ns      1012233 bytes_per_second=219.903M/s
bench_ascon::dec_128/128/32          663 ns          663 ns      1041001 bytes_per_second=230.198M/s
bench_ascon::enc_128/256/32         1141 ns         1141 ns       610784 bytes_per_second=240.617M/s
bench_ascon::dec_128/256/32         1086 ns         1086 ns       645051 bytes_per_second=252.864M/s
bench_ascon::enc_128/512/32         2051 ns         2051 ns       341111 bytes_per_second=252.94M/s
bench_ascon::dec_128/512/32         1921 ns         1921 ns       363877 bytes_per_second=269.999M/s
bench_ascon::enc_128/1024/32        3876 ns         3876 ns       180694 bytes_per_second=259.802M/s
bench_ascon::dec_128/1024/32        3569 ns         3569 ns       195782 bytes_per_second=282.162M/s
bench_ascon::enc_128/2048/32        7455 ns         7455 ns        93865 bytes_per_second=266.075M/s
bench_ascon::dec_128/2048/32        6908 ns         6908 ns       101280 bytes_per_second=287.152M/s
bench_ascon::enc_128/4096/32       14642 ns        14642 ns        47855 bytes_per_second=268.859M/s
bench_ascon::dec_128/4096/32       13556 ns        13557 ns        51619 bytes_per_second=290.396M/s
bench_ascon::enc_128a/64/32          354 ns          354 ns      1983005 bytes_per_second=258.96M/s
bench_ascon::dec_128a/64/32          352 ns          352 ns      1975733 bytes_per_second=260.183M/s
bench_ascon::enc_128a/128/32         479 ns          479 ns      1463446 bytes_per_second=318.561M/s
bench_ascon::dec_128a/128/32         477 ns          477 ns      1462037 bytes_per_second=320.037M/s
bench_ascon::enc_128a/256/32         751 ns          751 ns       925792 bytes_per_second=365.803M/s
bench_ascon::dec_128a/256/32         735 ns          735 ns       945545 bytes_per_second=373.906M/s
bench_ascon::enc_128a/512/32        1262 ns         1262 ns       557829 bytes_per_second=410.933M/s
bench_ascon::dec_128a/512/32        1229 ns         1229 ns       569172 bytes_per_second=422.086M/s
bench_ascon::enc_128a/1024/32       2274 ns         2274 ns       308259 bytes_per_second=442.825M/s
bench_ascon::dec_128a/1024/32       2228 ns         2228 ns       313910 bytes_per_second=452.067M/s
bench_ascon::enc_128a/2048/32       4300 ns         4300 ns       162781 bytes_per_second=461.31M/s
bench_ascon::dec_128a/2048/32       4218 ns         4218 ns       165794 bytes_per_second=470.286M/s
bench_ascon::enc_128a/4096/32       8360 ns         8360 ns        83735 bytes_per_second=470.901M/s
bench_ascon::dec_128a/4096/32       8217 ns         8217 ns        85455 bytes_per_second=479.128M/s
bench_ascon::enc_80pq/64/32          462 ns          462 ns      1514520 bytes_per_second=198.222M/s
bench_ascon::dec_80pq/64/32          451 ns          451 ns      1551066 bytes_per_second=202.933M/s
bench_ascon::enc_80pq/128/32         681 ns          681 ns      1028676 bytes_per_second=223.935M/s
bench_ascon::dec_80pq/128/32         670 ns          670 ns      1063233 bytes_per_second=227.754M/s
bench_ascon::enc_80pq/256/32        1132 ns         1132 ns       619092 bytes_per_second=242.718M/s
bench_ascon::dec_80pq/256/32        1085 ns         1085 ns       638814 bytes_per_second=253.235M/s
bench_ascon::enc_80pq/512/32        2002 ns         2002 ns       350277 bytes_per_second=259.144M/s
bench_ascon::dec_80pq/512/32        1915 ns         1915 ns       364758 bytes_per_second=270.974M/s
bench_ascon::enc_80pq/1024/32       3730 ns         3730 ns       186893 bytes_per_second=269.992M/s
bench_ascon::dec_80pq/1024/32       3577 ns         3577 ns       195322 bytes_per_second=281.531M/s
bench_ascon::enc_80pq/2048/32       7181 ns         7181 ns        97325 bytes_per_second=276.229M/s
bench_ascon::dec_80pq/2048/32       6923 ns         6923 ns       101211 bytes_per_second=286.535M/s
bench_ascon::enc_80pq/4096/32      14250 ns        14250 ns        49199 bytes_per_second=276.263M/s
bench_ascon::dec_80pq/4096/32      13611 ns        13611 ns        51519 bytes_per_second=289.235M/s
```

### On Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz ( when compiled with GCC )

```bash
2023-01-06T12:49:15+00:00
Running ./bench/a.out
Run on (128 X 1027.28 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x64)
  L1 Instruction 32 KiB (x64)
  L2 Unified 1280 KiB (x64)
  L3 Unified 55296 KiB (x2)
Load Average: 0.08, 0.02, 0.01
----------------------------------------------------------------------------------------
Benchmark                              Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------------------
bench_ascon::permutation<1>         7.08 ns         7.08 ns     98849119 bytes_per_second=5.26426G/s
bench_ascon::permutation<6>         28.2 ns         28.2 ns     24737484 bytes_per_second=1.3201G/s
bench_ascon::permutation<8>         37.2 ns         37.2 ns     18803222 bytes_per_second=1024.75M/s
bench_ascon::permutation<12>        54.7 ns         54.7 ns     12787309 bytes_per_second=696.913M/s
bench_ascon::hash/64                 621 ns          621 ns      1127894 bytes_per_second=98.3504M/s
bench_ascon::hash_a/64               431 ns          431 ns      1624201 bytes_per_second=141.608M/s
bench_ascon::hash/128               1041 ns         1041 ns       672069 bytes_per_second=117.208M/s
bench_ascon::hash_a/128              712 ns          712 ns       983337 bytes_per_second=171.476M/s
bench_ascon::hash/256               1890 ns         1890 ns       370418 bytes_per_second=129.206M/s
bench_ascon::hash_a/256             1279 ns         1279 ns       547068 bytes_per_second=190.833M/s
bench_ascon::hash/512               3573 ns         3573 ns       195914 bytes_per_second=136.644M/s
bench_ascon::hash_a/512             2403 ns         2403 ns       291328 bytes_per_second=203.204M/s
bench_ascon::hash/1024              6942 ns         6942 ns       100867 bytes_per_second=140.681M/s
bench_ascon::hash_a/1024            4649 ns         4649 ns       150543 bytes_per_second=210.054M/s
bench_ascon::hash/2048             13675 ns        13676 ns        51187 bytes_per_second=142.819M/s
bench_ascon::hash_a/2048            9143 ns         9144 ns        76552 bytes_per_second=213.607M/s
bench_ascon::hash/4096             27148 ns        27148 ns        25788 bytes_per_second=143.886M/s
bench_ascon::hash_a/4096           18129 ns        18129 ns        38601 bytes_per_second=215.466M/s
bench_ascon::enc_128/64/32           446 ns          446 ns      1568356 bytes_per_second=205.151M/s
bench_ascon::dec_128/64/32           447 ns          447 ns      1563236 bytes_per_second=204.838M/s
bench_ascon::enc_128/128/32          660 ns          660 ns      1059927 bytes_per_second=231.068M/s
bench_ascon::dec_128/128/32          657 ns          657 ns      1065148 bytes_per_second=232.226M/s
bench_ascon::enc_128/256/32         1088 ns         1088 ns       643328 bytes_per_second=252.422M/s
bench_ascon::dec_128/256/32         1078 ns         1078 ns       649843 bytes_per_second=254.899M/s
bench_ascon::enc_128/512/32         1944 ns         1944 ns       360105 bytes_per_second=266.895M/s
bench_ascon::dec_128/512/32         1918 ns         1918 ns       364913 bytes_per_second=270.444M/s
bench_ascon::enc_128/1024/32        3655 ns         3655 ns       191456 bytes_per_second=275.512M/s
bench_ascon::dec_128/1024/32        3606 ns         3606 ns       194152 bytes_per_second=279.258M/s
bench_ascon::enc_128/2048/32        7085 ns         7085 ns        98756 bytes_per_second=279.965M/s
bench_ascon::dec_128/2048/32        6970 ns         6970 ns       100382 bytes_per_second=284.6M/s
bench_ascon::enc_128/4096/32       13935 ns        13935 ns        50222 bytes_per_second=282.515M/s
bench_ascon::dec_128/4096/32       13696 ns        13696 ns        51121 bytes_per_second=287.449M/s
bench_ascon::enc_128a/64/32          362 ns          362 ns      1935021 bytes_per_second=253.065M/s
bench_ascon::dec_128a/64/32          358 ns          358 ns      1952022 bytes_per_second=255.834M/s
bench_ascon::enc_128a/128/32         507 ns          507 ns      1379937 bytes_per_second=300.836M/s
bench_ascon::dec_128a/128/32         498 ns          498 ns      1406240 bytes_per_second=306.507M/s
bench_ascon::enc_128a/256/32         798 ns          798 ns       877312 bytes_per_second=344.229M/s
bench_ascon::dec_128a/256/32         778 ns          778 ns       900257 bytes_per_second=353.246M/s
bench_ascon::enc_128a/512/32        1385 ns         1385 ns       505521 bytes_per_second=374.71M/s
bench_ascon::dec_128a/512/32        1344 ns         1344 ns       520882 bytes_per_second=385.983M/s
bench_ascon::enc_128a/1024/32       2547 ns         2547 ns       274815 bytes_per_second=395.363M/s
bench_ascon::dec_128a/1024/32       2464 ns         2464 ns       284210 bytes_per_second=408.727M/s
bench_ascon::enc_128a/2048/32       4873 ns         4873 ns       143633 bytes_per_second=407.061M/s
bench_ascon::dec_128a/2048/32       4702 ns         4702 ns       148856 bytes_per_second=421.854M/s
bench_ascon::enc_128a/4096/32       9527 ns         9527 ns        73478 bytes_per_second=413.236M/s
bench_ascon::dec_128a/4096/32       9178 ns         9179 ns        76277 bytes_per_second=428.907M/s
bench_ascon::enc_80pq/64/32          451 ns          451 ns      1550266 bytes_per_second=202.781M/s
bench_ascon::dec_80pq/64/32          448 ns          448 ns      1559914 bytes_per_second=204.423M/s
bench_ascon::enc_80pq/128/32         665 ns          665 ns      1052473 bytes_per_second=229.427M/s
bench_ascon::dec_80pq/128/32         657 ns          657 ns      1065555 bytes_per_second=232.279M/s
bench_ascon::enc_80pq/256/32        1093 ns         1093 ns       640714 bytes_per_second=251.386M/s
bench_ascon::dec_80pq/256/32        1075 ns         1075 ns       650891 bytes_per_second=255.489M/s
bench_ascon::enc_80pq/512/32        1947 ns         1947 ns       359523 bytes_per_second=266.445M/s
bench_ascon::dec_80pq/512/32        1911 ns         1911 ns       366192 bytes_per_second=271.467M/s
bench_ascon::enc_80pq/1024/32       3657 ns         3657 ns       191474 bytes_per_second=275.388M/s
bench_ascon::dec_80pq/1024/32       3590 ns         3590 ns       194960 bytes_per_second=280.533M/s
bench_ascon::enc_80pq/2048/32       7083 ns         7083 ns        98871 bytes_per_second=280.056M/s
bench_ascon::dec_80pq/2048/32       6936 ns         6936 ns       100962 bytes_per_second=285.993M/s
bench_ascon::enc_80pq/4096/32      13922 ns        13922 ns        50275 bytes_per_second=282.773M/s
bench_ascon::dec_80pq/4096/32      13628 ns        13628 ns        51355 bytes_per_second=288.877M/s
```

### On Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz ( when compiled with Clang )

```bash
2023-01-06T12:51:44+00:00
Running ./bench/a.out
Run on (128 X 848.536 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x64)
  L1 Instruction 32 KiB (x64)
  L2 Unified 1280 KiB (x64)
  L3 Unified 55296 KiB (x2)
Load Average: 0.16, 0.15, 0.06
----------------------------------------------------------------------------------------
Benchmark                              Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------------------
bench_ascon::permutation<1>         5.79 ns         5.79 ns    120980415 bytes_per_second=6.43707G/s
bench_ascon::permutation<6>         26.7 ns         26.7 ns     26174762 bytes_per_second=1.3931G/s
bench_ascon::permutation<8>         39.9 ns         39.9 ns     17563943 bytes_per_second=957.095M/s
bench_ascon::permutation<12>        58.9 ns         58.9 ns     11880466 bytes_per_second=647.633M/s
bench_ascon::hash/64                 599 ns          599 ns      1169193 bytes_per_second=101.952M/s
bench_ascon::hash_a/64               414 ns          414 ns      1692179 bytes_per_second=147.546M/s
bench_ascon::hash/128                996 ns          996 ns       702905 bytes_per_second=122.564M/s
bench_ascon::hash_a/128              679 ns          679 ns      1030993 bytes_per_second=179.802M/s
bench_ascon::hash/256               1796 ns         1796 ns       389745 bytes_per_second=135.96M/s
bench_ascon::hash_a/256             1215 ns         1214 ns       576396 bytes_per_second=201.023M/s
bench_ascon::hash/512               3383 ns         3383 ns       206907 bytes_per_second=144.33M/s
bench_ascon::hash_a/512             2274 ns         2274 ns       307923 bytes_per_second=214.767M/s
bench_ascon::hash/1024              6560 ns         6560 ns       106717 bytes_per_second=148.872M/s
bench_ascon::hash_a/1024            4392 ns         4393 ns       159367 bytes_per_second=222.322M/s
bench_ascon::hash/2048             12909 ns        12909 ns        54224 bytes_per_second=151.299M/s
bench_ascon::hash_a/2048            8632 ns         8632 ns        81107 bytes_per_second=226.273M/s
bench_ascon::hash/4096             25615 ns        25614 ns        27328 bytes_per_second=152.503M/s
bench_ascon::hash_a/4096           17106 ns        17107 ns        40920 bytes_per_second=228.347M/s
bench_ascon::enc_128/64/32           450 ns          450 ns      1555123 bytes_per_second=203.326M/s
bench_ascon::dec_128/64/32           448 ns          448 ns      1561793 bytes_per_second=204.293M/s
bench_ascon::enc_128/128/32          664 ns          664 ns      1056460 bytes_per_second=229.878M/s
bench_ascon::dec_128/128/32          658 ns          658 ns      1063541 bytes_per_second=231.776M/s
bench_ascon::enc_128/256/32         1087 ns         1087 ns       643750 bytes_per_second=252.668M/s
bench_ascon::dec_128/256/32         1079 ns         1079 ns       648793 bytes_per_second=254.618M/s
bench_ascon::enc_128/512/32         1934 ns         1934 ns       361131 bytes_per_second=268.207M/s
bench_ascon::dec_128/512/32         1920 ns         1920 ns       364307 bytes_per_second=270.249M/s
bench_ascon::enc_128/1024/32        3641 ns         3641 ns       192365 bytes_per_second=276.584M/s
bench_ascon::dec_128/1024/32        3610 ns         3610 ns       194129 bytes_per_second=278.982M/s
bench_ascon::enc_128/2048/32        7035 ns         7035 ns        99430 bytes_per_second=281.951M/s
bench_ascon::dec_128/2048/32        6978 ns         6978 ns       100364 bytes_per_second=284.279M/s
bench_ascon::enc_128/4096/32       13820 ns        13820 ns        50610 bytes_per_second=284.864M/s
bench_ascon::dec_128/4096/32       13704 ns        13704 ns        50976 bytes_per_second=287.268M/s
bench_ascon::enc_128a/64/32          401 ns          401 ns      1744283 bytes_per_second=228.094M/s
bench_ascon::dec_128a/64/32          393 ns          393 ns      1779304 bytes_per_second=232.759M/s
bench_ascon::enc_128a/128/32         555 ns          555 ns      1260873 bytes_per_second=274.885M/s
bench_ascon::dec_128a/128/32         546 ns          546 ns      1281165 bytes_per_second=279.398M/s
bench_ascon::enc_128a/256/32         863 ns          863 ns       811544 bytes_per_second=318.422M/s
bench_ascon::dec_128a/256/32         852 ns          852 ns       821639 bytes_per_second=322.404M/s
bench_ascon::enc_128a/512/32        1478 ns         1479 ns       473359 bytes_per_second=350.894M/s
bench_ascon::dec_128a/512/32        1472 ns         1472 ns       475592 bytes_per_second=352.537M/s
bench_ascon::enc_128a/1024/32       2708 ns         2708 ns       258460 bytes_per_second=371.826M/s
bench_ascon::dec_128a/1024/32       2695 ns         2695 ns       259801 bytes_per_second=373.732M/s
bench_ascon::enc_128a/2048/32       5169 ns         5169 ns       135436 bytes_per_second=383.733M/s
bench_ascon::dec_128a/2048/32       5141 ns         5141 ns       136126 bytes_per_second=385.812M/s
bench_ascon::enc_128a/4096/32      10089 ns        10089 ns        69382 bytes_per_second=390.209M/s
bench_ascon::dec_128a/4096/32      10033 ns        10033 ns        69778 bytes_per_second=392.366M/s
bench_ascon::enc_80pq/64/32          459 ns          459 ns      1524421 bytes_per_second=199.401M/s
bench_ascon::dec_80pq/64/32          458 ns          458 ns      1528139 bytes_per_second=199.852M/s
bench_ascon::enc_80pq/128/32         674 ns          674 ns      1038227 bytes_per_second=226.42M/s
bench_ascon::dec_80pq/128/32         669 ns          669 ns      1046357 bytes_per_second=228.241M/s
bench_ascon::enc_80pq/256/32        1103 ns         1103 ns       635105 bytes_per_second=249.012M/s
bench_ascon::dec_80pq/256/32        1091 ns         1091 ns       642148 bytes_per_second=251.861M/s
bench_ascon::enc_80pq/512/32        1959 ns         1959 ns       357166 bytes_per_second=264.85M/s
bench_ascon::dec_80pq/512/32        1933 ns         1933 ns       362022 bytes_per_second=268.373M/s
bench_ascon::enc_80pq/1024/32       3683 ns         3683 ns       190051 bytes_per_second=273.441M/s
bench_ascon::dec_80pq/1024/32       3627 ns         3627 ns       192875 bytes_per_second=277.676M/s
bench_ascon::enc_80pq/2048/32       7110 ns         7110 ns        98276 bytes_per_second=278.978M/s
bench_ascon::dec_80pq/2048/32       7003 ns         7003 ns       100017 bytes_per_second=283.257M/s
bench_ascon::enc_80pq/4096/32      13965 ns        13965 ns        50140 bytes_per_second=281.896M/s
bench_ascon::dec_80pq/4096/32      13745 ns        13745 ns        50941 bytes_per_second=286.413M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz ( when compiled with Clang )

```bash
2023-01-06T16:56:23+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 2.25, 1.96, 1.85
----------------------------------------------------------------------------------------
Benchmark                              Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------------------
bench_ascon::permutation<1>         4.73 ns         4.68 ns    124521925 bytes_per_second=7.96574G/s
bench_ascon::permutation<6>         25.3 ns         25.0 ns     27161260 bytes_per_second=1.49099G/s
bench_ascon::permutation<8>         35.4 ns         33.9 ns     21023673 bytes_per_second=1124.51M/s
bench_ascon::permutation<12>        49.7 ns         49.2 ns     13964530 bytes_per_second=775.653M/s
bench_ascon::hash/64                 562 ns          560 ns      1235091 bytes_per_second=108.907M/s
bench_ascon::hash_a/64               407 ns          403 ns      1584187 bytes_per_second=151.58M/s
bench_ascon::hash/128                971 ns          962 ns       689255 bytes_per_second=126.841M/s
bench_ascon::hash_a/128              658 ns          653 ns      1034600 bytes_per_second=187.026M/s
bench_ascon::hash/256               1760 ns         1750 ns       393241 bytes_per_second=139.548M/s
bench_ascon::hash_a/256             1189 ns         1178 ns       581806 bytes_per_second=207.283M/s
bench_ascon::hash/512               3231 ns         3220 ns       218017 bytes_per_second=151.66M/s
bench_ascon::hash_a/512             2201 ns         2159 ns       322158 bytes_per_second=226.111M/s
bench_ascon::hash/1024              6620 ns         6511 ns       106364 bytes_per_second=149.98M/s
bench_ascon::hash_a/1024            4224 ns         4195 ns       165815 bytes_per_second=232.784M/s
bench_ascon::hash/2048             12625 ns        12522 ns        54615 bytes_per_second=155.981M/s
bench_ascon::hash_a/2048            8409 ns         8339 ns        85579 bytes_per_second=234.219M/s
bench_ascon::hash/4096             24431 ns        24270 ns        27028 bytes_per_second=160.95M/s
bench_ascon::hash_a/4096           16332 ns        16248 ns        41928 bytes_per_second=240.414M/s
bench_ascon::enc_128/64/32           423 ns          421 ns      1668419 bytes_per_second=217.633M/s
bench_ascon::dec_128/64/32           433 ns          429 ns      1708817 bytes_per_second=213.371M/s
bench_ascon::enc_128/128/32          648 ns          640 ns      1062764 bytes_per_second=238.281M/s
bench_ascon::dec_128/128/32          651 ns          645 ns      1029487 bytes_per_second=236.59M/s
bench_ascon::enc_128/256/32         1027 ns         1021 ns       708115 bytes_per_second=269.09M/s
bench_ascon::dec_128/256/32          977 ns          976 ns       687690 bytes_per_second=281.388M/s
bench_ascon::enc_128/512/32         1752 ns         1750 ns       393219 bytes_per_second=296.46M/s
bench_ascon::dec_128/512/32         1764 ns         1762 ns       396646 bytes_per_second=294.379M/s
bench_ascon::enc_128/1024/32        3282 ns         3278 ns       209940 bytes_per_second=307.178M/s
bench_ascon::dec_128/1024/32        3304 ns         3301 ns       207684 bytes_per_second=305.067M/s
bench_ascon::enc_128/2048/32        6412 ns         6396 ns       110288 bytes_per_second=310.119M/s
bench_ascon::dec_128/2048/32        7238 ns         7124 ns        96678 bytes_per_second=278.457M/s
bench_ascon::enc_128/4096/32       13576 ns        13362 ns        54401 bytes_per_second=294.627M/s
bench_ascon::dec_128/4096/32       13085 ns        13007 ns        53879 bytes_per_second=302.655M/s
bench_ascon::enc_128a/64/32          350 ns          350 ns      1932826 bytes_per_second=261.512M/s
bench_ascon::dec_128a/64/32          380 ns          376 ns      2005036 bytes_per_second=243.476M/s
bench_ascon::enc_128a/128/32         508 ns          503 ns      1325331 bytes_per_second=303.117M/s
bench_ascon::dec_128a/128/32         482 ns          479 ns      1480626 bytes_per_second=318.364M/s
bench_ascon::enc_128a/256/32         789 ns          779 ns       908183 bytes_per_second=352.643M/s
bench_ascon::dec_128a/256/32         778 ns          769 ns       882557 bytes_per_second=357.3M/s
bench_ascon::enc_128a/512/32        1213 ns         1212 ns       574788 bytes_per_second=428.035M/s
bench_ascon::dec_128a/512/32        1337 ns         1323 ns       577396 bytes_per_second=392.022M/s
bench_ascon::enc_128a/1024/32       2258 ns         2252 ns       291266 bytes_per_second=447.164M/s
bench_ascon::dec_128a/1024/32       2192 ns         2189 ns       315232 bytes_per_second=460.094M/s
bench_ascon::enc_128a/2048/32       4398 ns         4350 ns       157749 bytes_per_second=456.008M/s
bench_ascon::dec_128a/2048/32       4620 ns         4559 ns       169528 bytes_per_second=435.128M/s
bench_ascon::enc_128a/4096/32       8052 ns         8046 ns        81555 bytes_per_second=489.259M/s
bench_ascon::dec_128a/4096/32       8031 ns         8023 ns        85692 bytes_per_second=490.684M/s
bench_ascon::enc_80pq/64/32          413 ns          412 ns      1695535 bytes_per_second=222.049M/s
bench_ascon::dec_80pq/64/32          418 ns          417 ns      1696020 bytes_per_second=219.666M/s
bench_ascon::enc_80pq/128/32         621 ns          619 ns      1078084 bytes_per_second=246.687M/s
bench_ascon::dec_80pq/128/32         613 ns          612 ns      1127704 bytes_per_second=249.168M/s
bench_ascon::enc_80pq/256/32         982 ns          981 ns       701797 bytes_per_second=279.882M/s
bench_ascon::dec_80pq/256/32         984 ns          983 ns       695362 bytes_per_second=279.36M/s
bench_ascon::enc_80pq/512/32        1784 ns         1778 ns       400009 bytes_per_second=291.801M/s
bench_ascon::dec_80pq/512/32        1931 ns         1906 ns       364627 bytes_per_second=272.183M/s
bench_ascon::enc_80pq/1024/32       3451 ns         3417 ns       191437 bytes_per_second=294.723M/s
bench_ascon::dec_80pq/1024/32       3512 ns         3478 ns       204852 bytes_per_second=289.528M/s
bench_ascon::enc_80pq/2048/32       6748 ns         6675 ns       110307 bytes_per_second=297.165M/s
bench_ascon::dec_80pq/2048/32       6813 ns         6746 ns       100699 bytes_per_second=294.042M/s
bench_ascon::enc_80pq/4096/32      13370 ns        13230 ns        52011 bytes_per_second=297.555M/s
bench_ascon::dec_80pq/4096/32      12688 ns        12649 ns        52823 bytes_per_second=311.224M/s
```
