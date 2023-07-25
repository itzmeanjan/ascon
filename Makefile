CXX = g++
CXX_FLAGS = -std=c++20
WARN_FLAGS = -Wall -Wextra -pedantic
OPT_FLAGS = -O3 -march=native -mtune=native
IFLAGS = -I ./include
DEP_IFLAGS = -I ./subtle/include

all: test

tests/test_ascon_perm.o: tests/test_ascon_perm.cpp include/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) -c $< -o $@

tests/test_ascon128_aead.o: tests/test_ascon128_aead.cpp include/*.hpp include/aead/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) -c $< -o $@

tests/test_ascon128a_aead.o: tests/test_ascon128a_aead.cpp include/*.hpp include/aead/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) -c $< -o $@

tests/test_ascon80pq_aead.o: tests/test_ascon80pq_aead.cpp include/*.hpp include/aead/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) -c $< -o $@

tests/a.out: tests/test_ascon_perm.o tests/test_ascon128_aead.o tests/test_ascon128a_aead.o tests/test_ascon80pq_aead.o
	$(CXX) $(OPT_FLAGS) $^ -lgtest -lgtest_main -o $@

test: tests/a.out
	./$<

benchmarks/bench_ascon_perm.o: benchmarks/bench_ascon_perm.cpp include/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) -c $< -o $@

benchmarks/perf_ascon_perm.o: benchmarks/bench_ascon_perm.cpp include/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) -DCYCLES_PER_BYTE -DINSTRUCTIONS_PER_CYCLE -c $< -o $@

benchmarks/bench_ascon128_aead.o: benchmarks/bench_ascon128_aead.cpp include/*.hpp include/aead/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) -c $< -o $@

benchmarks/perf_ascon128_aead.o: benchmarks/bench_ascon128_aead.cpp include/*.hpp include/aead/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) -DCYCLES_PER_BYTE -DINSTRUCTIONS_PER_CYCLE -c $< -o $@

benchmarks/bench.out: benchmarks/bench_ascon_perm.o benchmarks/bench_ascon128_aead.o
	# In case you haven't built google-benchmark with libPFM support.
	# More @ https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7
	$(CXX) $(OPT_FLAGS) $^ -lbenchmark -lbenchmark_main -lpthread -o $@

benchmarks/perf.out: benchmarks/perf_ascon_perm.o benchmarks/perf_ascon128_aead.o
	# In case you've built google-benchmark with libPFM support.
	# More @ https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7
	$(CXX) $(OPT_FLAGS) $^ -lbenchmark -lbenchmark_main -lpthread -lpfm -o $@

bench: benchmarks/bench.out
	./$< --benchmark_counters_tabular=true --benchmark_min_warmup_time=1.

perf: benchmarks/perf.out
	./$< --benchmark_counters_tabular=true --benchmark_min_warmup_time=1. --benchmark_perf_counters=CYCLES,INSTRUCTIONS

clean:
	find . -name '*.out' -o -name '*.o' -o -name '*.gch' | xargs rm -rf

format:
	find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla
