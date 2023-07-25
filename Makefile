CXX = g++
CXX_FLAGS = -std=c++20
WARN_FLAGS = -Wall -Wextra -pedantic
OPT_FLAGS = -O3 -march=native -mtune=native
IFLAGS = -I ./include
DEP_IFLAGS = -I ./subtle/include

all: test

tests/test_ascon_perm.o: tests/test_ascon_perm.cpp include/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) -c $< -o $@

tests/a.out: tests/test_ascon_perm.o
	$(CXX) $(OPT_FLAGS) $^ -lgtest -lgtest_main -o $@

test: tests/a.out
	./$<

benchmarks/bench.out: benchmarks/main.cpp include/*.hpp include/*/*.hpp
	# In case you haven't built google-benchmark with libPFM support.
	# More @ https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) $< -lbenchmark -lpthread -o $@

benchmark: benchmarks/bench.out
	./$< --benchmark_counters_tabular=true

benchmarks/perf.out: benchmarks/main.cpp include/*.hpp include/*/*.hpp
	# In case you've built google-benchmark with libPFM support.
	# More @ https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) \
				-DCYCLES_PER_BYTE -DINSTRUCTIONS_PER_CYCLE $< -lbenchmark -lpthread -lpfm -o $@

perf: benchmarks/perf.out
	./$< --benchmark_counters_tabular=true --benchmark_perf_counters=CYCLES,INSTRUCTIONS

clean:
	find . -name '*.out' -o -name '*.o' -o -name '*.gch' | xargs rm -rf

format:
	find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla
