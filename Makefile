CXX = g++
CXX_FLAGS = -std=c++20
WARN_FLAGS = -Wall -Wextra -pedantic
OPT_FLAGS = -O3 -march=native -mtune=native
IFLAGS = -I ./include
DEP_IFLAGS = -I ./subtle/include

all: test

test/a.out: test/main.cpp include/*.hpp include/test/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) $< -o $@

test: test/a.out
	./$<

bench/main.o: bench/main.cpp include/*.hpp include/bench/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) -c $< -o $@

bench/bench.out: bench/main.o
	# In case you haven't built google-benchmark with libPFM support.
	# More @ https://github.com/google/benchmark/blob/b323288cbac5fd1dd35f153e767497a23c337742/docs/perf_counters.md
	$(CXX) $(OPT_FLAGS) $^ -lbenchmark -o $@

benchmark: bench/bench.out
	./$< --benchmark_counters_tabular=true

bench/perf.out: bench/main.o
	# In case you've built google-benchmark with libPFM support.
	# More @ https://github.com/google/benchmark/blob/b323288cbac5fd1dd35f153e767497a23c337742/docs/perf_counters.md
	$(CXX) $(OPT_FLAGS) $^ -lbenchmark -lpfm -o $@

perf: bench/perf.out
	./$< --benchmark_counters_tabular=true --benchmark_perf_counters=CYCLES

clean:
	find . -name '*.out' -o -name '*.o' -o -name '*.gch' | xargs rm -rf

format:
	find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla
