CXX = g++
CXX_FLAGS = -std=c++20
WARN_FLAGS = -Wall -Wextra -pedantic
OPT_FLAGS = -O3 -march=native -mtune=native
IFLAGS = -I ./include
DEP_IFLAGS = -I ./subtle/include

all: test

tests/a.out: tests/main.cpp include/*.hpp include/*/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) $< -o $@

test: tests/a.out
	./$<

benchmarks/main.o: benchmarks/main.cpp include/*.hpp include/*/*.hpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(IFLAGS) $(DEP_IFLAGS) -c $< -o $@

benchmarks/bench.out: benchmarks/main.o
	# In case you haven't built google-benchmark with libPFM support.
	# More @ https://github.com/google/benchmark/blob/b323288cbac5fd1dd35f153e767497a23c337742/docs/perf_counters.md
	$(CXX) $(OPT_FLAGS) $^ -lbenchmark -o $@

benchmark: benchmarks/bench.out
	./$< --benchmark_counters_tabular=true

benchmarks/perf.out: benchmarks/main.o
	# In case you've built google-benchmark with libPFM support.
	# More @ https://github.com/google/benchmark/blob/b323288cbac5fd1dd35f153e767497a23c337742/docs/perf_counters.md
	$(CXX) $(OPT_FLAGS) $^ -lbenchmark -lpfm -o $@

perf: benchmarks/perf.out
	./$< --benchmark_counters_tabular=true --benchmark_perf_counters=CYCLES

clean:
	find . -name '*.out' -o -name '*.o' -o -name '*.gch' | xargs rm -rf

format:
	find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla
