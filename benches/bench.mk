BENCHMARK_BUILD_DIR := $(BUILD_DIR)/benchmark
PERF_BUILD_DIR := $(BUILD_DIR)/perf

BENCHMARK_DIR := benches
BENCHMARK_SOURCES := $(wildcard $(BENCHMARK_DIR)/*.cpp)
BENCHMARK_HEADERS := $(wildcard $(BENCHMARK_DIR)/*.hpp)
BENCHMARK_OBJECTS := $(addprefix $(BENCHMARK_BUILD_DIR)/, $(notdir $(BENCHMARK_SOURCES:.cpp=.o)))
BENCHMARK_LINK_FLAGS := -lbenchmark -lbenchmark_main -lpthread
BENCHMARK_BINARY := $(BENCHMARK_BUILD_DIR)/bench.out
PERF_OBJECTS := $(addprefix $(PERF_BUILD_DIR)/, $(notdir $(BENCHMARK_SOURCES:.cpp=.o)))
PERF_BINARY := $(PERF_BUILD_DIR)/perf.out
PERF_LINK_FLAGS := -lbenchmark -lbenchmark_main -lpfm -lpthread
BENCHMARK_OUT_FILE := bench_result_on_$(shell uname -s)_$(shell uname -r)_$(shell uname -m)_with_$(CXX)_$(shell $(CXX) -dumpversion).json

$(BENCHMARK_BUILD_DIR):
	mkdir -p $@

$(PERF_BUILD_DIR):
	mkdir -p $@

$(BENCHMARK_BUILD_DIR)/%.o: $(BENCHMARK_DIR)/%.cpp $(BENCHMARK_BUILD_DIR) $(SUBTLE_INC_DIR)
	$(CXX) $(CXX_DEFS) $(CXX_FLAGS) $(WARN_FLAGS) $(RELEASE_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

$(BENCHMARK_BINARY): $(BENCHMARK_OBJECTS)
	$(CXX) $(RELEASE_FLAGS) $(LINK_OPT_FLAGS) $^ $(BENCHMARK_LINK_FLAGS) -o $@

benchmark: $(BENCHMARK_BINARY) ## Build and run all benchmarks, without libPFM -based CPU CYCLE counter statistics
	# Must *not* build google-benchmark with libPFM
	./$< --benchmark_min_warmup_time=.05 --benchmark_enable_random_interleaving=false --benchmark_repetitions=10 --benchmark_min_time=0.1s --benchmark_display_aggregates_only=true --benchmark_report_aggregates_only=true --benchmark_counters_tabular=true --benchmark_out_format=json --benchmark_out=$(BENCHMARK_OUT_FILE)

$(PERF_BUILD_DIR)/%.o: $(BENCHMARK_DIR)/%.cpp $(PERF_BUILD_DIR) $(SUBTLE_INC_DIR)
	$(CXX) $(CXX_DEFS) $(CXX_FLAGS) $(WARN_FLAGS) $(RELEASE_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) $(PERF_DEFS) -c $< -o $@

$(PERF_BINARY): $(PERF_OBJECTS)
	$(CXX) $(RELEASE_FLAGS) $(LINK_OPT_FLAGS) $^ $(PERF_LINK_FLAGS) -o $@

perf: $(PERF_BINARY) ## Build and run all benchmarks, while also collecting libPFM -based CPU CYCLE counter statistics
	# Must build google-benchmark with libPFM, follow https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7
	./$< --benchmark_min_warmup_time=.05 --benchmark_enable_random_interleaving=false --benchmark_repetitions=10 --benchmark_min_time=0.1s --benchmark_display_aggregates_only=true --benchmark_report_aggregates_only=true --benchmark_counters_tabular=true --benchmark_perf_counters=CYCLES --benchmark_out_format=json --benchmark_out=$(BENCHMARK_OUT_FILE)
