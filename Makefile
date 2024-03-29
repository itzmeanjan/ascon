CXX ?= clang++
CXX_FLAGS = -std=c++20
WARN_FLAGS = -Wall -Wextra -pedantic
OPT_FLAGS = -O3 -march=native
LINK_FLAGS = -flto
PERF_DEFS = -DCYCLES_PER_BYTE
ASAN_FLAGS = -g -O1 -fno-omit-frame-pointer -fno-optimize-sibling-calls -fsanitize=address # From https://clang.llvm.org/docs/AddressSanitizer.html
UBSAN_FLAGS = -g -O1 -fno-omit-frame-pointer -fno-optimize-sibling-calls -fsanitize=undefined # From https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html

SRC_DIR = include
SUBTLE_INC_DIR = ./subtle/include
DUDECT_INC_DIR = ./dudect/src
I_FLAGS = -I $(SRC_DIR)
DEP_IFLAGS = -I $(SUBTLE_INC_DIR)
DUDECT_DEP_IFLAGS = $(DEP_IFLAGS) -I $(DUDECT_INC_DIR)
ASCON_SOURCES := $(wildcard $(SRC_DIR)/*.hpp)
BUILD_DIR = build

TEST_DIR = tests
DUDECT_TEST_DIR = $(TEST_DIR)/dudect
TEST_BUILD_DIR := $(BUILD_DIR)/$(TEST_DIR)
ASAN_BUILD_DIR = $(TEST_BUILD_DIR)/asan
UBSAN_BUILD_DIR = $(TEST_BUILD_DIR)/ubsan
DUDECT_BUILD_DIR = $(BUILD_DIR)/dudect
TEST_SOURCES := $(wildcard $(TEST_DIR)/*.cpp)
TEST_HEADERS := $(wildcard $(TEST_DIR)/*.hpp)
DUDECT_TEST_SOURCES := $(wildcard $(DUDECT_TEST_DIR)/*.cpp)
TEST_OBJECTS := $(addprefix $(TEST_BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.o,$(TEST_SOURCES))))
ASAN_TEST_OBJECTS := $(addprefix $(ASAN_BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.o,$(TEST_SOURCES))))
UBSAN_TEST_OBJECTS := $(addprefix $(UBSAN_BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.o,$(TEST_SOURCES))))
TEST_LINK_FLAGS = -lgtest -lgtest_main
TEST_BINARY = $(TEST_BUILD_DIR)/test.out
ASAN_TEST_BINARY = $(ASAN_BUILD_DIR)/test.out
UBSAN_TEST_BINARY = $(UBSAN_BUILD_DIR)/test.out
DUDECT_TEST_BINARIES := $(addprefix $(DUDECT_BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.out,$(DUDECT_TEST_SOURCES))))
GTEST_PARALLEL = ./gtest-parallel/gtest-parallel

BENCHMARK_DIR = benchmarks
BENCHMARK_SOURCES := $(wildcard $(BENCHMARK_DIR)/*.cpp)
BENCHMARK_HEADERS := $(wildcard $(BENCHMARK_DIR)/*.hpp)
BENCHMARK_BUILD_DIR := $(BUILD_DIR)/$(BENCHMARK_DIR)
PERF_BUILD_DIR := $(BUILD_DIR)/perfs
BENCHMARK_OBJECTS := $(addprefix $(BENCHMARK_BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.o,$(BENCHMARK_SOURCES))))
PERF_OBJECTS := $(addprefix $(PERF_BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.o,$(BENCHMARK_SOURCES))))
BENCHMARK_LINK_FLAGS = -lbenchmark -lbenchmark_main
BENCHMARK_BINARY = $(BENCHMARK_BUILD_DIR)/bench.out
PERF_LINK_FLAGS = -lbenchmark -lbenchmark_main -lpthread -lpfm
PERF_BINARY = $(PERF_BUILD_DIR)/perf.out

all: test

$(BUILD_DIR):
	mkdir -p $@

$(TEST_BUILD_DIR): $(BUILD_DIR)
	mkdir -p $@

$(ASAN_BUILD_DIR): $(TEST_BUILD_DIR)
	mkdir -p $@

$(UBSAN_BUILD_DIR): $(TEST_BUILD_DIR)
	mkdir -p $@

$(DUDECT_BUILD_DIR): $(TEST_BUILD_DIR)
	mkdir -p $@

$(BENCHMARK_BUILD_DIR): $(BUILD_DIR)
	mkdir -p $@

$(PERF_BUILD_DIR): $(BUILD_DIR)
	mkdir -p $@

$(SUBTLE_INC_DIR):
	git submodule update --init subtle

$(GTEST_PARALLEL): $(SUBTLE_INC_DIR)
	git submodule update --init gtest-parallel

$(DUDECT_INC_DIR): $(GTEST_PARALLEL)
	git submodule update --init dudect

$(TEST_BUILD_DIR)/%.o: $(TEST_DIR)/%.cpp $(TEST_BUILD_DIR) $(SUBTLE_INC_DIR)
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

$(ASAN_BUILD_DIR)/%.o: $(TEST_DIR)/%.cpp $(ASAN_BUILD_DIR) $(SUBTLE_INC_DIR)
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(ASAN_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

$(UBSAN_BUILD_DIR)/%.o: $(TEST_DIR)/%.cpp $(UBSAN_BUILD_DIR) $(SUBTLE_INC_DIR)
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(UBSAN_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

$(TEST_BINARY): $(TEST_OBJECTS)
	$(CXX) $(OPT_FLAGS) $(LINK_FLAGS) $^ $(TEST_LINK_FLAGS) -o $@

$(ASAN_TEST_BINARY): $(ASAN_TEST_OBJECTS)
	$(CXX) $(ASAN_FLAGS) $^ $(TEST_LINK_FLAGS) -o $@

$(UBSAN_TEST_BINARY): $(UBSAN_TEST_OBJECTS)
	$(CXX) $(UBSAN_FLAGS) $^ $(TEST_LINK_FLAGS) -o $@

$(DUDECT_BUILD_DIR)/%.out: $(DUDECT_TEST_DIR)/%.cpp $(DUDECT_BUILD_DIR) $(SUBTLE_INC_DIR) $(DUDECT_INC_DIR)
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(DUDECT_DEP_IFLAGS) -lm $(LINK_FLAGS) $< -o $@

test: $(TEST_BINARY) $(GTEST_PARALLEL)
	$(GTEST_PARALLEL) $< --print_test_times

asan_test: $(ASAN_TEST_BINARY) $(GTEST_PARALLEL)
	$(GTEST_PARALLEL) $< --print_test_times

ubsan_test: $(UBSAN_TEST_BINARY) $(GTEST_PARALLEL)
	$(GTEST_PARALLEL) $< --print_test_times

dudect_test_build: $(DUDECT_TEST_BINARIES)

$(BENCHMARK_BUILD_DIR)/%.o: $(BENCHMARK_DIR)/%.cpp $(BENCHMARK_BUILD_DIR)
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

$(PERF_BUILD_DIR)/%.o: $(BENCHMARK_DIR)/%.cpp $(PERF_BUILD_DIR)
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(PERF_DEFS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

$(BENCHMARK_BINARY): $(BENCHMARK_OBJECTS)
	$(CXX) $(OPT_FLAGS) $(LINK_FLAGS) $^ $(BENCHMARK_LINK_FLAGS) -o $@

benchmark: $(BENCHMARK_BINARY)
	# Must *not* build google-benchmark with libPFM
	./$< --benchmark_min_warmup_time=.1 --benchmark_enable_random_interleaving=true --benchmark_repetitions=10 --benchmark_min_time=0.1s --benchmark_counters_tabular=true --benchmark_display_aggregates_only=true

$(PERF_BINARY): $(PERF_OBJECTS)
	$(CXX) $(OPT_FLAGS) $(LINK_FLAGS) $^ $(PERF_LINK_FLAGS) -o $@

perf: $(PERF_BINARY)
	# Must build google-benchmark with libPFM, follow https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7
	./$< --benchmark_min_warmup_time=.1 --benchmark_enable_random_interleaving=true --benchmark_repetitions=10 --benchmark_min_time=0.1s --benchmark_counters_tabular=true --benchmark_display_aggregates_only=true --benchmark_perf_counters=CYCLES

.PHONY: format clean

clean:
	rm -rf $(BUILD_DIR)

format: $(ASCON_SOURCES) $(TEST_SOURCES) $(TEST_HEADERS) $(DUDECT_TEST_SOURCES) $(BENCHMARK_SOURCES) $(BENCHMARK_HEADERS)
	clang-format -i $^
