.DEFAULT_GOAL := help

# Collects inspiration from https://github.com/0xPolygonMiden/crypto/blob/3909b0199368b13fdfa934a324f984572d521e39/Makefile#L1-L5
# and https://github.com/gtramontina/sourcing/blob/853252ee184c16bc69dd53e8457107d718aca04f/Makefile#L68-L72
.PHONY: help
help:
	@for file in $(MAKEFILE_LIST); do \
		grep -E '^[a-zA-Z_-]+:.*?## .*$$' $${file} | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}';\
	done


CXX ?= clang++
CXX_DEFS +=
CXX_FLAGS := -std=c++20
WARN_FLAGS := -Wall -Wextra -Wpedantic
DEBUG_FLAGS := -O1 -g
RELEASE_FLAGS := -O3 -march=native
LINK_OPT_FLAGS := -flto

I_FLAGS := -I ./include
SUBTLE_INC_DIR = ./subtle/include
DEP_IFLAGS := -I $(SUBTLE_INC_DIR)
PERF_DEFS = -DCYCLES_PER_BYTE

SRC_DIR := include
ASCON_SOURCES := $(shell find $(SRC_DIR) -name '*.hpp')
BUILD_DIR := build

include tests/test.mk
include benches/bench.mk
include examples/example.mk

$(SUBTLE_INC_DIR):
	git submodule update --init subtle

$(GTEST_PARALLEL): $(SUBTLE_INC_DIR)
	git submodule update --init gtest-parallel

.PHONY: clean
clean: ## Remove build directory
	rm -rf $(BUILD_DIR)

.PHONY: format
format: $(ASCON_SOURCES) $(TEST_SOURCES) $(TEST_HEADERS) $(BENCHMARK_SOURCES) $(BENCHMARK_HEADERS) $(EXAMPLE_SOURCES) $(EXAMPLE_HEADERS) ## Format source code
	clang-format -i $^

.PHONY: sync_acvp_kats
sync_acvp_kats: ## Downloads NIST ACVP KAT vectors and updates local KATs
	cd kats/scripts &&\
	./sync_acvp_kats.sh &&\
	cd -
