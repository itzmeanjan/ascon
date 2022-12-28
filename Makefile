CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic
OPTFLAGS = -O3 -march=native -mtune=native
IFLAGS = -I ./include

all: test_ascon test_kat

test/a.out: test/main.cpp include/*.hpp
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $< -o $@

test_ascon: test/a.out
	./$<

lib:
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) -fPIC --shared wrapper/ascon.cpp -o wrapper/libascon.so

clean:
	find . -name 'a.out' -o -name '*.o' -o -name 'lib*.so' -o -name '__pycache__' | xargs rm -rf

format:
	find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla && python3 -m black wrapper/python/*.py

test_kat:
	# make sure you've `python3 -m pip install --user pytest`
	bash test.sh

bench_python:
	# make sure you've `python3 -m pip install --user pytest`
	# make sure you've `python3 -m pip install --user pytest-benchmark`
	bash bench.sh

bench/a.out: bench/main.cpp include/*.hpp
	# make sure you've google-benchmark globally installed;
	# see https://github.com/google/benchmark/tree/60b16f1#installation
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $< -lbenchmark -o $@

benchmark: bench/a.out
	./$<
