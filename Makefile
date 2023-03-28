CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic
OPTFLAGS = -O3 -march=native -mtune=native
IFLAGS = -I ./include
DEPFLAGS = -I ./subtle/include

all: test_ascon test_kat

test/a.out: test/main.cpp include/*.hpp include/test/*.hpp
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $(DEPFLAGS) $< -o $@

test_ascon: test/a.out
	./$<

lib:
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $(DEPFLAGS) -fPIC --shared wrapper/ascon.cpp -o wrapper/libascon.so

test_kat:
	bash test_kat.sh

clean:
	find . -name '*.out' -o -name '*.o' -o -name 'lib*.so' -o -name '__pycache__' -o -name '*.gch' | xargs rm -rf

format:
	find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla && python3 -m black wrapper/python/*.py

bench/a.out: bench/main.cpp include/*.hpp include/bench/*.hpp
	# make sure you've google-benchmark globally installed;
	# see https://github.com/google/benchmark/tree/60b16f1#installation
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $(DEPFLAGS) $< -lbenchmark -o $@

benchmark: bench/a.out
	./$<
