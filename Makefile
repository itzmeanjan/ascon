CXX = dpcpp
CXXFLAGS = -Wall -std=c++20
SYCLFLAGS = -fsycl
OPTFLAGS = -O3
IFLAGS = -I ./include

all: test_ascon

test/a.out: test/main.cpp include/*.hpp
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(SYCLFLAGS) $(IFLAGS) $< -o $@

test_ascon: test/a.out
	./test/a.out

lib:
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(SYCLFLAGS) $(IFLAGS) -fsycl-targets=spir64_x86_64 -fPIC --shared wrapper/hash.cpp -o wrapper/libascon_hash.so

clean:
	find . -name 'a.out' -o -name '*.o' -o -name 'lib*.so' -o -name '__pycache__' | xargs rm -rf

format:
	find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla
