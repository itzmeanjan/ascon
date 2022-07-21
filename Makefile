CXX = dpcpp
CXXFLAGS = -std=c++20 -Wall -Weverything -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-c++98-c++11-compat-binary-literal -Werror
SYCLFLAGS = -fsycl
SYCLCUDAFLAGS = -fsycl-targets=nvptx64-nvidia-cuda
OPTFLAGS = -O3
IFLAGS = -I ./include

all: test_ascon

test/a.out: test/main.cpp include/*.hpp
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $< -o $@

test_ascon: test/a.out
	./test/a.out

lib:
	g++ -std=c++20 -Wall -Wextra -pedantic $(OPTFLAGS) $(IFLAGS) -fPIC --shared wrapper/ascon.cpp -o wrapper/libascon.so

clean:
	find . -name 'a.out' -o -name '*.o' -o -name 'lib*.so' -o -name '__pycache__' | xargs rm -rf

format:
	find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla && python3 -m black wrapper/python/*.py

kat_test_python:
	# make sure you've `python3 -m pip install --user pytest`
	bash test.sh

bench_python:
	# make sure you've `python3 -m pip install --user pytest`
	# make sure you've `python3 -m pip install --user pytest-benchmark`
	bash bench.sh

bench/a.out: bench/main.cpp include/*.hpp
	# make sure you've google-benchmark globally installed;
	# see https://github.com/google/benchmark/tree/60b16f1#installation
	g++ -std=c++20 -Wall -Wextra -pedantic $(OPTFLAGS) $(IFLAGS) $< -lbenchmark -o $@

bench_cpp: bench/a.out
	./$<

aot_cpu:
	@if lscpu | grep -q 'avx512'; then \
		echo "Using avx512"; \
		$(CXX) -std=c++20 -Wall -DSYCL_TARGET_CPU $(SYCLFLAGS) $(OPTFLAGS) $(IFLAGS) -fsycl-targets=spir64_x86_64 -Xs "-march=avx512" bench_accel/main.cpp -o bench_accel/a.out; \
	elif lscpu | grep -q 'avx2'; then \
		echo "Using avx2"; \
		$(CXX) -std=c++20 -Wall -DSYCL_TARGET_CPU $(SYCLFLAGS) $(OPTFLAGS) $(IFLAGS) -fsycl-targets=spir64_x86_64 -Xs "-march=avx2" bench_accel/main.cpp -o bench_accel/a.out; \
	elif lscpu | grep -q 'avx'; then \
		echo "Using avx"; \
		$(CXX) -std=c++20 -Wall -DSYCL_TARGET_CPU $(SYCLFLAGS) $(OPTFLAGS) $(IFLAGS) -fsycl-targets=spir64_x86_64 -Xs "-march=avx" bench_accel/main.cpp -o bench_accel/a.out; \
	elif lscpu | grep -q 'sse4.2'; then \
		echo "Using sse4.2"; \
		$(CXX) -std=c++20 -Wall -DSYCL_TARGET_CPU $(SYCLFLAGS) $(OPTFLAGS) $(IFLAGS) -fsycl-targets=spir64_x86_64 -Xs "-march=sse4.2" bench_accel/main.cpp -o bench_accel/a.out; \
	else \
		echo "Can't AOT compile using avx, avx2, avx512 or sse4.2"; \
	fi
	./bench_accel/a.out

aot_gpu:
	# you may want to replace `device` identifier with `0x3e96` if you're targeting *Intel(R) UHD Graphics P630*
	#
	# otherwise, let it be what it's if you're targeting *Intel(R) Iris(R) Xe MAX Graphics*
	$(CXX) -std=c++20 -Wall -DSYCL_TARGET_GPU $(SYCLFLAGS) $(OPTFLAGS) $(IFLAGS) -fsycl-targets=spir64_gen -Xs "-device 0x4905" bench_accel/main.cpp -o bench_accel/a.out
	./bench_accel/a.out

cuda:
	clang++ -std=c++20 -Wall -DSYCL_TARGET_GPU $(SYCLFLAGS) $(SYCLCUDAFLAGS) $(OPTFLAGS) $(IFLAGS) bench_accel/main.cpp -o bench_accel/a.out
	./bench_accel/a.out
