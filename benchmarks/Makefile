
#
# Build/run json.hpp benchmarks, eg. CXX=g++-7 make
# 
# The existing json_benchmarks did not allow optimization under some compilers
# 
all: json_benchmarks json_benchmarks_simple number_jsons
	bash -c 'time ./json_benchmarks'
	bash -c 'time ./json_benchmarks_simple'

json_benchmarks: src/benchmarks.cpp ../src/json.hpp
	$(CXX) -std=c++11 -pthread $(CXXFLAGS) -DNDEBUG -O3 -flto -I thirdparty/benchpress -I thirdparty/cxxopts -I../src src/benchmarks.cpp $(LDFLAGS) -o $@

json_benchmarks_simple: src/benchmarks_simple.cpp ../src/json.hpp
	$(CXX) -std=c++11 $(CXXFLAGS) -DNDEBUG -O3 -flto -I../src $(<) $(LDFLAGS) -o $@

number_jsons:
	(test -e files/numbers/floats.json -a -e files/numbers/signed_ints.json -a -e files/numbers/unsigned_ints.json) || (cd files/numbers ; python generate.py)

clean:
	rm -f json_benchmarks json_benchmarks_simple files/numbers/*.json
