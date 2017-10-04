all: json_benchmarks
	./json_benchmarks

json_benchmarks: src/benchmarks.cpp ../src/json.hpp number_jsons
	$(CXX) -std=c++11 -pthread $(CXXFLAGS) -DNDEBUG -O3 -flto -I thirdparty/benchpress -I thirdparty/cxxopts -I../src src/benchmarks.cpp $(LDFLAGS) -o $@

number_jsons:
	(test -e files/numbers/floats.json -a -e files/numbers/signed_ints.json -a -e files/numbers/unsigned_ints.json) || (cd files/numbers ; python generate.py)

clean:
	rm -f json_benchmarks files/numbers/*.json
