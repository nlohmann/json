##############################################################################
# OSS-Fuzz
##############################################################################

# The following targets realize the integration to OSS-Fuzz.
# See <https://github.com/google/oss-fuzz/blob/master/projects/json/build.sh> for more information.

# additional flags
CXXFLAGS += -std=c++11
CPPFLAGS += -I ../single_include

FUZZER_ENGINE = src/fuzzer-driver_afl.cpp
FUZZERS = parse_afl_fuzzer parse_bson_fuzzer parse_cbor_fuzzer parse_msgpack_fuzzer parse_ubjson_fuzzer
fuzzers: $(FUZZERS)

parse_afl_fuzzer:
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(FUZZER_ENGINE) src/fuzzer-parse_json.cpp -o $@

parse_bson_fuzzer:
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(FUZZER_ENGINE) src/fuzzer-parse_bson.cpp -o $@

parse_cbor_fuzzer:
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(FUZZER_ENGINE) src/fuzzer-parse_cbor.cpp -o $@

parse_msgpack_fuzzer:
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(FUZZER_ENGINE) src/fuzzer-parse_msgpack.cpp -o $@

parse_ubjson_fuzzer:
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(FUZZER_ENGINE) src/fuzzer-parse_ubjson.cpp -o $@
