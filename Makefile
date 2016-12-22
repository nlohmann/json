.PHONY: pretty clean ChangeLog.md

# used programs
RE2C = re2c
SED = sed

# main target
all:
	$(MAKE) -C test

# clean up
clean:
	rm -fr json_unit json_benchmarks fuzz fuzz-testing *.dSYM test/*.dSYM
	rm -fr benchmarks/files/numbers/*.json
	$(MAKE) clean -Cdoc
	$(MAKE) clean -Ctest


##########################################################################
# unit tests
##########################################################################

# build unit tests
json_unit:
	@$(MAKE) json_unit -C test

# run unit tests
check:
	$(MAKE) check -C test

check-fast:
	$(MAKE) check -C test TEST_PATTERN=""


##########################################################################
# documentation tests
##########################################################################

# compile example files and check output
doctest:
	$(MAKE) check_output -C doc


##########################################################################
# fuzzing
##########################################################################

# the overall fuzz testing target
fuzz_testing:
	rm -fr fuzz-testing
	mkdir -p fuzz-testing fuzz-testing/testcases fuzz-testing/out
	$(MAKE) parse_afl_fuzzer -C test CXX=afl-clang++
	mv test/parse_afl_fuzzer fuzz-testing/fuzzer
	find test/data/json_tests -size -5k -name *json | xargs -I{} cp "{}" fuzz-testing/testcases
	@echo "Execute: afl-fuzz -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer"

fuzz_testing_cbor:
	rm -fr fuzz-testing
	mkdir -p fuzz-testing fuzz-testing/testcases fuzz-testing/out
	$(MAKE) parse_cbor_fuzzer -C test CXX=afl-clang++
	mv test/parse_cbor_fuzzer fuzz-testing/fuzzer
	find test/data -size -5k -name *cbor | xargs -I{} cp "{}" fuzz-testing/testcases
	@echo "Execute: afl-fuzz -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer"


##########################################################################
# static analyzer
##########################################################################

# call cppcheck on the main header file
cppcheck:
	cppcheck --enable=warning --inconclusive --force --std=c++11 src/json.hpp --error-exitcode=1

clang_sanitize: clean
	CXX=clang++ CXXFLAGS="-g -O2 -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer" $(MAKE)


##########################################################################
# maintainer targets
##########################################################################

# create scanner with re2c
re2c: src/json.hpp.re2c
	$(RE2C) -W --utf-8 --encoding-policy fail --bit-vectors --nested-ifs --no-debug-info $< | $(SED) '1d' > src/json.hpp

# pretty printer
pretty:
	astyle --style=allman --indent=spaces=4 --indent-modifiers \
	   --indent-switches --indent-preproc-block --indent-preproc-define \
	   --indent-col1-comments --pad-oper --pad-header --align-pointer=type \
	   --align-reference=type --add-brackets --convert-tabs --close-templates \
	   --lineend=linux --preserve-date --suffix=none --formatted \
	   src/json.hpp src/json.hpp.re2c test/src/*.cpp \
	   benchmarks/benchmarks.cpp doc/examples/*.cpp


##########################################################################
# benchmarks
##########################################################################

# benchmarks
json_benchmarks: benchmarks/benchmarks.cpp benchmarks/benchpress.hpp benchmarks/cxxopts.hpp src/json.hpp
	cd benchmarks/files/numbers ; python generate.py
	$(CXX) -std=c++11 -pthread $(CXXFLAGS) -DNDEBUG -O3 -flto -I src -I benchmarks $< $(LDFLAGS) -o $@
	./json_benchmarks


##########################################################################
# changelog
##########################################################################

NEXT_VERSION ?= "unreleased"

ChangeLog.md:
	github_changelog_generator -o ChangeLog.md --simple-list --release-url https://github.com/nlohmann/json/releases/tag/%s --future-release $(NEXT_VERSION)
	gsed -i 's|https://github.com/nlohmann/json/releases/tag/HEAD|https://github.com/nlohmann/json/tree/HEAD|' ChangeLog.md
	gsed -i '2i All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/).' ChangeLog.md
