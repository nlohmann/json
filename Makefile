.PHONY: pretty clean ChangeLog.md

# used programs
RE2C = re2c
SED = sed

# main target
all: json_unit

# clean up
clean:
	rm -fr json_unit json_benchmarks fuzz fuzz-testing *.dSYM
	$(MAKE) clean -Cdoc


##########################################################################
# unit tests
##########################################################################

# additional flags
FLAGS = -Wall -Wextra -pedantic -Weffc++ -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wmissing-declarations -Wmissing-include-dirs -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-overflow=5 -Wswitch -Wundef -Wno-unused -Wnon-virtual-dtor -Wreorder -Wdeprecated -Wfloat-equal

# build unit tests (TODO: Does this want its own makefile?)
json_unit: test/src/unit.cpp src/json.hpp test/src/catch.hpp
	$(CXX) -std=c++11 $(CXXFLAGS) $(FLAGS) $(CPPFLAGS) -I src -I test $< $(LDFLAGS) -o $@


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
	$(MAKE) fuzz CXX=afl-clang++
	mv fuzz fuzz-testing
	find test/data/json_tests -size -5k -name *json | xargs -I{} cp "{}" fuzz-testing/testcases
	@echo "Execute: afl-fuzz -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzz"

# the fuzzer binary
fuzz: test/src/fuzz.cpp src/json.hpp
	$(CXX) -std=c++11 $(CXXFLAGS) $(FLAGS) $(CPPFLAGS) -I src $< $(LDFLAGS) -o $@


##########################################################################
# static analyzer
##########################################################################

# call cppcheck on the main header file
cppcheck:
	cppcheck --enable=all --inconclusive --std=c++11 src/json.hpp


##########################################################################
# maintainer targets
##########################################################################

# create scanner with re2c
re2c: src/json.hpp.re2c
	$(RE2C) -W --bit-vectors --nested-ifs --no-debug-info $< | $(SED) '1d' > src/json.hpp

# pretty printer
pretty:
	astyle --style=allman --indent=spaces=4 --indent-modifiers \
	   --indent-switches --indent-preproc-block --indent-preproc-define \
	   --indent-col1-comments --pad-oper --pad-header --align-pointer=type \
	   --align-reference=type --add-brackets --convert-tabs --close-templates \
	   --lineend=linux --preserve-date --suffix=none --formatted \
	   src/json.hpp src/json.hpp.re2c test/src/unit.cpp test/src/fuzz.cpp benchmarks/benchmarks.cpp doc/examples/*.cpp


##########################################################################
# benchmarks
##########################################################################

# benchmarks
json_benchmarks: benchmarks/benchmarks.cpp benchmarks/benchpress.hpp benchmarks/cxxopts.hpp src/json.hpp
	$(CXX) -std=c++11 $(CXXFLAGS) -O3 -flto -I src -I benchmarks $< $(LDFLAGS) -o $@
	./json_benchmarks


##########################################################################
# changelog
##########################################################################

ChangeLog.md:
	github_changelog_generator -o ChangeLog.md --simple-list --release-url https://github.com/nlohmann/json/releases/tag/%s
	gsed -i 's|https://github.com/nlohmann/json/releases/tag/HEAD|https://github.com/nlohmann/json/tree/HEAD|' ChangeLog.md
	gsed -i '2i All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/).' ChangeLog.md
