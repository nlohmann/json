.PHONY: pretty clean ChangeLog.md

SRCS = include/nlohmann/json.hpp \
       include/nlohmann/json_fwd.hpp \
       include/nlohmann/adl_serializer.hpp \
       include/nlohmann/detail/conversions/from_json.hpp \
       include/nlohmann/detail/conversions/to_chars.hpp \
       include/nlohmann/detail/conversions/to_json.hpp \
       include/nlohmann/detail/exceptions.hpp \
       include/nlohmann/detail/input/binary_reader.hpp \
       include/nlohmann/detail/input/input_adapters.hpp \
       include/nlohmann/detail/input/json_sax.hpp \
       include/nlohmann/detail/input/lexer.hpp \
       include/nlohmann/detail/input/parser.hpp \
       include/nlohmann/detail/iterators/internal_iterator.hpp \
       include/nlohmann/detail/iterators/iter_impl.hpp \
       include/nlohmann/detail/iterators/iteration_proxy.hpp \
       include/nlohmann/detail/iterators/json_reverse_iterator.hpp \
       include/nlohmann/detail/iterators/primitive_iterator.hpp \
       include/nlohmann/detail/json_pointer.hpp \
       include/nlohmann/detail/json_ref.hpp \
       include/nlohmann/detail/macro_scope.hpp \
       include/nlohmann/detail/macro_unscope.hpp \
       include/nlohmann/detail/meta/cpp_future.hpp \
       include/nlohmann/detail/meta/detected.hpp \
       include/nlohmann/detail/meta/type_traits.hpp \
       include/nlohmann/detail/meta/void_t.hpp \
       include/nlohmann/detail/output/binary_writer.hpp \
       include/nlohmann/detail/output/output_adapters.hpp \
       include/nlohmann/detail/output/serializer.hpp \
       include/nlohmann/detail/value_t.hpp

UNAME = $(shell uname)
CXX=clang++

AMALGAMATED_FILE=single_include/nlohmann/json.hpp

# main target
all:
	@echo "amalgamate - amalgamate file single_include/nlohmann/json.hpp from the include/nlohmann sources"
	@echo "ChangeLog.md - generate ChangeLog file"
	@echo "check - compile and execute test suite"
	@echo "check-amalgamation - check whether sources have been amalgamated"
	@echo "check-fast - compile and execute test suite (skip long-running tests)"
	@echo "clean - remove built files"
	@echo "coverage - create coverage information with lcov"
	@echo "cppcheck - analyze code with cppcheck"
	@echo "doctest - compile example files and check their output"
	@echo "fuzz_testing - prepare fuzz testing of the JSON parser"
	@echo "fuzz_testing_cbor - prepare fuzz testing of the CBOR parser"
	@echo "fuzz_testing_msgpack - prepare fuzz testing of the MessagePack parser"
	@echo "fuzz_testing_ubjson - prepare fuzz testing of the UBJSON parser"
	@echo "json_unit - create single-file test executable"
	@echo "pedantic_clang - run Clang with maximal warning flags"
	@echo "pedantic_gcc - run GCC with maximal warning flags"
	@echo "pretty - beautify code with Artistic Style"
	@echo "run_benchmarks - build and run benchmarks"

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

# clean up
clean:
	rm -fr json_unit json_benchmarks fuzz fuzz-testing *.dSYM test/*.dSYM
	rm -fr benchmarks/files/numbers/*.json
	rm -fr build_coverage build_benchmarks
	$(MAKE) clean -Cdoc
	$(MAKE) clean -Ctest


##########################################################################
# coverage
##########################################################################

coverage:
	mkdir build_coverage
	cd build_coverage ; CXX=g++-7 cmake .. -GNinja -DJSON_Coverage=ON -DJSON_MultipleHeaders=ON
	cd build_coverage ; ninja
	cd build_coverage ; ctest -E '.*_default' -j10
	cd build_coverage ; ninja lcov_html
	open build_coverage/test/html/index.html


##########################################################################
# documentation tests
##########################################################################

# compile example files and check output
doctest:
	$(MAKE) check_output -C doc


##########################################################################
# warning detector
##########################################################################

# calling Clang with all warnings, except:
# -Wno-documentation-unknown-command: code uses user-defined commands like @complexity
# -Wno-exit-time-destructors: warning in Catch code
# -Wno-keyword-macro: unit-tests use "#define private public"
# -Wno-deprecated-declarations: the library deprecated some functions
# -Wno-weak-vtables: exception class is defined inline, but has virtual method
# -Wno-range-loop-analysis: items tests "for(const auto i...)"
# -Wno-float-equal: not all comparisons in the tests can be replaced by Approx
# -Wno-switch-enum -Wno-covered-switch-default: pedantic/contradicting warnings about switches
# -Wno-padded: padding is nothing to warn about
pedantic_clang:
	$(MAKE) json_unit CXXFLAGS="\
		-std=c++11 -Wno-c++98-compat -Wno-c++98-compat-pedantic \
		-Werror \
		-Weverything \
		-Wno-documentation-unknown-command \
		-Wno-exit-time-destructors \
		-Wno-keyword-macro \
		-Wno-deprecated-declarations \
		-Wno-weak-vtables \
		-Wno-range-loop-analysis \
		-Wno-float-equal \
		-Wno-switch-enum -Wno-covered-switch-default \
		-Wno-padded"

# calling GCC with most warnings
pedantic_gcc:
	$(MAKE) json_unit CXXFLAGS="\
		-std=c++11 \
		-Wno-deprecated-declarations \
		-Werror \
		-Wall -Wpedantic -Wextra \
		-Walloca \
		-Warray-bounds=2 \
		-Wcast-qual -Wcast-align \
		-Wchar-subscripts \
		-Wconditionally-supported \
		-Wconversion \
		-Wdate-time \
		-Wdeprecated \
		-Wdisabled-optimization \
		-Wdouble-promotion \
		-Wduplicated-branches \
		-Wduplicated-cond \
		-Wformat-overflow=2 \
		-Wformat-signedness \
		-Wformat-truncation=2 \
		-Wformat=2 \
		-Wno-ignored-qualifiers \
		-Wimplicit-fallthrough=5 \
		-Wlogical-op \
		-Wmissing-declarations \
		-Wmissing-format-attribute \
		-Wmissing-include-dirs \
		-Wnoexcept \
		-Wnonnull \
		-Wnull-dereference \
		-Wold-style-cast \
		-Woverloaded-virtual \
		-Wparentheses \
		-Wplacement-new=2 \
		-Wredundant-decls \
		-Wreorder \
		-Wrestrict \
		-Wshadow=global \
		-Wshift-overflow=2 \
		-Wsign-conversion \
		-Wsign-promo \
		-Wsized-deallocation \
		-Wstrict-overflow=5 \
		-Wsuggest-attribute=const \
		-Wsuggest-attribute=format \
		-Wsuggest-attribute=noreturn \
		-Wsuggest-attribute=pure \
		-Wsuggest-final-methods \
		-Wsuggest-final-types \
		-Wsuggest-override \
		-Wtrigraphs \
		-Wundef \
		-Wuninitialized -Wunknown-pragmas \
		-Wunused \
		-Wunused-const-variable=2 \
		-Wunused-macros \
		-Wunused-parameter \
		-Wuseless-cast \
		-Wvariadic-macros \
		-Wctor-dtor-privacy \
		-Winit-self \
		-Wstrict-null-sentinel"

##########################################################################
# benchmarks
##########################################################################

run_benchmarks:
	mkdir build_benchmarks
	cd build_benchmarks ; cmake ../benchmarks
	cd build_benchmarks ; make
	cd build_benchmarks ; ./json_benchmarks

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
	find test/data -size -5k -name *.cbor | xargs -I{} cp "{}" fuzz-testing/testcases
	@echo "Execute: afl-fuzz -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer"

fuzz_testing_msgpack:
	rm -fr fuzz-testing
	mkdir -p fuzz-testing fuzz-testing/testcases fuzz-testing/out
	$(MAKE) parse_msgpack_fuzzer -C test CXX=afl-clang++
	mv test/parse_msgpack_fuzzer fuzz-testing/fuzzer
	find test/data -size -5k -name *.msgpack | xargs -I{} cp "{}" fuzz-testing/testcases
	@echo "Execute: afl-fuzz -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer"

fuzz_testing_ubjson:
	rm -fr fuzz-testing
	mkdir -p fuzz-testing fuzz-testing/testcases fuzz-testing/out
	$(MAKE) parse_ubjson_fuzzer -C test CXX=afl-clang++
	mv test/parse_ubjson_fuzzer fuzz-testing/fuzzer
	find test/data -size -5k -name *.ubjson | xargs -I{} cp "{}" fuzz-testing/testcases
	@echo "Execute: afl-fuzz -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer"

fuzzing-start:
	afl-fuzz -S fuzzer1 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer > /dev/null &
	afl-fuzz -S fuzzer2 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer > /dev/null &
	afl-fuzz -S fuzzer3 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer > /dev/null &
	afl-fuzz -S fuzzer4 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer > /dev/null &
	afl-fuzz -S fuzzer5 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer > /dev/null &
	afl-fuzz -S fuzzer6 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer > /dev/null &
	afl-fuzz -S fuzzer7 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer > /dev/null &
	afl-fuzz -M fuzzer0 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer

fuzzing-stop:
	-killall fuzzer
	-killall afl-fuzz

##########################################################################
# static analyzer
##########################################################################

# call cppcheck on the main header file
cppcheck:
	cppcheck --enable=warning --inconclusive --force --std=c++11 $(AMALGAMATED_FILE) --error-exitcode=1

# compile and check with Clang Static Analyzer
clang_analyze:
	rm -fr clang_analyze_build
	mkdir clang_analyze_build
	cd clang_analyze_build ; CCC_CXX=/Users/niels/Documents/projects/llvm-clang/local/bin/clang++ /Users/niels/Documents/projects/llvm-clang/local/bin/scan-build cmake ..
	/Users/niels/Documents/projects/llvm-clang/local/bin/scan-build -enable-checker alpha.core.DynamicTypeChecker,alpha.core.PointerArithm,alpha.core.PointerSub,alpha.cplusplus.DeleteWithNonVirtualDtor,alpha.cplusplus.IteratorRange,alpha.cplusplus.MisusedMovedObject,alpha.security.ArrayBoundV2,alpha.core.Conversion --use-c++=/Users/niels/Documents/projects/llvm-clang/local/bin/clang++ --view -analyze-headers -o clang_analyze_build/report.html make -j10 -C clang_analyze_build

##########################################################################
# maintainer targets
##########################################################################

# pretty printer
pretty:
	astyle --style=allman --indent=spaces=4 --indent-modifiers \
	   --indent-switches --indent-preproc-block --indent-preproc-define \
	   --indent-col1-comments --pad-oper --pad-header --align-pointer=type \
	   --align-reference=type --add-brackets --convert-tabs --close-templates \
	   --lineend=linux --preserve-date --suffix=none --formatted \
	   $(SRCS) $(AMALGAMATED_FILE) test/src/*.cpp \
	   benchmarks/src/benchmarks.cpp doc/examples/*.cpp

# create single header file
amalgamate: $(AMALGAMATED_FILE)

$(AMALGAMATED_FILE): $(SRCS)
	third_party/amalgamate/amalgamate.py -c third_party/amalgamate/config.json -s . --verbose=yes
	$(MAKE) pretty

# check if single_include/nlohmann/json.hpp has been amalgamated from the nlohmann sources
check-amalgamation:
	@mv $(AMALGAMATED_FILE) $(AMALGAMATED_FILE)~
	@$(MAKE) amalgamate
	@diff $(AMALGAMATED_FILE) $(AMALGAMATED_FILE)~ || (echo "===================================================================\n  Amalgamation required! Please read the contribution guidelines\n  in file .github/CONTRIBUTING.md.\n===================================================================" ; mv $(AMALGAMATED_FILE)~ $(AMALGAMATED_FILE) ; false)
	@mv $(AMALGAMATED_FILE)~ $(AMALGAMATED_FILE)

# check if every header in nlohmann includes sufficient headers to be compiled
# individually
check-single-includes:
	for x in $(SRCS); do \
	  echo "#include <$$x>\nint main() {}\n" | sed 's|include/||' > single_include_test.cpp; \
	  $(CXX) $(CXXFLAGS) -Iinclude -std=c++11 single_include_test.cpp -o single_include_test; \
	  rm single_include_test.cpp single_include_test; \
	done

##########################################################################
# changelog
##########################################################################

NEXT_VERSION ?= "unreleased"

ChangeLog.md:
	github_changelog_generator -o ChangeLog.md --simple-list --release-url https://github.com/nlohmann/json/releases/tag/%s --future-release $(NEXT_VERSION)
	gsed -i 's|https://github.com/nlohmann/json/releases/tag/HEAD|https://github.com/nlohmann/json/tree/HEAD|' ChangeLog.md
	gsed -i '2i All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/).' ChangeLog.md


##########################################################################
# release
##########################################################################

release:
	mkdir release_files
	zip -9 -r include.zip include/*
	gpg --armor --detach-sig include.zip
	mv include.zip include.zip.asc release_files
	gpg --armor --detach-sig single_include/nlohmann/json.hpp
	cp single_include/nlohmann/json.hpp release_files
	mv single_include/nlohmann/json.hpp.asc release_files
	cd release_files ; shasum -a 256 json.hpp > hashes.txt
	cd release_files ; shasum -a 256 include.zip >> hashes.txt
