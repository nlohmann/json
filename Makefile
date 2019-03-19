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
       include/nlohmann/detail/input/position_t.hpp \
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

# directory to recent compiler binaries
COMPILER_DIR=/Users/niels/Documents/projects/compilers/local/bin

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
	@echo "cpplint - analyze code with cpplint"
	@echo "clang_tidy - analyze code with Clang-Tidy"
	@echo "clang_analyze - analyze code with Clang-Analyzer"
	@echo "doctest - compile example files and check their output"
	@echo "fuzz_testing - prepare fuzz testing of the JSON parser"
	@echo "fuzz_testing_bson - prepare fuzz testing of the BSON parser"
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
# -Wno-c++2a-compat: u8 literals will behave differently in C++20...
# -Wno-padded: padding is nothing to warn about
pedantic_clang:
	$(MAKE) json_unit CXX=$(COMPILER_DIR)/clang++ CXXFLAGS=" \
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
		-Wno-c++2a-compat \
		-Wno-c++17-extensions \
		-Wno-padded"

# calling GCC with most warnings
pedantic_gcc:
	$(MAKE) json_unit CXX=$(COMPILER_DIR)/g++ CXXFLAGS=" \
		-std=c++11 \
		-Waddress \
		-Waddress-of-packed-member \
		-Waggressive-loop-optimizations \
		-Waligned-new=all \
		-Wall \
		-Walloc-zero \
		-Walloca \
		-Warray-bounds \
		-Warray-bounds=2 \
		-Wattribute-alias=2 \
		-Wattribute-warning \
		-Wattributes \
		-Wbool-compare \
		-Wbool-operation \
		-Wbuiltin-declaration-mismatch \
		-Wbuiltin-macro-redefined \
		-Wcannot-profile \
		-Wcast-align \
		-Wcast-function-type \
		-Wcast-qual \
		-Wcatch-value=3 \
		-Wchar-subscripts \
		-Wclass-conversion \
		-Wclass-memaccess \
		-Wclobbered \
		-Wcomment \
		-Wcomments \
		-Wconditionally-supported \
		-Wconversion \
		-Wconversion-null \
		-Wcoverage-mismatch \
		-Wcpp \
		-Wctor-dtor-privacy \
		-Wdangling-else \
		-Wdate-time \
		-Wdelete-incomplete \
		-Wdelete-non-virtual-dtor \
		-Wdeprecated \
		-Wdeprecated-copy \
		-Wdeprecated-copy-dtor \
		-Wdeprecated-declarations \
		-Wdisabled-optimization \
		-Wdiv-by-zero \
		-Wdouble-promotion \
		-Wduplicated-branches \
		-Wduplicated-cond \
		-Weffc++ \
		-Wempty-body \
		-Wendif-labels \
		-Wenum-compare \
		-Wexpansion-to-defined \
		-Werror \
		-Wextra \
		-Wextra-semi \
		-Wfloat-conversion \
		-Wfloat-equal \
		-Wformat \
		-Wformat-contains-nul \
		-Wformat-extra-args \
		-Wformat-nonliteral \
		-Wformat-overflow=2 \
		-Wformat-security \
		-Wformat-signedness \
		-Wformat-truncation=2 \
		-Wformat-y2k \
		-Wformat-zero-length \
		-Wformat=2 \
		-Wframe-address \
		-Wfree-nonheap-object \
		-Whsa \
		-Wif-not-aligned \
		-Wignored-attributes \
		-Wignored-qualifiers \
		-Wimplicit-fallthrough=5 \
		-Winherited-variadic-ctor \
		-Winit-list-lifetime \
		-Winit-self \
		-Winline \
		-Wint-in-bool-context \
		-Wint-to-pointer-cast \
		-Winvalid-memory-model \
		-Winvalid-offsetof \
		-Winvalid-pch \
		-Wliteral-suffix \
		-Wlogical-not-parentheses \
		-Wlogical-op \
		-Wlto-type-mismatch \
		-Wmain \
		-Wmaybe-uninitialized \
		-Wmemset-elt-size \
		-Wmemset-transposed-args \
		-Wmisleading-indentation \
		-Wmissing-attributes \
		-Wmissing-braces \
		-Wmissing-declarations \
		-Wmissing-field-initializers \
		-Wmissing-format-attribute \
		-Wmissing-include-dirs \
		-Wmissing-noreturn \
		-Wmissing-profile \
		-Wmultichar \
		-Wmultiple-inheritance \
		-Wmultistatement-macros \
		-Wnarrowing \
		-Wno-deprecated-declarations \
		-Wno-long-long \
		-Wno-namespaces \
		-Wno-padded \
		-Wno-switch-enum \
		-Wno-system-headers \
		-Wno-templates \
		-Wno-undef \
		-Wnoexcept \
		-Wnoexcept-type \
		-Wnon-template-friend \
		-Wnon-virtual-dtor \
		-Wnonnull \
		-Wnonnull-compare \
		-Wnonportable-cfstrings \
		-Wnormalized \
		-Wnull-dereference \
		-Wodr \
		-Wold-style-cast \
		-Wopenmp-simd \
		-Woverflow \
		-Woverlength-strings \
		-Woverloaded-virtual \
		-Wpacked \
		-Wpacked-bitfield-compat \
		-Wpacked-not-aligned \
		-Wparentheses \
		-Wpedantic \
		-Wpessimizing-move \
		-Wplacement-new=2 \
		-Wpmf-conversions \
		-Wpointer-arith \
		-Wpointer-compare \
		-Wpragmas \
		-Wprio-ctor-dtor \
		-Wpsabi \
		-Wredundant-decls \
		-Wredundant-move \
		-Wregister \
		-Wreorder \
		-Wrestrict \
		-Wreturn-local-addr \
		-Wreturn-type \
		-Wscalar-storage-order \
		-Wsequence-point \
		-Wshadow \
		-Wshadow-compatible-local \
		-Wshadow-local \
		-Wshadow=compatible-local \
		-Wshadow=global \
		-Wshadow=local \
		-Wshift-count-negative \
		-Wshift-count-overflow \
		-Wshift-negative-value \
		-Wshift-overflow=2 \
		-Wsign-compare \
		-Wsign-conversion \
		-Wsign-promo \
		-Wsized-deallocation \
		-Wsizeof-array-argument \
		-Wsizeof-pointer-div \
		-Wsizeof-pointer-memaccess \
		-Wstack-protector \
		-Wstrict-aliasing=3 \
		-Wstrict-null-sentinel \
		-Wstrict-overflow=5 \
		-Wstringop-overflow=4 \
		-Wstringop-truncation \
		-Wsubobject-linkage \
		-Wsuggest-attribute=cold \
		-Wsuggest-attribute=const \
		-Wsuggest-attribute=format \
		-Wsuggest-attribute=malloc \
		-Wsuggest-attribute=noreturn \
		-Wsuggest-attribute=pure \
		-Wsuggest-final-methods \
		-Wsuggest-final-types \
		-Wsuggest-override \
		-Wswitch \
		-Wswitch-bool \
		-Wswitch-default \
		-Wswitch-unreachable \
		-Wsync-nand \
		-Wsynth \
		-Wtautological-compare \
		-Wterminate \
		-Wtrampolines \
		-Wtrigraphs \
		-Wtype-limits \
		-Wuninitialized \
		-Wunknown-pragmas \
		-Wunreachable-code \
		-Wunsafe-loop-optimizations \
		-Wunused \
		-Wunused-but-set-parameter \
		-Wunused-but-set-variable \
		-Wunused-const-variable=2 \
		-Wunused-function \
		-Wunused-label \
		-Wunused-local-typedefs \
		-Wunused-macros \
		-Wunused-parameter \
		-Wunused-result \
		-Wunused-value \
		-Wunused-variable \
		-Wuseless-cast \
		-Wvarargs \
		-Wvariadic-macros \
		-Wvector-operation-performance \
		-Wvirtual-inheritance \
		-Wvirtual-move-assign \
		-Wvla \
		-Wvolatile-register-var \
		-Wwrite-strings \
		-Wzero-as-null-pointer-constant \
		"

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

fuzz_testing_bson:
	rm -fr fuzz-testing
	mkdir -p fuzz-testing fuzz-testing/testcases fuzz-testing/out
	$(MAKE) parse_bson_fuzzer -C test CXX=afl-clang++
	mv test/parse_bson_fuzzer fuzz-testing/fuzzer
	find test/data -size -5k -name *.bson | xargs -I{} cp "{}" fuzz-testing/testcases
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
	cppcheck --enable=warning --inline-suppr --inconclusive --force --std=c++11 $(SRCS) --error-exitcode=1

# compile and check with Clang Static Analyzer
clang_analyze:
	rm -fr clang_analyze_build
	mkdir clang_analyze_build
	cd clang_analyze_build ; CCC_CXX=$(COMPILER_DIR)/clang++ CXX=$(COMPILER_DIR)/clang++ $(COMPILER_DIR)/scan-build cmake .. -GNinja
	cd clang_analyze_build ; $(COMPILER_DIR)/scan-build -enable-checker alpha.core.BoolAssignment,alpha.core.CallAndMessageUnInitRefArg,alpha.core.CastSize,alpha.core.CastToStruct,alpha.core.Conversion,alpha.core.DynamicTypeChecker,alpha.core.FixedAddr,alpha.core.PointerArithm,alpha.core.PointerSub,alpha.core.SizeofPtr,alpha.core.StackAddressAsyncEscape,alpha.core.TestAfterDivZero,alpha.deadcode.UnreachableCode,core.builtin.BuiltinFunctions,core.builtin.NoReturnFunctions,core.CallAndMessage,core.DivideZero,core.DynamicTypePropagation,core.NonnilStringConstants,core.NonNullParamChecker,core.NullDereference,core.StackAddressEscape,core.UndefinedBinaryOperatorResult,core.uninitialized.ArraySubscript,core.uninitialized.Assign,core.uninitialized.Branch,core.uninitialized.CapturedBlockVariable,core.uninitialized.UndefReturn,core.VLASize,cplusplus.InnerPointer,cplusplus.Move,cplusplus.NewDelete,cplusplus.NewDeleteLeaks,cplusplus.SelfAssignment,deadcode.DeadStores,nullability.NullableDereferenced,nullability.NullablePassedToNonnull,nullability.NullableReturnedFromNonnull,nullability.NullPassedToNonnull,nullability.NullReturnedFromNonnull --use-c++=$(COMPILER_DIR)/clang++ --view -analyze-headers -o clang_analyze_build/report.html ninja

# call cpplint (some errors expected due to false positives)
cpplint:
	third_party/cpplint/cpplint.py --filter=-whitespace,-legal,-readability/alt_tokens,-runtime/references,-runtime/explicit --quiet --recursive include

clang_tidy:
	$(COMPILER_DIR)/clang-tidy $(SRCS) -- -Iinclude -std=c++11

pvs_studio:
	rm -fr pvs_studio_build
	mkdir pvs_studio_build
	cd pvs_studio_build ; cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS=On
	cd pvs_studio_build ; pvs-studio-analyzer analyze -j 10
	cd pvs_studio_build ; plog-converter -a'GA:1,2;64:1;CS' -t fullhtml PVS-Studio.log -o pvs
	open pvs_studio_build/pvs/index.html

infer:
	rm -fr infer_build
	mkdir infer_build
	cd infer_build ; infer compile -- cmake .. ; infer run -- make -j 4

oclint:
	oclint $(SRCS) -report-type html -enable-global-analysis -o oclint_report.html -max-priority-1=10000 -max-priority-2=10000 -max-priority-3=10000 -- -std=c++11 -Iinclude
	open oclint_report.html

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
	@for x in $(SRCS); do \
	  echo "Checking self-sufficiency of $$x..." ; \
	  echo "#include <$$x>\nint main() {}\n" | sed 's|include/||' > single_include_test.cpp; \
	  $(CXX) $(CXXFLAGS) -Iinclude -std=c++11 single_include_test.cpp -o single_include_test; \
	  rm -f single_include_test.cpp single_include_test; \
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
