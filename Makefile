.PHONY: pretty clean ChangeLog.md release

##########################################################################
# configuration
##########################################################################

# find GNU sed to use `-i` parameter
SED:=$(shell command -v gsed || which sed)


##########################################################################
# source files
##########################################################################

# the list of sources in the include folder
SRCS=$(shell find include -type f | sort)

# the list of sources in the tests folder
TESTS_SRCS=$(shell find tests -type f \( -name '*.hpp' -o -name '*.cpp' -o -name '*.cu' \) -not -path 'tests/thirdparty/*' -not -path 'tests/abi/include/nlohmann/*' | sort)

# the single headers (amalgamated from the source files)
AMALGAMATED_FILE=single_include/nlohmann/json.hpp
AMALGAMATED_FWD_FILE=single_include/nlohmann/json_fwd.hpp


##########################################################################
# documentation of the Makefile's targets
##########################################################################

# main target
all:
	@echo "amalgamate - amalgamate files single_include/nlohmann/json{,_fwd}.hpp from the include/nlohmann sources"
	@echo "ChangeLog.md - generate ChangeLog file"
	@echo "check-amalgamation - check whether sources have been amalgamated"
	@echo "clean - remove built files"
	@echo "doctest - compile example files and check their output"
	@echo "fuzz_testing - prepare fuzz testing of the JSON parser"
	@echo "fuzz_testing_bson - prepare fuzz testing of the BSON parser"
	@echo "fuzz_testing_cbor - prepare fuzz testing of the CBOR parser"
	@echo "fuzz_testing_msgpack - prepare fuzz testing of the MessagePack parser"
	@echo "fuzz_testing_ubjson - prepare fuzz testing of the UBJSON parser"
	@echo "pretty - beautify code with Artistic Style"
	@echo "run_benchmarks - build and run benchmarks"


##########################################################################
# documentation tests
##########################################################################

# compile example files and check output
doctest:
	$(MAKE) check_output -C docs


##########################################################################
# benchmarks
##########################################################################

run_benchmarks:
	rm -fr cmake-build-benchmarks
	mkdir cmake-build-benchmarks
	cd cmake-build-benchmarks ; cmake ../tests/benchmarks -GNinja -DCMAKE_BUILD_TYPE=Release
	cd cmake-build-benchmarks ; ninja
	cd cmake-build-benchmarks ; ./json_benchmarks


##########################################################################
# fuzzing
##########################################################################

# the overall fuzz testing target
fuzz_testing:
	rm -fr fuzz-testing
	mkdir -p fuzz-testing fuzz-testing/testcases fuzz-testing/out
	$(MAKE) parse_afl_fuzzer -C tests CXX=afl-clang++
	mv tests/parse_afl_fuzzer fuzz-testing/fuzzer
	find tests/data/json_tests -size -5k -name *json | xargs -I{} cp "{}" fuzz-testing/testcases
	@echo "Execute: afl-fuzz -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer"

fuzz_testing_bson:
	rm -fr fuzz-testing
	mkdir -p fuzz-testing fuzz-testing/testcases fuzz-testing/out
	$(MAKE) parse_bson_fuzzer -C tests CXX=afl-clang++
	mv tests/parse_bson_fuzzer fuzz-testing/fuzzer
	find tests/data -size -5k -name *.bson | xargs -I{} cp "{}" fuzz-testing/testcases
	@echo "Execute: afl-fuzz -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer"

fuzz_testing_cbor:
	rm -fr fuzz-testing
	mkdir -p fuzz-testing fuzz-testing/testcases fuzz-testing/out
	$(MAKE) parse_cbor_fuzzer -C tests CXX=afl-clang++
	mv tests/parse_cbor_fuzzer fuzz-testing/fuzzer
	find tests/data -size -5k -name *.cbor | xargs -I{} cp "{}" fuzz-testing/testcases
	@echo "Execute: afl-fuzz -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer"

fuzz_testing_msgpack:
	rm -fr fuzz-testing
	mkdir -p fuzz-testing fuzz-testing/testcases fuzz-testing/out
	$(MAKE) parse_msgpack_fuzzer -C tests CXX=afl-clang++
	mv tests/parse_msgpack_fuzzer fuzz-testing/fuzzer
	find tests/data -size -5k -name *.msgpack | xargs -I{} cp "{}" fuzz-testing/testcases
	@echo "Execute: afl-fuzz -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/fuzzer"

fuzz_testing_ubjson:
	rm -fr fuzz-testing
	mkdir -p fuzz-testing fuzz-testing/testcases fuzz-testing/out
	$(MAKE) parse_ubjson_fuzzer -C tests CXX=afl-clang++
	mv tests/parse_ubjson_fuzzer fuzz-testing/fuzzer
	find tests/data -size -5k -name *.ubjson | xargs -I{} cp "{}" fuzz-testing/testcases
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
# Static analysis
##########################################################################

# call PVS-Studio Analyzer <https://www.viva64.com/en/pvs-studio/>
pvs_studio:
	rm -fr cmake-build-pvs-studio
	mkdir cmake-build-pvs-studio
	cd cmake-build-pvs-studio ; cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS=On -DJSON_MultipleHeaders=ON
	cd cmake-build-pvs-studio ; pvs-studio-analyzer analyze -j 10
	cd cmake-build-pvs-studio ; plog-converter -a'GA:1,2;64:1;CS' -t fullhtml PVS-Studio.log -o pvs
	open cmake-build-pvs-studio/pvs/index.html


##########################################################################
# Code format and source amalgamation
##########################################################################

# call the Artistic Style pretty printer on all source files
pretty:
	astyle \
	    --style=allman \
	    --indent=spaces=4 \
	    --indent-modifiers \
	    --indent-switches \
	    --indent-preproc-block \
	    --indent-preproc-define \
	    --indent-col1-comments \
	    --pad-oper \
	    --pad-header \
	    --align-pointer=type \
	    --align-reference=type \
	    --add-brackets \
	    --convert-tabs \
	    --close-templates \
	    --lineend=linux \
	    --preserve-date \
	    --suffix=none \
	    --formatted \
	   $(SRCS) $(TESTS_SRCS) $(AMALGAMATED_FILE) $(AMALGAMATED_FWD_FILE) docs/examples/*.cpp

# call the Clang-Format on all source files
pretty_format:
	for FILE in $(SRCS) $(TESTS_SRCS) $(AMALGAMATED_FILE) docs/examples/*.cpp; do echo $$FILE; clang-format -i $$FILE; done

# create single header files and pretty print
amalgamate: $(AMALGAMATED_FILE) $(AMALGAMATED_FWD_FILE)
	$(MAKE) pretty

# call the amalgamation tool for json.hpp
$(AMALGAMATED_FILE): $(SRCS)
	tools/amalgamate/amalgamate.py -c tools/amalgamate/config_json.json -s . --verbose=yes

# call the amalgamation tool for json_fwd.hpp
$(AMALGAMATED_FWD_FILE): $(SRCS)
	tools/amalgamate/amalgamate.py -c tools/amalgamate/config_json_fwd.json -s . --verbose=yes

# check if file single_include/nlohmann/json.hpp has been amalgamated from the nlohmann sources
# Note: this target is called by Travis
check-amalgamation:
	@mv $(AMALGAMATED_FILE) $(AMALGAMATED_FILE)~
	@mv $(AMALGAMATED_FWD_FILE) $(AMALGAMATED_FWD_FILE)~
	@$(MAKE) amalgamate
	@diff $(AMALGAMATED_FILE) $(AMALGAMATED_FILE)~ || (echo "===================================================================\n  Amalgamation required! Please read the contribution guidelines\n  in file .github/CONTRIBUTING.md.\n===================================================================" ; mv $(AMALGAMATED_FILE)~ $(AMALGAMATED_FILE) ; false)
	@diff $(AMALGAMATED_FWD_FILE) $(AMALGAMATED_FWD_FILE)~ || (echo "===================================================================\n  Amalgamation required! Please read the contribution guidelines\n  in file .github/CONTRIBUTING.md.\n===================================================================" ; mv $(AMALGAMATED_FWD_FILE)~ $(AMALGAMATED_FWD_FILE) ; false)
	@mv $(AMALGAMATED_FILE)~ $(AMALGAMATED_FILE)
	@mv $(AMALGAMATED_FWD_FILE)~ $(AMALGAMATED_FWD_FILE)

BUILD.bazel: $(SRCS)
	cmake -P cmake/scripts/gen_bazel_build_file.cmake

##########################################################################
# ChangeLog
##########################################################################

# Create a ChangeLog based on the git log using the GitHub Changelog Generator
# (<https://github.com/github-changelog-generator/github-changelog-generator>).

# variable to control the diffs between the last released version and the current repository state
NEXT_VERSION ?= "unreleased"

ChangeLog.md:
	github_changelog_generator -o ChangeLog.md --user nlohmann --project json --simple-list --release-url https://github.com/nlohmann/json/releases/tag/%s --future-release $(NEXT_VERSION)
	$(SED) -i 's|https://github.com/nlohmann/json/releases/tag/HEAD|https://github.com/nlohmann/json/tree/HEAD|' ChangeLog.md
	$(SED) -i '2i All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/).' ChangeLog.md


##########################################################################
# Release files
##########################################################################

# Create a tar.gz archive that contains sufficient files to be used as CMake project (e.g., using FetchContent). The
# archive is created according to the advices of <https://reproducible-builds.org/docs/archives/>.
json.tar.xz:
	mkdir json
	rsync -R $(shell find LICENSE.MIT nlohmann_json.natvis CMakeLists.txt cmake/*.in include single_include -type f) json
	gtar --sort=name --mtime="@$(shell git log -1 --pretty=%ct)" --owner=0 --group=0 --numeric-owner --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime --create --file - json | xz --compress -9e --threads=2 - > json.tar.xz
	rm -fr json

# We use `-X` to make the resulting ZIP file reproducible, see
# <https://content.pivotal.io/blog/barriers-to-deterministic-reproducible-zip-files>.
include.zip: BUILD.bazel
	zip -9 --recurse-paths -X include.zip $(SRCS) $(AMALGAMATED_FILE) $(AMALGAMATED_FWD_FILE) BUILD.bazel WORKSPACE.bazel meson.build LICENSE.MIT

# Create the files for a release and add signatures and hashes.
release: include.zip json.tar.xz
	rm -fr release_files
	mkdir release_files
	gpg --armor --detach-sig include.zip
	gpg --armor --detach-sig $(AMALGAMATED_FILE)
	gpg --armor --detach-sig $(AMALGAMATED_FWD_FILE)
	gpg --armor --detach-sig json.tar.xz
	cp $(AMALGAMATED_FILE) release_files
	cp $(AMALGAMATED_FWD_FILE) release_files
	mv $(AMALGAMATED_FILE).asc $(AMALGAMATED_FWD_FILE).asc json.tar.xz json.tar.xz.asc include.zip include.zip.asc release_files
	cd release_files ; shasum -a 256 json.hpp include.zip json.tar.xz > hashes.txt


##########################################################################
# Maintenance
##########################################################################

# clean up
clean:
	rm -fr fuzz fuzz-testing *.dSYM tests/*.dSYM
	rm -fr benchmarks/files/numbers/*.json
	rm -fr cmake-build-benchmarks fuzz-testing cmake-build-pvs-studio release_files
	$(MAKE) clean -Cdocs


##########################################################################
# Thirdparty code
##########################################################################

update_hedley:
	rm -f include/nlohmann/thirdparty/hedley/hedley.hpp include/nlohmann/thirdparty/hedley/hedley_undef.hpp
	curl https://raw.githubusercontent.com/nemequ/hedley/master/hedley.h -o include/nlohmann/thirdparty/hedley/hedley.hpp
	$(SED) -i 's/HEDLEY_/JSON_HEDLEY_/g' include/nlohmann/thirdparty/hedley/hedley.hpp
	grep "[[:blank:]]*#[[:blank:]]*undef" include/nlohmann/thirdparty/hedley/hedley.hpp | grep -v "__" | sort | uniq | $(SED) 's/ //g' | $(SED) 's/undef/undef /g' > include/nlohmann/thirdparty/hedley/hedley_undef.hpp
	$(SED) -i '1s/^/#pragma once\n\n/' include/nlohmann/thirdparty/hedley/hedley.hpp
	$(SED) -i '1s/^/#pragma once\n\n/' include/nlohmann/thirdparty/hedley/hedley_undef.hpp
	$(MAKE) amalgamate

##########################################################################
# serve_header.py
##########################################################################

serve_header:
	./tools/serve_header/serve_header.py --make $(MAKE)

##########################################################################
# REUSE
##########################################################################

reuse:
	pipx run reuse addheader --recursive single_include include -tjson --license MIT --copyright "Niels Lohmann <https://nlohmann.me>" --year "2013-2022"
	pipx run reuse addheader $(TESTS_SRCS) --style=c -tjson_support --license MIT --copyright "Niels Lohmann <https://nlohmann.me>" --year "2013-2022"
	pipx run reuse lint
