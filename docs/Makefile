SRCDIR = ../single_include

all: create_output

##########################################################################
# example files
##########################################################################

# where are the example cpp files
EXAMPLES = $(wildcard examples/*.cpp)

# create output from a stand-alone example file
%.output: %.cpp
	$(MAKE) $(<:.cpp=) CPPFLAGS="-I $(SRCDIR)" CXXFLAGS="-std=c++11"
	./$(<:.cpp=) > $@
	rm $(<:.cpp=)

# compare created output with current output of the example files
%.test: %.cpp
	$(MAKE) $(<:.cpp=) CPPFLAGS="-I $(SRCDIR)" CXXFLAGS="-std=c++11"
	./$(<:.cpp=) > $@
	diff $@ $(<:.cpp=.output)
	rm $(<:.cpp=) $@

# create output from all stand-alone example files
create_output: $(EXAMPLES:.cpp=.output)

# check output of all stand-alone example files
check_output: $(EXAMPLES:.cpp=.test)

# check output of all stand-alone example files (exclude files with platform-dependent output.)
# This target is used in the CI (ci_test_documentation).
check_output_portable: $(filter-out examples/meta.test examples/max_size.test examples/std_hash.test examples/basic_json__CompatibleType.test,$(EXAMPLES:.cpp=.test))

clean:
	rm -fr $(EXAMPLES:.cpp=)
	$(MAKE) clean -C docset
	$(MAKE) clean -C mkdocs
