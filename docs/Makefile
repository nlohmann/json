SRCDIR = ../single_include

all: create_output

##########################################################################
# example files
##########################################################################

# where are the example cpp files
EXAMPLES = $(wildcard mkdocs/docs/examples/*.cpp)

cxx_standard = $(lastword c++11 $(filter c++%, $(subst ., ,$1)))

# create output from a stand-alone example file
%.output: %.cpp
	@echo "standard $(call cxx_standard $(<:.cpp=))"
	$(MAKE) $(<:.cpp=) \
		CPPFLAGS="-I $(SRCDIR) -DJSON_USE_GLOBAL_UDLS=0" \
		CXXFLAGS="-std=$(call cxx_standard,$(<:.cpp=)) -Wno-deprecated-declarations"
	./$(<:.cpp=) > $@
	rm $(<:.cpp=)

# compare created output with current output of the example files
%.test: %.cpp
	$(MAKE) $(<:.cpp=) \
		CPPFLAGS="-I $(SRCDIR) -DJSON_USE_GLOBAL_UDLS=0" \
		CXXFLAGS="-std=$(call cxx_standard,$(<:.cpp=)) -Wno-deprecated-declarations"
	./$(<:.cpp=) > $@
	diff $@ $(<:.cpp=.output)
	rm $(<:.cpp=) $@

# create output from all stand-alone example files
create_output: $(EXAMPLES:.cpp=.output)

# check output of all stand-alone example files
check_output: $(EXAMPLES:.cpp=.test)

# check output of all stand-alone example files (exclude files with platform-dependent output.)
# This target is used in the CI (ci_test_documentation).
check_output_portable: $(filter-out mkdocs/docs/examples/meta.test mkdocs/docs/examples/max_size.test mkdocs/docs/examples/std_hash.test mkdocs/docs/examples/basic_json__CompatibleType.test,$(EXAMPLES:.cpp=.test))

clean:
	rm -fr $(EXAMPLES:.cpp=)
	$(MAKE) clean -C docset
