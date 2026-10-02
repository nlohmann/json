SRCDIR = ../single_include

all: create_output

##########################################################################
# example files
##########################################################################

# where are the example cpp files
EXAMPLES = $(wildcard mkdocs/docs/examples/*.cpp)

cxx_standard = $(lastword c++11 $(filter c++%, $(subst ., ,$1)))

# common compile flags for the stand-alone example files
EXAMPLE_CPPFLAGS = -I $(SRCDIR) -DJSON_USE_GLOBAL_UDLS=0
EXAMPLE_WARNFLAGS = -Werror=deprecated-declarations

# examples that document deprecated API and are allowed to use it
DEPRECATED_EXAMPLES = $(addprefix mkdocs/docs/examples/, \
	json_pointer__operator__equal_stringtype \
	json_pointer__operator__notequal_stringtype \
	json_pointer__operator_string_t)
$(DEPRECATED_EXAMPLES:=.output) $(DEPRECATED_EXAMPLES:=.test): EXAMPLE_WARNFLAGS = -Wno-deprecated-declarations

# create output from a stand-alone example file
%.output: %.cpp
	@echo "standard $(call cxx_standard,$(<:.cpp=))"
	$(MAKE) $(<:.cpp=) \
		CPPFLAGS="$(EXAMPLE_CPPFLAGS)" \
		CXXFLAGS="-std=$(call cxx_standard,$(<:.cpp=)) $(EXAMPLE_WARNFLAGS)"
	./$(<:.cpp=) > $@
	rm $(<:.cpp=)

# compare created output with current output of the example files
%.test: %.cpp
	$(MAKE) $(<:.cpp=) \
		CPPFLAGS="$(EXAMPLE_CPPFLAGS)" \
		CXXFLAGS="-std=$(call cxx_standard,$(<:.cpp=)) $(EXAMPLE_WARNFLAGS)"
	./$(<:.cpp=) > $@
	diff $@ $(<:.cpp=.output)
	rm $(<:.cpp=) $@

# create output from all stand-alone example files
create_output: $(EXAMPLES:.cpp=.output)

# check output of all stand-alone example files
check_output: $(EXAMPLES:.cpp=.test)

# check output of all stand-alone example files (exclude files whose output depends on the platform by nature:
# library and compiler information, container size limits, and hash values)
# This target is used in the CI (ci_test_documentation).
check_output_portable: $(filter-out mkdocs/docs/examples/meta.test mkdocs/docs/examples/max_size.test mkdocs/docs/examples/std_hash.test,$(EXAMPLES:.cpp=.test))

clean:
	rm -fr $(EXAMPLES:.cpp=)
	$(MAKE) clean -C docset
