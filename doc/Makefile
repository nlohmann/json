SRCDIR = ../single_include

all: create_output

##########################################################################
# example files
##########################################################################

# where are the example cpp files
EXAMPLES = $(wildcard examples/*.cpp)

# create output from a stand-alone example file
%.output: %.cpp
	make $(<:.cpp=) CPPFLAGS="-I $(SRCDIR)" CXXFLAGS="-std=c++11"
	./$(<:.cpp=) > $@
	rm $(<:.cpp=)

# compare created output with current output of the example files
%.test: %.cpp
	make $(<:.cpp=) CPPFLAGS="-I $(SRCDIR)" CXXFLAGS="-std=c++11"
	./$(<:.cpp=) > $@
	diff $@ $(<:.cpp=.output)
	rm $(<:.cpp=) $@

# create output from all stand-alone example files
create_output: $(EXAMPLES:.cpp=.output)

# check output of all stand-alone example files
check_output: $(EXAMPLES:.cpp=.test)

clean:
	rm -fr $(EXAMPLES:.cpp=)
	$(MAKE) clean -C docset
	$(MAKE) clean -C mkdocs
