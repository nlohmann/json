SRCDIR = ../single_include
SED:=$(shell command -v gsed || which sed)

all: doxygen


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

# create links to try the code online
%.link: %.cpp
	rm -fr tmp
	mkdir tmp
	cp -r $(SRCDIR)/nlohmann tmp
	python2 scripts/send_to_wandbox.py tmp $< > $@.tmp
	/bin/echo -n "<a target=\"_blank\" href=\"`cat $@.tmp`\"><b>online</b></a>" > $@
	rm -fr tmp $@.tmp

# create output from all stand-alone example files
create_output: $(EXAMPLES:.cpp=.output)

create_links: $(EXAMPLES:.cpp=.link)

# check output of all stand-alone example files
check_output: $(EXAMPLES:.cpp=.test)


clean:
	rm -fr me.nlohmann.json.docset html $(EXAMPLES:.cpp=)
	$(MAKE) clean -C docset
	$(MAKE) clean -C mkdocs


##########################################################################
# Doxygen HTML documentation
##########################################################################

# create Doxygen documentation
doxygen: create_output create_links
	doxygen
	$(SED) -i 's@&lt; ObjectType, ArrayType, StringType, BooleanType, NumberIntegerType, NumberFloatType, AllocatorType, JSONSerializer &gt;@@g' html/*.html
	$(SED) -i 's@&lt;&#160;ObjectType,&#160;ArrayType,&#160;StringType,&#160;BooleanType,&#160;NumberIntegerType,&#160;NumberFloatType,&#160;AllocatorType&#160;JSONSerializer&#160;&gt;@@g' html/*.html
	$(SED) -i 's@&lt; ObjectType, ArrayType, StringType, BooleanType, NumberIntegerType, NumberUnsignedType, NumberFloatType, AllocatorType, JSONSerializer &gt;@@g' html/*.html
	$(SED) -i 's@< ObjectType, ArrayType, StringType, BooleanType, NumberIntegerType, NumberUnsignedType, NumberFloatType, AllocatorType, JSONSerializer >@@g' html/*.html
	$(SED) -i 's@&lt;&#160;ObjectType,&#160;ArrayType,&#160;StringType,&#160;BooleanType,&#160;NumberIntegerType,&#160;NumberUnsignedType,&#160;NumberFloatType,&#160;AllocatorType&#160;JSONSerializer&#160;&gt;@@g' html/*.html
	$(SED) -i 's@template&lt;template&lt; typename U, typename V, typename... Args &gt; class ObjectType = std::map, template&lt; typename U, typename... Args &gt; class ArrayType = std::vector, class StringType = std::string, class BooleanType = bool, class NumberIntegerType = std::int64_t, class NumberUnsignedType = std::uint64_t, class NumberFloatType = double, template&lt; typename U &gt; class AllocatorType = std::allocator, template&lt; typename T, typename SFINAE=void &gt; class JSONSerializer = adl_serializer&gt;@@g' html/*.html
	$(SED) -i 's@&lt; ObjectType, ArrayType, StringType, BooleanType, NumberIntegerType, NumberUnsignedType, NumberFloatType, AllocatorType, JSONSerializer &gt;@@g' html/*.html
	$(SED) -i 's@&lt;&#160;ObjectType,&#160;ArrayType,&#160;StringType,&#160;BooleanType,&#160;NumberIntegerType,&#160;NumberUnsignedType,&#160;NumberFloatType,&#160;AllocatorType,&#160;JSONSerializer&#160;&gt;@@g' html/*.html
	$(SED) -i 's@JSON_HEDLEY_RETURNS_NON_NULL@@g' html/*.html
	$(SED) -i 's@JSON_HEDLEY_WARN_UNUSED_RESULT@@g' html/*.html

upload: clean doxygen check_output
	scripts/git-update-ghpages nlohmann/json html
	rm -fr html
	open http://nlohmann.github.io/json/
