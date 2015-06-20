SRCDIR = ../../src

EXAMPLES = $(wildcard *.cpp)

all:
	@echo "check"
	@echo "create"

clean:
	rm -f $(EXAMPLES:.cpp=) $(EXAMPLES:.cpp=.output) $(EXAMPLES:.cpp=.test)

%.output: %.cpp
	make $(<:.cpp=) CPPFLAGS="-I $(SRCDIR)" CXXFLAGS="-std=c++11"
	./$(<:.cpp=) > $@
	rm $(<:.cpp=)

%.test: %.cpp
	make $(<:.cpp=) CPPFLAGS="-I $(SRCDIR)" CXXFLAGS="-std=c++11"
	./$(<:.cpp=) > $@
	diff $@ $(<:.cpp=.output)
	rm $(<:.cpp=) $@

create: $(EXAMPLES:.cpp=.output)

check: $(EXAMPLES:.cpp=.test)
