##########################################################################
# unit tests
##########################################################################

# additional flags
CXXFLAGS += -std=c++11 -Wall -Wextra -pedantic -Weffc++ -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wmissing-declarations -Wmissing-include-dirs -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-overflow=5 -Wswitch -Wundef -Wno-unused -Wnon-virtual-dtor -Wreorder -Wdeprecated -Wfloat-equal
INCDIRS = -I ../src -I .

SOURCES = src/unit-runner.cpp src/unit.cpp
OBJECTS = $(SOURCES:.cpp=.o)

all: json_unit

json_unit: $(OBJECTS) ../src/json.hpp src/catch.hpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(OBJECTS) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCDIRS) -c $< -o $@

clean:
	rm -fr json_unit $(OBJECTS)
