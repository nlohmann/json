.PHONY: header_only

noinst_PROGRAMS = json_unit

FLAGS = -Wall -Wextra -pedantic -Weffc++ -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wmissing-declarations -Wmissing-include-dirs -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-overflow=5 -Wswitch -Wundef -Wno-unused -Wnon-virtual-dtor -Wreorder

json_unit_SOURCES = src/json.hpp test/catch.hpp test/unit.cpp
json_unit_CXXFLAGS = $(FLAGS) -std=c++11
json_unit_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/test -Dprivate=public

# parameters:
# -b                     use bit vectors
# -s                     nested ifs
# -i                     do not create #line information
# --no-generation-date   suppress generation date output
src/json.hpp: src/json.hpp.re2c
	$(AM_V_GEN)$(RE2C) -b -s -i --no-generation-date $< | $(SED) '1d' > $@

cppcheck:
	cppcheck --enable=all --inconclusive --std=c++11 src/json.hpp

svn-clean: maintainer-clean
	rm -fr configure INSTALL aclocal.m4 build-aux depcomp install-sh missing test-driver
	for DIR in $(DIST_SUBDIRS) .; do rm -f $$DIR/Makefile.in; done

pretty:
	astyle --style=allman --indent=spaces=4 --indent-modifiers \
	   --indent-switches --indent-preproc-block --indent-preproc-define \
	   --indent-col1-comments --pad-oper --pad-header --align-pointer=type \
	   --align-reference=type --add-brackets --convert-tabs --close-templates \
	   --lineend=linux --preserve-date --suffix=none \
	   src/json.hpp src/json.hpp.re2c test/unit.cpp
