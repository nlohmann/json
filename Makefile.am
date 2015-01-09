.PHONY: header_only

# the order is important: header before other sources
CORE_SOURCES = src/json.h src/json.cc

noinst_PROGRAMS = json_unit json_parser

FLAGS = -Wall -Wextra -pedantic -Weffc++ -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wmissing-declarations -Wmissing-include-dirs -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-overflow=5 -Wswitch -Wundef -Wno-unused -Wnon-virtual-dtor -Wreorder

json_unit_SOURCES = $(CORE_SOURCES) test/catch.hpp test/json_unit.cc
json_unit_CXXFLAGS = $(FLAGS) -std=c++11
json_unit_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/test -Dprivate=public

json_parser_SOURCES = $(CORE_SOURCES) benchmark/parse.cc
json_parser_CXXFLAGS = -O3 -std=c++11 -flto
json_parser_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/benchmark

cppcheck:
	cppcheck --enable=all --inconclusive --std=c++11 src/json.*

svn-clean: maintainer-clean
	rm -fr configure INSTALL aclocal.m4 build-aux depcomp install-sh missing test-driver
	for DIR in $(DIST_SUBDIRS) .; do rm -f $$DIR/Makefile.in; done

pretty:
	astyle --style=allman --indent=spaces=4 --indent-modifiers \
	   --indent-switches --indent-preproc-block --indent-preproc-define \
	   --indent-col1-comments --pad-oper --pad-header --align-pointer=type \
	   --align-reference=type --add-brackets --convert-tabs --close-templates \
	   --lineend=linux --preserve-date --suffix=none \
	   $(SOURCES)

parser:
	make CXXFLAGS="" json_parser

header_only/json.h: $(CORE_SOURCES)
	cat $(CORE_SOURCES) | $(SED) 's/#include "json.h"//' > header_only/json.h

BUILT_SOURCES = header_only/json.h
