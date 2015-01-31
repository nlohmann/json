.PHONY: header_only

noinst_PROGRAMS = json_unit

FLAGS = -Wall -Wextra -pedantic -Weffc++ -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wmissing-declarations -Wmissing-include-dirs -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-overflow=5 -Wswitch -Wundef -Wno-unused -Wnon-virtual-dtor -Wreorder

json_unit_SOURCES = $(CORE_SOURCES) test/catch.hpp test/unit.cpp src/json.hpp
json_unit_CXXFLAGS = $(FLAGS) -std=c++11
json_unit_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/test -Dprivate=public

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
