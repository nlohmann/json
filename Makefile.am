noinst_PROGRAMS = json json98 json98benchmark
TESTS = ./json ./json98

json_SOURCES = src/JSON.cc src/JSON.h test/JSON_test.cc
json_CXXFLAGS = -std=c++11
json_CPPFLAGS = -I$(top_srcdir)/src

json98_SOURCES = src/JSON.cc src/JSON.h test/JSON_test.cc
json98_CXXFLAGS = -std=c++98
json98_CPPFLAGS = -I$(top_srcdir)/src

json98benchmark_SOURCES = src/JSON.cc src/JSON.h benchmark/JSON_benchmark.cc
json98benchmark_CXXFLAGS = -std=c++98 -O3
json98benchmark_CPPFLAGS = -I$(top_srcdir)/src -DNDEBUG

svn-clean: maintainer-clean
	rm -fr configure INSTALL aclocal.m4 build-aux depcomp install-sh missing test-driver cover_html *.gcda *.gcno coverage*.info
	for DIR in $(DIST_SUBDIRS) .; do rm -f $$DIR/Makefile.in; done

cover:
	make clean
	make json98 CXXFLAGS+="--coverage -g -fprofile-arcs -ftest-coverage" CPPFLAGS+="-DNDEBUG"
	./json98
	lcov --capture --directory . --output-file coverage98.info
	genhtml coverage*.info --output-directory cover_html --show-details --title "$(PACKAGE_STRING)" --legend --demangle-cpp
