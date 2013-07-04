noinst_PROGRAMS = json json98
TESTS = ./json ./json98

#CXXFLAGS = -O3 -flto

json_SOURCES = src/JSON.cc src/JSON.h test/JSON_test.cc
json_CXXFLAGS = -std=c++11
json_CPPFLAGS = -I$(top_srcdir)/src

json98_SOURCES = src/JSON.cc src/JSON.h test/JSON_test.cc
json98_CXXFLAGS = -std=c++98
json98_CPPFLAGS = -I$(top_srcdir)/src

svn-clean: maintainer-clean
	rm -fr configure INSTALL aclocal.m4 build-aux depcomp install-sh missing test-driver
	for DIR in $(DIST_SUBDIRS) .; do rm -f $$DIR/Makefile.in; done
