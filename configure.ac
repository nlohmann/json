AC_INIT([JSON], [3.0], [mail@nlohmann.me])
AC_CONFIG_SRCDIR([src/json.hpp.re2c])

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

AC_PROG_CXX
AC_PROG_SED
AC_PATH_PROG(RE2C, [re2c])
AM_MISSING_PROG(CPPCHECK, [cppcheck])
AM_MISSING_PROG(ASTYLE, [astyle])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
