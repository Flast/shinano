#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([shinano], [0.2], [flast@tsukuba.wide.ad.jp])

AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_SRCDIR([src/shinano.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CXX
AC_LANG_PUSH([C++])
    AX_CXX_COMPILE_STDCXX_11
AC_LANG_POP

AM_PROG_LIBTOOL

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADER([execinfo.h])
AC_CHECK_HEADER([linux/if_tun.h])
AC_CHECK_HEADER([boost/version.hpp])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
