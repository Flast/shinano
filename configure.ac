#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([shinano], [0.2], [flast@tsukuba.wide.ad.jp])

AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_SRCDIR([src/shinano.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_LANG([C++])

# Checks for programs.
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX_11
AX_CHECK_COMPILE_FLAG([-Wall],   [CXXFLAGS="$CXXFLAGS -Wall"])
AX_CHECK_COMPILE_FLAG([-Wextra], [CXXFLAGS="$CXXFLAGS -Wextra"])

AM_PROG_LIBTOOL
AX_CHECK_LINK_FLAG([-rdynamic], [LDFLAGS="$LDFLAGS -rdynamic"])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADER([execinfo.h])
AC_CHECK_HEADER([linux/if_tun.h])
AC_CHECK_HEADER([boost/version.hpp])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
#AX_CXX_CHECK_LIB([boost_system], [boost::system::generic_category()]
#                ,
#                , [AC_MSG_ERROR(Boost.System required)])
#AX_CXX_CHECK_LIB([boost_chrono], [boost::chrono::system_clock::now()]
#                ,
#                , [AC_MSG_ERROR(Boost.Chrono required)])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
