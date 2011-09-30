#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([loafers], [0.1], [russ@eatnumber1.com])
AC_CONFIG_SRCDIR([include/loafers.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])

# Checks for programs.
#AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_LIBTOOL

# Checks for header files.
AC_HEADER_STDBOOL
AC_HEADER_ASSERT

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([getaddrinfo freeaddrinfo inet_ntop gai_strerror])
AC_CHECK_FUNCS([htonl htons ntohl ntohs])

# Checks for talloc library
PKG_CHECK_MODULES([TALLOC], [talloc])

m4_include([m4/m4_ifnblank.m4])
AX_TLS([], [
	AC_MSG_WARN([No thread-local support. Loafers will not be thread-safe])
	AC_DEFINE_UNQUOTED([TLS], [])
])

AC_CONFIG_FILES([Makefile examples/Makefile loafers.pc])
AC_OUTPUT
