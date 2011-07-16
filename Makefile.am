ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libshoes.la
libshoes_la_SOURCES = src/shoes.c
libshoes_la_CFLAGS = -I$(srcdir)/include -std=gnu99 -fshort-enums $(libpack_CFLAGS)
libshoes_la_LDFLAGS = -no-undefined -version-info 0:0:0
libshoes_la_LIBADD = $(libpack_LIBS)

libshoes_la_includedir = $(includedir)
libshoes_la_include_HEADERS = include/shoes.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = shoes.pc
