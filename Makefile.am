ACLOCAL_AMFLAGS = -I m4

CFLAGS += -std=c99 -Wall -Werror -Wextra

lib_LTLIBRARIES = libshoes.la
libshoes_la_SOURCES = src/shoes.c
libshoes_la_CFLAGS = -I$(srcdir)/include -fshort-enums
libshoes_la_LDFLAGS = -no-undefined -version-info 0:0:0

libshoes_la_includedir = $(includedir)
libshoes_la_include_HEADERS = include/shoes.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = shoes.pc

.PHONY: examples

all-local: libshoes.la
	$(MAKE) -C examples

clean-local:
	$(MAKE) -C examples clean
