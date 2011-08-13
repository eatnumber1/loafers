ACLOCAL_AMFLAGS = -I m4

CFLAGS += -std=gnu99 -Wall -Werror -Wextra

lib_LTLIBRARIES = libloafers.la
libloafers_la_SOURCES = src/loafers.c
libloafers_la_CFLAGS = -I$(srcdir)/include -fshort-enums
libloafers_la_LDFLAGS = -no-undefined -version-info 0:0:0

libloafers_la_includedir = $(includedir)
libloafers_la_include_HEADERS = include/loafers.h

noinst_HEADERS = include/_loafers.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = loafers.pc

.PHONY: examples

all-local: libloafers.la
	$(MAKE) -C examples

clean-local:
	$(MAKE) -C examples clean
