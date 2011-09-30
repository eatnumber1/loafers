ACLOCAL_AMFLAGS = -I m4

CFLAGS += -Wall -Werror -Wextra

lib_LTLIBRARIES = libloafers.la
libloafers_la_SOURCES = src/loafers.c src/statemachine.c src/stream.c
libloafers_la_CFLAGS = -I$(srcdir)/include -fshort-enums -fvisibility=hidden $(TALLOC_CFLAGS)
libloafers_la_LDFLAGS = -no-undefined -version-info 0:0:0 $(TALLOC_LIBS)

libloafers_la_includedir = $(includedir)
libloafers_la_include_HEADERS = include/loafers.h

noinst_HEADERS = include/_loafers.h include/_statemachine.h include/_common.h include/_stream.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = loafers.pc

.PHONY: examples

all-local: libloafers.la
	$(MAKE) -C examples

clean-local:
	$(MAKE) -C examples clean
