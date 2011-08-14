bin_PROGRAMS = hello nonblock-hello sockscat listen

hello_SOURCES = hello.c
hello_CFLAGS = -I$(top_srcdir)/include
hello_LDADD = $(top_builddir)/libloafers.la

nonblock_hello_SOURCES = nonblock-hello.c
nonblock_hello_CFLAGS = -I$(top_srcdir)/include
nonblock_hello_LDADD = $(top_builddir)/libloafers.la

sockscat_SOURCES = sockscat.c
sockscat_CFLAGS = -I$(top_srcdir)/include
sockscat_LDADD = $(top_builddir)/libloafers.la

listen_SOURCES = listen.c
listen_CFLAGS = -I$(top_srcdir)/include -fshort-enums
listen_LDADD = $(top_builddir)/libloafers.la
