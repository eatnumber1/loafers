bin_PROGRAMS = hello nonblock-hello listen

hello_SOURCES = hello.c
hello_CFLAGS = -I$(top_srcdir)/include
hello_LDADD = $(top_builddir)/libloafers.la

nonblock_hello_SOURCES = nonblock-hello.c
nonblock_hello_CFLAGS = -I$(top_srcdir)/include
nonblock_hello_LDADD = $(top_builddir)/libloafers.la

listen_SOURCES = listen.c
listen_CFLAGS = -I$(top_srcdir)/include -fshort-enums
listen_LDADD = $(top_builddir)/libloafers.la
