bin_PROGRAMS = hello nonblock-hello listen

hello_SOURCES = hello.c
hello_CFLAGS = -I$(top_srcdir)/include $(TALLOC_CFLAGS)
hello_LDADD = $(top_builddir)/libloafers.la $(TALLOC_LIBS)

nonblock_hello_SOURCES = nonblock-hello.c
nonblock_hello_CFLAGS = -I$(top_srcdir)/include $(TALLOC_CFLAGS)
nonblock_hello_LDADD = $(top_builddir)/libloafers.la $(TALLOC_LIBS)

listen_SOURCES = listen.c
listen_CFLAGS = -I$(top_srcdir)/include -fshort-enums $(TALLOC_CFLAGS)
listen_LDADD = $(top_builddir)/libloafers.la $(TALLOC_LIBS)
