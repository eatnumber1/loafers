# TODO: Better Makefile

CC := llvm-gcc

CPPFLAGS := -Iinclude -I/Users/russ/Downloads/libpack-0.3/install/include
LDFLAGS := -L/Users/russ/Downloads/libpack-0.3/install/lib -lpack
CFLAGS := -fshort-enums -std=gnu99 -Wall -Wextra -Werror -ggdb

CPPFLAGS += $(shell pkg-config --cflags talloc)
LDFLAGS += $(shell pkg-config --libs talloc)

SOURCES := src/shoes.c
OBJECTS := $(SOURCES:.c=.o)

.PHONY: all clean examples

all: libshoes.dylib

clean:
	$(RM) $(OBJECTS) libshoes.dylib examples/hello examples/hello.o
	$(RM) -r libshoes.dylib.dSYM

examples: examples/hello

examples/hello: examples/hello.o
	$(CC) $(CFLAGS) -Wl,-rpath,$(PWD) -L$(PWD) -lshoes -o $@ $<

examples/hello.o: examples/hello.c include/shoes.h
	$(CC) -c -Iinclude $(CFLAGS) -o $@ $<

libshoes.dylib: $(OBJECTS)
	$(CC) -shared $(CFLAGS) $(LDFLAGS) -o $@ $<

src/shoes.o: include/shoes.h src/shoes.c
