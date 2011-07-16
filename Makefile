# TODO: Better Makefile

CC := llvm-gcc-4.2

CPPFLAGS := -Iinclude
LDFLAGS :=
CFLAGS := -fshort-enums -std=gnu99 -Wall -Wextra -Werror -ggdb -fPIC

CPPFLAGS += $(shell pkg-config --cflags libpack)
LDFLAGS += $(shell pkg-config --libs libpack)

SOURCES := src/shoes.c
OBJECTS := $(SOURCES:.c=.o)

.PHONY: all clean examples

all: libshoes.so

clean:
	$(RM) $(OBJECTS) libshoes.so examples/hello examples/hello.o examples/sockscat examples/sockscat.o

examples: examples/hello examples/sockscat

examples/hello: examples/hello.o
	$(CC) $(CFLAGS) -Wl,-rpath,$(PWD) -L$(PWD) -lshoes -o $@ $<

examples/hello.o: examples/hello.c include/shoes.h
	$(CC) -c -Iinclude $(CFLAGS) -o $@ $<

examples/sockscat: examples/sockscat.o
	$(CC) $(CFLAGS) -Wl,-rpath,$(PWD) -L$(PWD) -lshoes -o $@ $<

examples/sockscat.o: examples/sockscat.c include/shoes.h
	$(CC) -c -Iinclude $(CFLAGS) -o $@ $<

libshoes.so: $(OBJECTS)
	$(CC) -shared $(CFLAGS) $(LDFLAGS) -o $@ $<

src/shoes.o: include/shoes.h src/shoes.c
