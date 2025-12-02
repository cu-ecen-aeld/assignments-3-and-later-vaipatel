# Default CROSS_COMPILE to empty string, unless user supplies a value.
CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall -Wextra

.PHONY: all clean writer

all: writer

writer: writer.o
	$(CC) $(CFLAGS) writer.o -o writer

writer.o: writer.c
	$(CC) $(CFLAGS) -c writer.c -o writer.o

clean:
	rm -f writer *.o
