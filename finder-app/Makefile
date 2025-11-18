# Default CROSS_COMPILE to empty string, unless user supplies a value.
CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc

writer: writer.o
	$(CC) writer.o -o writer

writer.o: writer.c
	$(CC) -c writer.c -o writer.o

clean:
	rm -f writer *.o
