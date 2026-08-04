CC = gcc
CFLAGS = -m32 -D_FILE_OFFSET_BITS=64 -Wall -g

all: myELF

myELF: myELF.o
	$(CC) $(CFLAGS) -o myELF myELF.o

myELF.o: myELF.c
	$(CC) $(CFLAGS) -c myELF.c

clean:
	rm -f *.o myELF out.ro