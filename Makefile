CC = gcc
CFLAGS = -m32 -D_FILE_OFFSET_BITS=64 -Wall -Wextra -g
# Example objects must be 32-bit and non-PIE so they contain plain ELF32 relocations
EXAMPLE_CFLAGS = -m32 -c -fno-pie -O0
EXAMPLES = examples/main_part.o examples/helper_part.o examples/conflict.o

.PHONY: all examples clean

all: myELF

myELF: myELF.o
	$(CC) $(CFLAGS) -o myELF myELF.o

myELF.o: myELF.c
	$(CC) $(CFLAGS) -c myELF.c

examples: $(EXAMPLES)

examples/%.o: examples/%.c
	$(CC) $(EXAMPLE_CFLAGS) $< -o $@

clean:
	rm -f *.o myELF out.ro examples/*.o
