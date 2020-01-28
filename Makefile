INCLUDEDIR=./include

CC=gcc
CFLAGS=-I./include -lfuse3 -pthread -lm -lssl -lcrypto -D_FILE_FFSET_BITS=64

OBJ = fs_main.o log.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

uselessfs: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f *.o uselessfs
