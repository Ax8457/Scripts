BLAKE2_DIR = /home/nfsv4/dev/BLAKE2/ref
CC = gcc
CFLAGS = -Wall -I$(BLAKE2_DIR)

BLAKE2_OBJ = $(BLAKE2_DIR)/blake2s-ref.o

TARGET = prototype1

all: $(TARGET)

$(TARGET): prototype1.o noise_crypto.o server.o $(BLAKE2_OBJ)
	$(CC) prototype1.o noise_crypto.o server.o $(BLAKE2_OBJ) -o $(TARGET) -lsodium

prototype1.o: prototype1.c noise_crypto.h
	$(CC) $(CFLAGS) -c prototype1.c -o prototype1.o

noise_crypto.o: noise_crypto.c noise_crypto.h
	$(CC) $(CFLAGS) -c noise_crypto.c -o noise_crypto.o

server.o: server.c server.h
	$(CC) $(CFLAGS) -c server.c -o server.o
	
check: $(TARGET)
	./$(TARGET)

clean:
	rm -f *.o $(TARGET)
