BLAKE2_DIR = /home/nfsv4/dev/BLAKE2/ref
CC = gcc
CFLAGS = -Wall -I$(BLAKE2_DIR)

BLAKE2_OBJ = $(BLAKE2_DIR)/blake2s-ref.o

TARGET = prototype1_client

all: $(TARGET)

$(TARGET): prototype1_client.o client.o noise_crypto.o $(BLAKE2_OBJ)
	$(CC) prototype1_client.o client.o noise_crypto.o $(BLAKE2_OBJ) -o $(TARGET) -lsodium

prototype1_client.o: prototype1_client.c client.h noise_crypto.h
	$(CC) $(CFLAGS) -c prototype1_client.c -o prototype1_client.o

client.o: client.c client.h noise_crypto.h
	$(CC) $(CFLAGS) -c client.c -o client.o

noise_crypto.o: noise_crypto.c noise_crypto.h
	$(CC) $(CFLAGS) -c noise_crypto.c -o noise_crypto.o

check: $(TARGET)
	./$(TARGET)

clean:
	rm -f *.o $(TARGET)
