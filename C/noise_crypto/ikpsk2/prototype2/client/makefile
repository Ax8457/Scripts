BLAKE2_DIR = /home/nfsv4/dev/BLAKE2/ref
CC = gcc
CFLAGS = -Wall -I$(BLAKE2_DIR)

BLAKE2_OBJ = $(BLAKE2_DIR)/blake2s-ref.o

TARGET = prototype2_client

all: $(TARGET)

$(TARGET): prototype2_client.o noise_crypto.o client.o handshake.o $(BLAKE2_OBJ)
	$(CC) prototype2_client.o noise_crypto.o client.o handshake.o $(BLAKE2_OBJ) -o $(TARGET) -lsodium

prototype2.o: prototype2_client.c noise_crypto.h
	$(CC) $(CFLAGS) -c prototype2_client.c -o prototype2.o

noise_crypto.o: noise_crypto.c noise_crypto.h
	$(CC) $(CFLAGS) -c noise_crypto.c -o noise_crypto.o

client.o: client.c client.h
	$(CC) $(CFLAGS) -c client.c -o client.o

handshake.o: handshake.c
	$(CC) $(CFLAGS) -c handshake.c -o handshake.o
    
check: $(TARGET)
	./$(TARGET)

clean:
	rm -f *.o $(TARGET)