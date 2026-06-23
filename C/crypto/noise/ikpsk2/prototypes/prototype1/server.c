// HWU MSc project
/*
*	NFSv4 Data-In-Flight Encryption over Noise protocol Framework 
*
*	Axel Biegalski
*/

/*
	Libs
*/
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include "server.h"
#include "noise_crypto.h"
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <string.h>

/*
	Functions
*/
//Create two pipes <=> biderectional comm 
//1 pipe client to server (read only for server process and read + write for client process
//1 pipe server to client (same but conversely)
void create_named_pipe(const char *fifo_name)
{    
    char fifo_path[128];
    snprintf(fifo_path, sizeof(fifo_path), "/tmp/%s", fifo_name);
    if (mkfifo(fifo_path, 0666) < 0){
    	printf("[ERROR] Value of errno: %d\n", errno);
        perror("[x] Failed to create named pipe");
    }
    else{
    	printf("[DEBUG] Value of errno: %d\n", errno);
        printf("[OK] Success,named pipe created: %s\n", fifo_path);
    }   
}
//utilities to send/receive message
void read_message_from_client(int fd){
	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));
	ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1); //read(fc2s_fd, buffer, sizeof(buffer));
	if (bytes_read > 0) { 
		printf("[<==] %s\n",buffer);
	} 
	
	//**** + logic of handshake
};
void send_message_to_client(int fd, char * message){
	write(fd, message, strlen(message));
	printf("[==>] %s\n",message); 
}

/*
	TODO modify signature to take only peer struct as parameter
*/
//launch server
void start_server(ikpsk2_msg1 *i_m, noise_handshake *handshake, uint8_t *key, noise_peer *peer){
	int fc2s_fd = open("/tmp/" FIFO_C2S, O_RDONLY);  
	int fs2c_fd = open("/tmp/" FIFO_S2C, O_WRONLY);

	if (fc2s_fd < 0 || fs2c_fd < 0) {
		printf("[ERROR] Value of errno: %d\n", errno);
		perror("[x] Failed to open pipes");
		return;
	}

	// Configuration du poll pour inclure le pipe et l'entrée clavier (stdin = 0)
	struct pollfd fds[2];
	fds[0].fd = fc2s_fd;
	fds[0].events = POLLIN;
	fds[1].fd = 0;
	fds[1].events = POLLIN;

	// Clés déclarées ici pour être persistantes pendant toute la phase COMM
	uint8_t transport_key_encrypt[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t transport_key_decrypt[NOISE_SYMMETRIC_KEY_LEN];

	printf("[*] Server listening (State: %d)...\n", handshake->state);
	while(1) {
		// nfds = 1 pendant le handshake (uniquement le pipe), nfds = 2 en mode COMM (pipe + clavier)
		int nfds = (handshake->state == COMM) ? 2 : 1;
		int ret = poll(fds, nfds, -1);
		if (ret < 0) {
			printf("[ERROR] Value of errno: %d\n", errno);
			perror("[x] Poll error");
			break;
		}

		// Gestion des messages reçus sur le Pipe (Client -> Serveur)
		if (fds[0].revents & POLLIN) {
			switch (handshake->state) {
				case HANDSHAKE_ZEROED: {
					//init + first message from client
					ikpsk2_msg1 i_m1;
					ikpsk2_msg1 *msg1_rec = &i_m1;
					ssize_t bytes_read = read(fc2s_fd, msg1_rec, sizeof(ikpsk2_msg1));
					if (bytes_read == sizeof(ikpsk2_msg1)) {
						printf("[<==] Message 1 received from client (%zd bytes)\n", bytes_read);
						//copy to msg1 struct /!\ temp, by the end everthing in a dedicated handshake struct
						memcpy(i_m->ephemeral_public_key, msg1_rec->ephemeral_public_key, NOISE_PUBLIC_KEY_LEN);
						memcpy(i_m->encrypted_static_key, msg1_rec->encrypted_static_key, NOISE_PUBLIC_KEY_LEN + crypto_aead_chacha20poly1305_ABYTES);
						memcpy(i_m->encrypted_timestamp, msg1_rec->encrypted_timestamp, NOISE_TIMESTAMP_LEN + crypto_aead_chacha20poly1305_ABYTES);
						//DEBUG
						printf("Received Ephemeral Pub Key from client (E_Pub_I) : ");
						for (int i = 0; i < NOISE_PUBLIC_KEY_LEN; i++) {
    							printf("%02x", i_m->ephemeral_public_key[i]);
						}
						printf("\n");
						printf("Received Encrypted Static Pub Key from client (S_Pub_I_enc) : ");
						for (int i = 0; i < NOISE_PUBLIC_KEY_LEN + crypto_aead_chacha20poly1305_ABYTES; i++) {
    							printf("%02x", i_m->encrypted_static_key[i]);
						}
						printf("\n");
						printf("Received Encrypted Timestamp from client (Timestamp_I_enc) : ");
						for (int i = 0; i < NOISE_TIMESTAMP_LEN + + crypto_aead_chacha20poly1305_ABYTES; i++) {
    							printf("%02x", i_m->encrypted_timestamp[i]);
						}
						printf("\n");
						//DEBUG 
						//update
						handshake->state = HANDSHAKE_CONSUMED_INITIATION;
						memcpy(handshake->remote_ephemeral, msg1_rec->ephemeral_public_key, NOISE_PUBLIC_KEY_LEN);
						printf("[STATE] State updated to: HANDSHAKE_CONSUMED_INITIATION\n");
						
					} else if (bytes_read == 0) {
						goto end_loop;
					}
				}
				case HANDSHAKE_CONSUMED_INITIATION:
					//message 2
					printf("[*] Message 1 consumed. Building response...\n");
					/*
						C1 + H2
					*/
					message_e(handshake->remote_ephemeral, handshake->chaining_key, handshake->hash_transcript);
					//DEBUG
					printf("Chaining key updated (C1): ");
					for (int i = 0; i < NOISE_HASH_LEN; i++) {
    						printf("%02x", handshake->chaining_key[i]);
					}
					printf("\n");
					printf("Hash Transcript updated (H2): ");
					for (int i = 0; i < NOISE_HASH_LEN; i++) {
    						printf("%02x", handshake->hash_transcript[i]);
					}
					printf("\n");
					//DEBUG
					
					/*
						C2 + K1
					*/
					mix_dh(handshake->chaining_key, key, peer->static_keys->private_key, handshake->remote_ephemeral);
					//DEBUG
					printf("Chaining key updated (C2): ");
					for (int i = 0; i < NOISE_HASH_LEN; i++) {
    						printf("%02x", handshake->chaining_key[i]);
					}
					printf("\n");
					printf("Key (K1): ");
					for (int i = 0; i < NOISE_SYMMETRIC_KEY_LEN; i++) {
    						printf("%02x", key[i]);
					}
					printf("\n");
					//DEBUG
					
					/*
						dec_S_PUB + H3					
					*/
					uint8_t dec_pubkey[NOISE_PUBLIC_KEY_LEN];
					message_decrypt(dec_pubkey, i_m->encrypted_static_key, NOISE_PUBLIC_KEY_LEN + crypto_aead_chacha20poly1305_ABYTES, key, handshake->hash_transcript);
					printf("Hash Transcript updated (H3): ");
					for (int i = 0; i < NOISE_HASH_LEN; i++) {
    						printf("%02x", handshake->hash_transcript[i]);
					}
					printf("\n");
					//update noise struct with remote pubkey (static)
					memcpy(peer->remote_public_key, dec_pubkey,NOISE_PUBLIC_KEY_LEN);
					/*
						C3 + K2
					*/
					mix_dh(peer->n_handshake->chaining_key, key, peer->static_keys->private_key, peer->remote_public_key);
					//DEBUG
					printf("Chaining key updated (C3): ");
					for (int i = 0; i < NOISE_HASH_LEN; i++) {
    						printf("%02x",peer->n_handshake->chaining_key[i]);
					}
					printf("\n");
					printf("Key (K2): ");
					for (int i = 0; i < NOISE_SYMMETRIC_KEY_LEN; i++) {
    						printf("%02x", key[i]);
					}
					printf("\n");
					//DEBUG
					
					/*
						dec_timestamp + H4
					*/
					uint8_t dec_timestamp[NOISE_TIMESTAMP_LEN];
					message_decrypt(dec_timestamp, i_m->encrypted_timestamp, NOISE_TIMESTAMP_LEN + crypto_aead_chacha20poly1305_ABYTES, key, handshake->hash_transcript);
					printf("Hash Transcript updated (H4): ");
					for (int i = 0; i < NOISE_HASH_LEN; i++) {
    						printf("%02x", peer->n_handshake->hash_transcript[i]);
					}
					printf("\n");
					//update ts
					memcpy(peer->n_handshake->last_timestamp, dec_timestamp,NOISE_TIMESTAMP_LEN); //keep track of ts
					//update state 
					handshake->state = HANDSHAKE_CREATED_RESPONSE;
					
					/*
						C4 + H5		
					*/
					message_e(peer->ephemeral_keys->public_key, peer->n_handshake->chaining_key, peer->n_handshake->hash_transcript);
					//DEBUG
					printf("Chaining key updated (C4): ");
					for (int i = 0; i < NOISE_HASH_LEN; i++) {
    						printf("%02x", peer->n_handshake->chaining_key[i]);
					}
					printf("\n");
					printf("Hash Transcript updated (H5): ");
					for (int i = 0; i < NOISE_HASH_LEN; i++) {
    						printf("%02x", peer->n_handshake->hash_transcript[i]);
					}
					printf("\n");
					//DEBUG
					/*
						ee: C5 
					*/
					message_ee(peer->n_handshake->remote_ephemeral, peer->ephemeral_keys->private_key, peer->n_handshake->chaining_key);
					//DEBUG
					printf("Chaining key updated (C5): ");
					for (int i = 0; i < NOISE_HASH_LEN; i++) {
    						printf("%02x", peer->n_handshake->chaining_key[i]);
					}
					printf("\n");
					//DEBUG
					
					/*
						se: C6
					*/
					message_se(peer->ephemeral_keys->private_key, peer->remote_public_key, peer->n_handshake->chaining_key);
					//DEBUG
					printf("Chaining key updated (C6): ");
					for (int i = 0; i < NOISE_HASH_LEN; i++) {
    						printf("%02x", peer->n_handshake->chaining_key[i]);
					}
					printf("\n");
					//DEBUG
					
					/*
						es: C7, pi, psk
					*/
					uint8_t pi[NOISE_SYMMETRIC_KEY_LEN];
					mix_psk(peer->n_handshake->psk, key, pi, peer->n_handshake->chaining_key, peer->n_handshake->hash_transcript);
					//DEBUG
					printf("Chaining key updated (C7): ");
					for (int i = 0; i < NOISE_HASH_LEN; i++) {
    						printf("%02x", peer->n_handshake->chaining_key[i]);
					}
					printf("\n");
					printf("Hash Transcript updated (H6): ");
					for (int i = 0; i < NOISE_HASH_LEN; i++) {
    						printf("%02x", peer->n_handshake->hash_transcript[i]);
					}
					printf("\n");
					//DEBUG
					
					/*
						Message encryption (empty) + H7 
					*/
					uint8_t encrypted_empty[crypto_aead_chacha20poly1305_ABYTES];
					message_encrypt(encrypted_empty, (uint8_t *)"", 0, key, peer->n_handshake->hash_transcript);
					printf("Encrypted timestamp : ");
					for (int i = 0; i < (crypto_aead_chacha20poly1305_ABYTES); i++) {
    						printf("%02x", encrypted_empty[i]);
					}
					printf("\n");
					printf("Hash Transcript updated (H7): ");
					for (int i = 0; i < NOISE_HASH_LEN; i++) {
    						printf("%02x", peer->n_handshake->hash_transcript[i]);
					}
					printf("\n");
					/*
						Send message to client
					*/
					ikpsk2_msg2 i_m2;
					ikpsk2_msg2 *ikpsk2_m2 = &i_m2;
					memcpy(ikpsk2_m2->ephemeral_public_key, peer->ephemeral_keys->public_key, NOISE_PUBLIC_KEY_LEN);
					memcpy(ikpsk2_m2->encrypted_empty, encrypted_empty, crypto_aead_chacha20poly1305_ABYTES);
					//send msg2
					ssize_t bytes_written = write(fs2c_fd, ikpsk2_m2, sizeof(ikpsk2_msg2));
					if (bytes_written < 0) {
						printf("[ERROR] Value of errno: %d\n", errno);
						perror("[x] Failed to send MSG2 through pipe");
					} else if (bytes_written != sizeof(ikpsk2_msg2)) {
						printf("[WARNING] Incomplete write to FIFO_S2C (%zd bytes written instead of %zu)\n", 
							bytes_written, sizeof(ikpsk2_msg2));
					} else {
						printf("[==>] Message 2 sent to client (%zd bytes)\n", bytes_written);
						
						derive_keys(transport_key_decrypt, transport_key_encrypt, peer->n_handshake->chaining_key);
						
						printf("[*] Server Transport Encryption Key derived: ");
						for (int i = 0; i < NOISE_SYMMETRIC_KEY_LEN; i++) {
								printf("%02x", transport_key_encrypt[i]);
						}
						printf("\n");
						printf("[*] Server Transport Decryption Key derived: ");
						for (int i = 0; i < NOISE_SYMMETRIC_KEY_LEN; i++) {
								printf("%02x", transport_key_decrypt[i]);
						}
						printf("\n");
						
						sodium_memzero(key, NOISE_SYMMETRIC_KEY_LEN);
					}

					// update state to communication state 
					handshake->state = COMM;
					printf("[STATE] State updated to: COMM\n");
					printf("Serveur > ");
					fflush(stdout);
					break;
					
				case COMM: {
					//decrypt packet
					uint8_t encrypted_packet[1024];
					ssize_t bytes_read = read(fc2s_fd, encrypted_packet, sizeof(encrypted_packet));
					printf("\n[DEBUG] Cipher : ", bytes_read);
        				for (ssize_t i = 0; i < bytes_read; i++) {
            					printf("%c", encrypted_packet[i]);
        				}
        				printf("\n");
					if (bytes_read > 0) {
						uint8_t decrypted_message[1024];
						uint8_t dummy_hash[NOISE_HASH_LEN] = {0}; // Buffer de 32 octets vide
						message_decrypt(decrypted_message, encrypted_packet, bytes_read, transport_key_decrypt, dummy_hash);
						printf("\n[Client] %s\nServeur > ", decrypted_message);
						fflush(stdout);
					} else if (bytes_read == 0) {
						printf("\n[*] Client déconnecté.\n");
						goto end_loop;
					}
					break;
				}
					
				case HANDSHAKE_CREATED_RESPONSE:	
					
				default://default
					printf("[WARNING] Unexpected packet received for current state (%d)\n", handshake->state);
					break;
			}
		}

		// communication
		if (handshake->state == COMM && (fds[1].revents & POLLIN)) {
			char input_buffer[512];
			if (fgets(input_buffer, sizeof(input_buffer), stdin) != NULL) {
				input_buffer[strcspn(input_buffer, "\n")] = 0; 
				if (strlen(input_buffer) > 0) {
					uint8_t encrypted_packet[1024];
					uint8_t dummy_hash[NOISE_HASH_LEN] = {0}; 
					//encrypt message
					message_encrypt(encrypted_packet, (uint8_t *)input_buffer, strlen(input_buffer) + 1, transport_key_encrypt, dummy_hash);
					//write pipe
					write(fs2c_fd, encrypted_packet, strlen(input_buffer) + 1 + crypto_aead_chacha20poly1305_ABYTES);
				}
				printf("Serveur > ");
				fflush(stdout);
			}
		}
	}

end_loop:
	close(fc2s_fd);
	close(fs2c_fd);
}
