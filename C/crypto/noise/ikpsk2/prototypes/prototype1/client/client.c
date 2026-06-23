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
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include "client.h"
#include "noise_crypto.h"

/*
	Functions
*/
//utilities to send/receive message
void read_message_from_server(int fd){
	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));
	ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1); //read(fc2s_fd, buffer, sizeof(buffer));
	if (bytes_read > 0) { 
		printf("[<==] %s\n",buffer);
	} 
	
	//**** + logic of handshake
};
//send messages through pipe
void send_message_to_server(int fd, char * message){
	write(fd, message, strlen(message));
	printf("[==>] %s\n",message); 
}

//bind server
void bind_server(ikpsk2_msg1 *msg1,  noise_peer *peer){
	//pipes
	int fc2s_fd = open("/tmp/" FIFO_C2S, O_WRONLY);    
	int fs2c_fd = open("/tmp/" FIFO_S2C, O_RDONLY);

	if (fc2s_fd < 0 || fs2c_fd < 0) {
		printf("[ERROR] Value of errno: %d\n", errno);
		perror("[x] Failed to open pipes");
		return;
	}

	// Init state
	enum noise_handshake_state state = HANDSHAKE_ZEROED;

	// message 1 
	if (state == HANDSHAKE_ZEROED) {
		ssize_t bytes_written = write(fc2s_fd, msg1, sizeof(ikpsk2_msg1));
		if (bytes_written == sizeof(ikpsk2_msg1)) {
			printf("[==>] msg1 sent to server (%zd bytes)\n", bytes_written);
			state = HANDSHAKE_CREATED_INITIATION;
			printf("[STATE] State updated to: HANDSHAKE_CREATED_INITIATION\n");
		} else {
			perror("[x] Failed to send complete msg1");
			close(fc2s_fd);
			close(fs2c_fd);
			return;
		}
	}
	
	//polling mec
	struct pollfd fds[2];
	fds[0].fd = fs2c_fd;
	fds[0].events = POLLIN;
	fds[1].fd = 0;
	fds[1].events = POLLIN;

	printf("[*] Client listening for server response (State: %d)...\n", state);
	
	// temp key
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];

	// temps
	uint8_t transport_key_encrypt[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t transport_key_decrypt[NOISE_SYMMETRIC_KEY_LEN];

	//process handshake
	while(1) {
		int nfds = (state == COMM) ? 2 : 1;
		int ret = poll(fds, nfds, -1);
		if (ret < 0) {
			printf("[ERROR] Value of errno: %d\n", errno);
			perror("[x] Poll error");
			break;
		}
		if (fds[0].revents & POLLIN) {
			switch (state) {
				case HANDSHAKE_CREATED_INITIATION: {
					//message2 received from server
					ikpsk2_msg2 i_m2;
					ikpsk2_msg2 *msg2_rec = &i_m2;
					ssize_t bytes_read = read(fs2c_fd, msg2_rec, sizeof(ikpsk2_msg2));
					if (bytes_read == sizeof(ikpsk2_msg2)) {
						printf("[<==] Message 2 received from server (%zd bytes)\n", bytes_read);
						
						// update remote ephemeral
						memcpy(peer->n_handshake->remote_ephemeral, msg2_rec->ephemeral_public_key, NOISE_PUBLIC_KEY_LEN);

						/*
							C4 + H5
						*/
						message_e(peer->n_handshake->remote_ephemeral, peer->n_handshake->chaining_key, peer->n_handshake->hash_transcript);
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

						/*
							ee: C5
						*/
						message_ee(peer->n_handshake->remote_ephemeral, peer->ephemeral_keys->private_key, peer->n_handshake->chaining_key);
						printf("Chaining key updated (C5): ");
						for (int i = 0; i < NOISE_HASH_LEN; i++) {
    							printf("%02x", peer->n_handshake->chaining_key[i]);
						}
						printf("\n");

						/*
							se: C6 (dh(E_priv_i, S_pub_r))
						*/
						message_se(peer->static_keys->private_key, peer->n_handshake->remote_ephemeral, peer->n_handshake->chaining_key);
						printf("Chaining key updated (C6): ");
						for (int i = 0; i < NOISE_HASH_LEN; i++) {
    							printf("%02x", peer->n_handshake->chaining_key[i]);
						}
						printf("\n");

						/*
							es: C7, pi, psk 
						*/
						uint8_t pi[NOISE_SYMMETRIC_KEY_LEN];
						mix_psk(peer->n_handshake->psk, key, pi, peer->n_handshake->chaining_key, peer->n_handshake->hash_transcript);
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

						/*
							Message decryption (empty) + H7
						*/
						uint8_t dec_empty[0]; // empty buff
						message_decrypt(dec_empty, msg2_rec->encrypted_empty, crypto_aead_chacha20poly1305_ABYTES, key, peer->n_handshake->hash_transcript);
						printf("Hash Transcript updated (H7): ");
						for (int i = 0; i < NOISE_HASH_LEN; i++) {
    							printf("%02x", peer->n_handshake->hash_transcript[i]);
						}
						printf("\n");

						/*
							Derive Transport Keys
						*/
						derive_keys(transport_key_encrypt, transport_key_decrypt, peer->n_handshake->chaining_key);
						
						// Debug
						printf("Transport Encryption Key derived: ");
						for (int i = 0; i < NOISE_SYMMETRIC_KEY_LEN; i++) {
    							printf("%02x", transport_key_encrypt[i]);
						}
						printf("\n");
						printf("Transport Decryption Key derived: ");
						for (int i = 0; i < NOISE_SYMMETRIC_KEY_LEN; i++) {
    							printf("%02x", transport_key_decrypt[i]);
						}
						printf("\n");
						//update state
						state = COMM; 
						printf("[STATE] State updated to: COMM\n");
						printf("Client > ");
						fflush(stdout);
						
					} else if (bytes_read == 0) {
						printf("[*] Server closed the pipe connection.\n");
						break;
					} else {
						printf("[WARNING] Incomplete read from FIFO_S2C\n");
					}
					break;
				}

				case COMM: {
					uint8_t encrypted_packet[1024];
					ssize_t bytes_read = read(fs2c_fd, encrypted_packet, sizeof(encrypted_packet));
					if (bytes_read > 0) {
						uint8_t decrypted_message[1024];
						uint8_t dummy_hash[NOISE_HASH_LEN] = {0};
						message_decrypt(decrypted_message, encrypted_packet, bytes_read, transport_key_decrypt, dummy_hash);
						printf("\n[Serveur] %s\nClient > ", decrypted_message);
						fflush(stdout);
					} else if (bytes_read == 0) {
						printf("\n[*] Server closed the pipe connection.\n");
						goto end_loop;
					}
					break;
				}

				default:
					printf("[WARNING] Unexpected packet or state condition (%d)\n", state);
					break;
			}
		}

		if (state == COMM && (fds[1].revents & POLLIN)) {
			char input_buffer[512];
			if (fgets(input_buffer, sizeof(input_buffer), stdin) != NULL) {
				input_buffer[strcspn(input_buffer, "\n")] = 0;
				if (strlen(input_buffer) > 0) {
					uint8_t encrypted_packet[1024];
					uint8_t dummy_hash2[NOISE_HASH_LEN] = {0};
					message_encrypt(encrypted_packet, (uint8_t *)input_buffer, strlen(input_buffer) + 1, transport_key_encrypt, dummy_hash2);
					write(fc2s_fd, encrypted_packet, strlen(input_buffer) + 1 + crypto_aead_chacha20poly1305_ABYTES);
				}
				printf("Client > ");
				fflush(stdout);
			}
		}
	}
end_loop:
	close(fc2s_fd);
	close(fs2c_fd);
}


