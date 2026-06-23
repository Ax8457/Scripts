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
#include "noise_crypto.h"
#include "client.h"
#include "handshake.h"

/*
	Functions
*/
//bind server
void bind_server(struct noise_peer *peer){
	//vars to handle messages
	struct ikpsk2_msg1 *m1 = calloc(1, sizeof(struct ikpsk2_msg1));
	struct ikpsk2_msg2 *m2 = calloc(1, sizeof(struct ikpsk2_msg2));
	//pipes
	int fc2s_fd = open("/tmp/" FIFO_C2S, O_WRONLY);    
	int fs2c_fd = open("/tmp/" FIFO_S2C, O_RDONLY);
	if (fc2s_fd < 0 || fs2c_fd < 0) {
		printf("[ERROR] Value of errno: %d\n", errno);
		perror("[x] Failed to open pipes");
		return;
	}
	
	//polling mec
	struct pollfd fds[2];
	fds[0].fd = fs2c_fd;
	fds[0].events = POLLIN;
	fds[1].fd = 0;
	fds[1].events = POLLIN;

	printf("binding server.\n");

	if (peer->handshake.state == HANDSHAKE_ZEROED){
		//message1
		noise_handshake_create_initiation(m1, &peer->handshake);
		printf("handshake initiation ok.\n");	
		//send message and update state
		if (write(fc2s_fd, m1, sizeof(struct ikpsk2_msg1)) > 0) {
            printf("handshake initiation sent to server.\n");
            peer->handshake.state = HANDSHAKE_CREATED_INITIATION;       
        } else {
            perror("[x] Failed to send handshake initiation");
            free(m1);
            return;
        }		
	}
	//free struct allocated
	free(m1);

	//process handshake
	while(1) {
		if (peer->handshake.state == HANDSHAKE_CREATED_INITIATION || peer->handshake.state == COMM) {
			int nfds = (peer->handshake.state == COMM) ? 2 : 1;
			fds[0].revents = 0;
			fds[1].revents = 0;
			
			int ret = poll(fds, nfds, -1);
			if (ret < 0) {
				printf("[ERROR] Value of errno: %d\n", errno);
				perror("[x] Poll error");
				break;
			}
		}

		switch (peer->handshake.state) {

			case HANDSHAKE_CREATED_INITIATION: {
				if (fds[0].revents & POLLIN) {
					ssize_t bytes_read = read(fs2c_fd, m2, sizeof(struct ikpsk2_msg2));
					if (bytes_read <= 0) {
						perror("[x] Failed to read Message 2 or server disconnected");
						goto end_loop;
					}
					printf("message2 received.\n");

					handshake_consume_response(m2, peer);

					printf("message2 consumed.\n");
					printf("state updated.\n");
					
					peer->handshake.state = HANDSHAKE_CONSUMED_RESPONSE;
				}
				break;
			}

			case HANDSHAKE_CONSUMED_RESPONSE: {
				begin_session(peer);
				peer->handshake.state = COMM;
				printf("Client > ");
				fflush(stdout);
				break;
			}

			case COMM: {
				if (fds[0].revents & POLLIN) {
					uint8_t encrypted_packet[1024];
					ssize_t bytes_read = read(fs2c_fd, encrypted_packet, sizeof(encrypted_packet));
					if (bytes_read > 0) {
						uint8_t decrypted_message[1024];
						uint8_t dummy_hash[NOISE_HASH_LEN] = {0};
						message_decrypt(decrypted_message, encrypted_packet, bytes_read, peer->symmetric_keys.receiving_key, dummy_hash);
						printf("\n[Server] %s\nClient > ", decrypted_message);
						fflush(stdout);
					} else if (bytes_read == 0) {
						printf("\n[*] Server closed the pipe connection.\n");
						goto end_loop;
					}
				}

				if (fds[1].revents & POLLIN) {
					char input_buffer[512];
					if (fgets(input_buffer, sizeof(input_buffer), stdin) != NULL) {
						input_buffer[strcspn(input_buffer, "\n")] = 0;
						if (strlen(input_buffer) > 0) {
							uint8_t encrypted_packet[1024];
							uint8_t dummy_hash2[NOISE_HASH_LEN] = {0};
							message_encrypt(encrypted_packet, (uint8_t *)input_buffer, strlen(input_buffer) + 1, peer->symmetric_keys.sending_key, dummy_hash2);
							write(fc2s_fd, encrypted_packet, strlen(input_buffer) + 1 + crypto_aead_chacha20poly1305_ABYTES);
						}
						printf("Client > ");
						fflush(stdout);
					}
				}
				break;
			}

			default:
				printf("[WARNING] Unexpected packet or state condition (%d)\n", peer->handshake.state);
				goto end_loop;
		}
	}
end_loop:
	close(fc2s_fd);
	close(fs2c_fd);
}



