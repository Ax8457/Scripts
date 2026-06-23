// HWU MSc project
/*
* NFSv4 Data-In-Flight Encryption over Noise protocol Framework 
*
* Axel Biegalski
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
#include <stdlib.h>
#include "noise_crypto.h"
#include "server.h"  
#include "handshake.h"

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
    	//printf("[DEBUG] Value of errno: %d\n", errno);
        printf("[OK] Success,named pipe created: %s\n", fifo_path);
    }   
}

//start server 
void start_server(struct noise_peer *peer) {
    //create structs 
    struct ikpsk2_msg1 *m1 = calloc(1, sizeof(struct ikpsk2_msg1));
    struct ikpsk2_msg2 *m2 = calloc(1, sizeof(struct ikpsk2_msg2));
    if (!m1 || !m2) {
        perror("[x] Memory allocation failed");
        free(m1);
        free(m2);
        return;
    }

    //open pipes 
    int fc2s_fd = open("/tmp/" FIFO_C2S, O_RDONLY);    
    int fs2c_fd = open("/tmp/" FIFO_S2C, O_WRONLY);
    
    if (fc2s_fd < 0 || fs2c_fd < 0) {
        printf("[ERROR] Value of errno: %d\n", errno);
        perror("[x] Failed to open pipes");
        free(m1);
        free(m2);
        if (fc2s_fd >= 0) close(fc2s_fd);
        if (fs2c_fd >= 0) close(fs2c_fd);
        return;
    }

    printf("server ready.\n");

    //polling mec
    struct pollfd fds[2];
    fds[0].fd = fc2s_fd; 
    fds[0].events = POLLIN;
    fds[1].fd = 0;       
    fds[1].events = POLLIN;
    //update state 
    peer->handshake.state = HANDSHAKE_ZEROED;

    while(1) {
        if (peer->handshake.state == HANDSHAKE_ZEROED || peer->handshake.state == COMM) {
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

            case HANDSHAKE_ZEROED: {
                if (fds[0].revents & POLLIN) {
                    ssize_t bytes_read = read(fc2s_fd, m1, sizeof(struct ikpsk2_msg1));
                    if (bytes_read <= 0) {
                        perror("[x] Failed to read Message 1 or client disconnected");
                        goto end_loop;
                    }
                    printf("message1 received.\n");
                    handshake_consume_initiation(m1, peer);

                    printf("message1 consumed.\n");
                    printf("state updated.\n");
                    
                    peer->handshake.state = HANDSHAKE_CONSUMED_INITIATION;
                }
                break;
            }

            case HANDSHAKE_CONSUMED_INITIATION: {
                handshake_create_response(m2, peer);

                printf("response created.\n");
                ssize_t bytes_written = write(fs2c_fd, m2, sizeof(struct ikpsk2_msg2));
                if (bytes_written <= 0) {
                    perror("[x] Failed to send Handshake Response (Message 2)");
                    goto end_loop;
                }
                printf("message2 sent to client.\n");

                printf("state updated\n");
                
                peer->handshake.state = HANDSHAKE_CREATED_RESPONSE;
                break;
            }

            case HANDSHAKE_CREATED_RESPONSE: {
                derive_keys(peer->symmetric_keys.sending_key, peer->symmetric_keys.receiving_key, peer->handshake.chaining_key);
                peer->handshake.state = COMM;
                printf("Server > ");
                fflush(stdout);
                break;
            }

            case COMM: {
                if (fds[0].revents & POLLIN) {
                    uint8_t encrypted_packet[1024];
                    ssize_t bytes_read = read(fc2s_fd, encrypted_packet, sizeof(encrypted_packet));
                    if (bytes_read > 0) {
                        uint8_t decrypted_message[1024];
                        uint8_t dummy_hash[NOISE_HASH_LEN] = {0}; 
                        message_decrypt(decrypted_message, encrypted_packet, bytes_read, peer->symmetric_keys.receiving_key, dummy_hash);
                        printf("\n[Client] %s\nServer > ", decrypted_message);
                        fflush(stdout);
                    } else if (bytes_read == 0) {
                        printf("\n[*] Client disconnected.\n");
                        goto end_loop;
                    }
                }

                if (fds[1].revents & POLLIN) {
                    char input_buffer[512];
                    if (fgets(input_buffer, sizeof(input_buffer), stdin) != NULL) {
                        input_buffer[strcspn(input_buffer, "\n")] = 0; 
                        if (strlen(input_buffer) > 0) {
                            uint8_t encrypted_packet[1024];
                            uint8_t dummy_hash[NOISE_HASH_LEN] = {0}; 
                            message_encrypt(encrypted_packet, (uint8_t *)input_buffer, strlen(input_buffer) + 1, peer->symmetric_keys.sending_key, dummy_hash);
                            write(fs2c_fd, encrypted_packet, strlen(input_buffer) + 1 + crypto_aead_chacha20poly1305_ABYTES);
                        }
                        printf("Server > ");
                        fflush(stdout);
                    }
                }
                break;
            }

            default:
                printf("[WARNING] Unexpected state condition (%d)\n", peer->handshake.state);
                goto end_loop;
        }
    }

end_loop:
    free(m1);
    free(m2);
    close(fc2s_fd);
    close(fs2c_fd);
}