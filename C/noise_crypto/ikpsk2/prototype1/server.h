// HWU MSc project
/*
*	NFSv4 Data-In-Flight Encryption over Noise protocol Framework 
*
*	Axel Biegalski
*/

#ifndef SERVER_H
#define SERVER_H

#define FIFO_C2S "fifo_client_to_server"
#define FIFO_S2C "fifo_server_to_client"

#define SERVER_SEED "a4e53dc2f480b8fce6fe688b1317658b446299df23ad533394406427c8c19557"
#define PSK "9e9c6fa32d24e2153b48a84da15c35cb1447409aeab7129fdad7feddfaecc8ba" 

#include <stdint.h>
#include "noise_crypto.h"
/*
	functions
*/
extern void create_named_pipe(const char *fifo_name);
extern void read_message_from_client(int fd);
extern void start_server(ikpsk2_msg1 *i_m, noise_handshake *handshake, uint8_t *key, noise_peer *noise_peer);
extern void send_message_to_client(int fd, char * message);

#endif
