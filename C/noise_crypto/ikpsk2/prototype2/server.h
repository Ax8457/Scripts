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

#include <stdint.h>
#include "noise_crypto.h"
/*
	functions
*/
extern void create_named_pipe(const char *fifo_name);
extern void start_server(struct noise_peer *peer);

#endif