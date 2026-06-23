#ifndef CLIENT_H
#define CLIENT_H

#define FIFO_C2S "fifo_client_to_server"
#define FIFO_S2C "fifo_server_to_client"

#include <stdint.h>
#include "noise_crypto.h"
/*
	Functions
*/
extern void bind_server(struct noise_peer *peer);

#endif
