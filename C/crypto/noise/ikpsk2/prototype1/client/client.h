#ifndef CLIENT_H
#define CLIENT_H

#define FIFO_C2S "fifo_client_to_server"
#define FIFO_S2C "fifo_server_to_client"

#define CLIENT_SEED "99dac17e610ee4d66c029a60692f12a2007dc01cc1133aa0f88ec6ec32a615fa"
#define SERVER_STATIC_PUBKEY "UBmN+IpBdxvlP1S/NsbxY7EpqFGv5o4jXduMndeW5xw="
#define PSK "9e9c6fa32d24e2153b48a84da15c35cb1447409aeab7129fdad7feddfaecc8ba" 

#include <stdint.h>
#include "noise_crypto.h"
/*
	Functions
*/
extern void read_message_from_server(int fd);
extern void send_message_to_server(int fd, char * message);
extern void bind_server(ikpsk2_msg1 *msg1,  noise_peer *peer);
#endif
