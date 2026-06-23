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
#include <string.h>  
#include <errno.h> 
#include "noise_crypto.h"  
#include "server.h"
#include "handshake.h"
//launch server

int main(int argc, char *argv[]){
    if (argc < 2) {
        return 1;
    }

    if (sodium_init() < 0) {
        return 1;
    }

    //create named pipes 
    create_named_pipe(FIFO_C2S);
	create_named_pipe(FIFO_S2C);
    
	//create structs
    struct noise_static_identity *server_identity = calloc(1, sizeof(struct noise_static_identity));
    struct noise_peer *server_peer = calloc(1, sizeof(struct noise_peer));
    server_peer->handshake.static_identity = server_identity;

    //load conf from file 
    load_conf(
        argv[1], 
        server_peer->handshake.static_identity->static_private, 
        server_peer->handshake.remote_static, 
        server_peer->handshake.psk
    );
    printf("conf loaded.\n");
    printf("[DEBUG] Private Key loaded: ");
	for (int i = 0; i < NOISE_PUBLIC_KEY_LEN; i++) {
		printf("%02x", server_peer->handshake.static_identity->static_private[i]);
	}
	printf("\n");
    printf("[DEBUG] Remote Public key loaded: ");
	for (int i = 0; i < NOISE_PUBLIC_KEY_LEN; i++) {
		printf("%02x", server_peer->handshake.remote_static[i]);
	}
	printf("\n");
    printf("[DEBUG] PSK loaded: ");
	for (int i = 0; i < NOISE_SYMMETRIC_KEY_LEN; i++) {
		printf("%02x", server_peer->handshake.psk[i]);
	}
	printf("\n");

	//pubkey from privkey
    crypto_scalarmult_base(
        server_peer->handshake.static_identity->static_public, 
        server_peer->handshake.static_identity->static_private
    );

	//init noise
	/*
		H0, C0
	*/
    ikpsk2_noise_init();
    printf("init ok. \n");
    //set state after init successful
    server_peer->handshake.state = HANDSHAKE_ZEROED;
    printf("init peer state set.\n");
    
	//start server
    start_server(server_peer);

	//free structs
    free(server_peer);
    free(server_identity);
    return 0;
}
