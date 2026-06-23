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
#include "client.h"
#include "handshake.h"
//launch server

int main(int argc, char *argv[]){
    if (argc < 2) {
        return 1;
    }

    if (sodium_init() < 0) {
        return 1;
    }
    
	//create structs
    struct noise_static_identity *client_identity = calloc(1, sizeof(struct noise_static_identity));
    struct noise_peer *client_peer = calloc(1, sizeof(struct noise_peer));
    client_peer->handshake.static_identity = client_identity;

    //load conf from file 
    load_conf(
        argv[1], 
        client_peer->handshake.static_identity->static_private, 
        client_peer->handshake.remote_static, 
        client_peer->handshake.psk
    );
    printf("conf loaded.\n");
    printf("[DEBUG] Private Key loaded: ");
	for (int i = 0; i < NOISE_PUBLIC_KEY_LEN; i++) {
		printf("%02x", client_peer->handshake.static_identity->static_private[i]);
	}
	printf("\n");
    printf("[DEBUG] Remote Public key loaded: ");
	for (int i = 0; i < NOISE_PUBLIC_KEY_LEN; i++) {
		printf("%02x", client_peer->handshake.remote_static[i]);
	}
	printf("\n");
    printf("[DEBUG] PSK loaded: ");
	for (int i = 0; i < NOISE_SYMMETRIC_KEY_LEN; i++) {
		printf("%02x", client_peer->handshake.psk[i]);
	}
	printf("\n");

	//pubkey from privkey
    crypto_scalarmult_base(
        client_peer->handshake.static_identity->static_public, 
        client_peer->handshake.static_identity->static_private
    );

	//init noise
	/*
		H0, C0
	*/
    ikpsk2_noise_init();
    printf("init ok. \n");
    //set state after init successful
    client_peer->handshake.state = HANDSHAKE_ZEROED;
    printf("init peer state set.\n");
    
	//bind server
    bind_server(client_peer);

	//free structs
    free(client_peer);
    free(client_identity);
    return 0;
}
