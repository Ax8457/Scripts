// HWU MSc project
/*
*	NFSv4 Data-In-Flight Encryption over Noise protocol Framework 
*
*	Axel Biegalski
*/

/*
	Libs
*/
#include "noise_crypto.h"
#include "server.h"
#include <errno.h>

/*
	MAIN
*/
int main(int argc, char *argv[]) {
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	//DEBUG
	//create client server model with pipes
	create_named_pipe(FIFO_C2S);
	create_named_pipe(FIFO_S2C);
	//DEBUG
	//init libsodium
	if (sodium_init() < 0) {
		printf("[ERROR] Value of errno: %d\n", errno);
        	perror("[x] Failed to initiate libsodium");
        	/* panic! the library couldn't be initialized; it is not safe to use */
    	}
    	//create and complete peer structs
    	noise_peer peer;
    	noise_keypair k1;
    	noise_keypair k2;
    	noise_handshake n_h;
    	noise_peer *server_peer = &peer;
    	noise_keypair *n_static_k = &k1 ; 
    	noise_keypair *n_ephemeral_k = &k2;
    	server_peer->n_handshake = &n_h;
    	server_peer->n_handshake->state = HANDSHAKE_ZEROED;
    	generate_ephemeral_keys(n_ephemeral_k); //cf crypto : random keys => in RAM  (no seed)
    	server_peer->static_keys = n_static_k;
    	server_peer->ephemeral_keys = n_ephemeral_k;
    	ikpsk2_msg1 i_m1;
    	ikpsk2_msg1 *ikpsk2_m1_received = &i_m1;
    	//seed
    	sodium_hex2bin(
    		server_peer->seed,
    		crypto_box_SEEDBYTES,
    		SERVER_SEED,
    		64,
    		NULL,
    		NULL, 
    		NULL);
    	//psk
    	sodium_hex2bin(
    		server_peer->n_handshake->psk,
    		NOISE_SYMMETRIC_KEY_LEN,
    		PSK,
    		64,
    		NULL,
    		NULL, 
    		NULL);
    	//generate key pair
    	generate_static_keys(n_static_k, server_peer);
    	server_peer->static_keys = n_static_k;
    	
/*
	Handshake init: C0, H0, H1
	C0 = hash(handshake_name)  **arbitrary notation
	H0 = hash(C0,identifier_name)  **arbitrary notation
	H1 = hash(H0, Static Initiator Pubkey S_pub_i)
*/
	ikpsk2_noise_init();
	printf("Init ok\n");
	
	size_t b64_size = sodium_base64_ENCODED_LEN(crypto_box_PUBLICKEYBYTES, sodium_base64_VARIANT_ORIGINAL);
	char b64_buffer[b64_size];
	sodium_bin2base64(
		b64_buffer, 
		b64_size, 
		server_peer->static_keys->public_key, 
		crypto_box_PUBLICKEYBYTES, 
		sodium_base64_VARIANT_ORIGINAL
	);
	printf("Server Pubkey (base64): %s\n",b64_buffer);
	//DEBUG
	printf("Chaining Key (C0): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    		printf("%02x", handshake_init_chaining_key[i]);
	}
	printf("\n");
	printf("Hash Transcript (H0): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    		printf("%02x", handshake_init_hash[i]);
	}
	printf("\n");
	//DEBUG
	
	init_handshake(server_peer->n_handshake->chaining_key, server_peer->n_handshake->hash_transcript,server_peer->static_keys->public_key);
	printf("Hash Transcript updated (H1): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    		printf("%02x", server_peer->n_handshake->hash_transcript[i]);
	}
	printf("\n");
	//start server
	start_server(ikpsk2_m1_received,server_peer->n_handshake, key, server_peer);
	
	
	return 0;
}
