#ifndef NOISE_CRYPTO_H
#define NOISE_CRYPTO_H

#include <stdint.h>
#include <sodium.h>

#define BLAKE2S_HASH_SIZE 32
#define NOISE_PUBLIC_KEY_LEN 32
#define NOISE_SYMMETRIC_KEY_LEN 32
#define NOISE_TIMESTAMP_LEN 12
/*
	Vars
	u8 => kernel
	uint8_t => user space
*/
//noise infos
enum noise_lengths {
	NOISE_HASH_LEN = BLAKE2S_HASH_SIZE
};
static const uint8_t handshake_name[19] = "test_handshake_name";
static const uint8_t identifier_name[14] = "Axel_Biegalski";
//Chaining key and Hash transcript
extern uint8_t handshake_init_hash[NOISE_HASH_LEN] ;
extern uint8_t handshake_init_chaining_key[NOISE_HASH_LEN];

/*
	Structs
	TODO migrate everything in a dedicated handshake struct gathering identity, remote identity, messages ...
*/
//handshake states
enum noise_handshake_state {
	HANDSHAKE_ZEROED,
	HANDSHAKE_CREATED_INITIATION,
	HANDSHAKE_CONSUMED_INITIATION,
	HANDSHAKE_CREATED_RESPONSE,
	HANDSHAKE_CONSUMED_RESPONSE,
	COMM
};

//handshake struct
typedef struct noise_handshake {
	uint8_t hash_transcript[NOISE_HASH_LEN];
	uint8_t chaining_key[NOISE_HASH_LEN];
	uint8_t remote_static[NOISE_PUBLIC_KEY_LEN];
	uint8_t remote_ephemeral[NOISE_PUBLIC_KEY_LEN];
	enum noise_handshake_state state;
	uint8_t last_timestamp[NOISE_TIMESTAMP_LEN];
	uint8_t psk[NOISE_SYMMETRIC_KEY_LEN];
}noise_handshake; 
//curve25519 keys struct
typedef struct noise_keypair {
	unsigned char public_key[crypto_scalarmult_curve25519_BYTES];
	unsigned char private_key[crypto_scalarmult_curve25519_SCALARBYTES];
}noise_keypair;
//peer struct to store information
typedef struct noise_peer {
	unsigned char seed[crypto_box_SEEDBYTES]; //seed used to generate static keypair deterministically
	noise_keypair *static_keys; //static keys struct
	noise_keypair *ephemeral_keys; //ephemeral keys struct
	unsigned char remote_public_key[crypto_scalarmult_curve25519_BYTES]; //remote pubkey (cf I or K);
	noise_handshake *n_handshake;
	uint8_t last_timestamp[NOISE_TIMESTAMP_LEN];
}noise_peer;
//message1
typedef struct ikpsk2_msg1{
	uint8_t ephemeral_public_key[NOISE_PUBLIC_KEY_LEN];                     
    	uint8_t encrypted_static_key[NOISE_PUBLIC_KEY_LEN + crypto_aead_chacha20poly1305_ABYTES];                 
    	uint8_t encrypted_timestamp[NOISE_TIMESTAMP_LEN + crypto_aead_chacha20poly1305_ABYTES]; 
}ikpsk2_msg1;
//message2
typedef struct ikpsk2_msg2{
	uint8_t ephemeral_public_key[NOISE_PUBLIC_KEY_LEN];                     
    	uint8_t encrypted_empty[crypto_aead_chacha20poly1305_ABYTES];
}ikpsk2_msg2;

/*
	Function prototypes
*/
extern void generate_static_keys(noise_keypair *n_k, noise_peer *n_p);
extern void ikpsk2_noise_init(void);
extern void update_transcript(uint8_t hash[NOISE_HASH_LEN], uint8_t *src, size_t src_len);
extern void init_handshake(uint8_t chaining_key[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN], uint8_t remote_pubkey[NOISE_PUBLIC_KEY_LEN]);
extern void message_e(uint8_t ephemeral_pubkey_initiator[NOISE_PUBLIC_KEY_LEN],uint8_t chaining_key[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN]);
extern void generate_ephemeral_keys(noise_keypair *n_k);
extern void mix_dh(uint8_t chaining_key[NOISE_HASH_LEN], uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t  private_key[NOISE_PUBLIC_KEY_LEN], uint8_t  public_key[NOISE_PUBLIC_KEY_LEN]);
extern void message_encrypt(uint8_t *dst_ciphertext, uint8_t *src_plaintext, size_t src_len, uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t hash[NOISE_HASH_LEN]);
extern void get_userspace_timestamp(uint8_t output[NOISE_TIMESTAMP_LEN]);
extern void message_decrypt(uint8_t *dst_plaintext,uint8_t *src_ciphertext, size_t src_len, uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t hash[NOISE_HASH_LEN]);
extern void message_ee(uint8_t ephemeral_public[NOISE_PUBLIC_KEY_LEN], uint8_t ephemeral_private[NOISE_PUBLIC_KEY_LEN] ,uint8_t chaining_key[NOISE_HASH_LEN]);
extern void message_se(uint8_t ephemeral_private_key[NOISE_PUBLIC_KEY_LEN], uint8_t remote_static[NOISE_PUBLIC_KEY_LEN] ,uint8_t chaining_key[NOISE_HASH_LEN]);
extern void mix_psk(uint8_t psk[NOISE_SYMMETRIC_KEY_LEN], uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t pi[NOISE_SYMMETRIC_KEY_LEN],uint8_t chaining_key[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN]);
extern void derive_keys(uint8_t first_key[NOISE_SYMMETRIC_KEY_LEN], uint8_t second_key[NOISE_SYMMETRIC_KEY_LEN], const uint8_t chaining_key[NOISE_HASH_LEN]);
	
#endif


