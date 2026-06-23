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
	uint8_t => user space
*/
enum noise_lengths {
	NOISE_HASH_LEN = BLAKE2S_HASH_SIZE
};
//noise info
static const uint8_t handshake_name[19] = "test_handshake_name";
static const uint8_t identifier_name[14] = "Axel_Biegalski";
//Chaining key and Hash transcript
extern uint8_t handshake_init_hash[NOISE_HASH_LEN];
extern uint8_t handshake_init_chaining_key[NOISE_HASH_LEN];

/*
	Enums
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

/*
	Structs
*/
//encrypt and decrypt data once the handshake is done 
struct noise_keypair {
	uint8_t sending_key[NOISE_SYMMETRIC_KEY_LEN];
	unsigned char receiving_key[NOISE_SYMMETRIC_KEY_LEN];
};
//static identity
struct noise_static_identity {
	uint8_t static_public[crypto_scalarmult_curve25519_BYTES];
	uint8_t static_private[crypto_scalarmult_curve25519_SCALARBYTES];
};
//noise handshake
struct noise_handshake {
	//handshake state
	enum noise_handshake_state state;
	//handshake infos
	uint8_t hash_transcript[NOISE_HASH_LEN];
	uint8_t chaining_key[NOISE_HASH_LEN];
	//remote identities
	uint8_t remote_static[NOISE_PUBLIC_KEY_LEN];
	uint8_t remote_ephemeral[NOISE_PUBLIC_KEY_LEN];
	//local ephemeral identity
	/*
	* Public ephemeral note stored => scalar mult
	*/
	uint8_t ephemeral_private[NOISE_PUBLIC_KEY_LEN];
	//timestamp message1
	uint8_t latest_timestamp[NOISE_TIMESTAMP_LEN];
	//preshared key => ikpsk2
	uint8_t psk[NOISE_SYMMETRIC_KEY_LEN];
	/* pre computed static
	* dh(S_priv_i, S_pub_r) C3, k2 for initiator and diffie hellman equivalent for responder
	*/
	uint8_t precomputed_static_static[NOISE_PUBLIC_KEY_LEN];
	//static identity
	struct noise_static_identity *static_identity;
	
}; 

struct noise_peer {
	//after handshake => derive keys
	struct noise_keypair symmetric_keys;    
	//handshake data
	struct noise_handshake handshake;
};

//handshake messages
//m1 i -> r
struct ikpsk2_msg1 {
	uint8_t unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];                     
	uint8_t encrypted_static[NOISE_PUBLIC_KEY_LEN + crypto_aead_chacha20poly1305_ABYTES];                 
	uint8_t encrypted_timestamp[NOISE_TIMESTAMP_LEN + crypto_aead_chacha20poly1305_ABYTES]; 
};
//m2 r -> i
struct ikpsk2_msg2 {
	uint8_t ephemeral_public_key[NOISE_PUBLIC_KEY_LEN];                     
	uint8_t encrypted_empty[crypto_aead_chacha20poly1305_ABYTES];
};
//enc data
struct data{
	size_t len;
	uint8_t enc_data[];
};


/*
	Function prototypes 
*/
extern void ikpsk2_noise_init(void);
extern void update_transcript(uint8_t hash[NOISE_HASH_LEN], uint8_t *src, size_t src_len);
extern void init_handshake(uint8_t chaining_key[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN], uint8_t remote_pubkey[NOISE_PUBLIC_KEY_LEN]);
extern void generate_ephemeral_secret(uint8_t ephemeral_private[NOISE_PUBLIC_KEY_LEN]);
extern void generate_public(uint8_t pubkey[NOISE_PUBLIC_KEY_LEN], uint8_t privkey[NOISE_PUBLIC_KEY_LEN]);
extern void message_e(uint8_t dst[NOISE_PUBLIC_KEY_LEN], uint8_t ephemeral_pubkey_initiator[NOISE_PUBLIC_KEY_LEN],uint8_t chaining_key[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN]);
extern void mix_dh(uint8_t chaining_key[NOISE_HASH_LEN], uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t private_key[NOISE_PUBLIC_KEY_LEN], uint8_t public_key[NOISE_PUBLIC_KEY_LEN]);
extern void message_encrypt(uint8_t *dst_ciphertext, uint8_t *src_plaintext, size_t src_len, uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t hash[NOISE_HASH_LEN]);
extern void get_userspace_timestamp(uint8_t output[NOISE_TIMESTAMP_LEN]);

extern void message_decrypt(uint8_t *dst_plaintext, uint8_t *src_ciphertext, size_t src_len, uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t hash[NOISE_HASH_LEN]);
extern void message_ee(uint8_t ephemeral_public[NOISE_PUBLIC_KEY_LEN], uint8_t ephemeral_private[NOISE_PUBLIC_KEY_LEN], uint8_t chaining_key[NOISE_HASH_LEN]);
extern void message_se(uint8_t ephemeral_private_key[NOISE_PUBLIC_KEY_LEN], uint8_t remote_static[NOISE_PUBLIC_KEY_LEN], uint8_t chaining_key[NOISE_HASH_LEN]);
extern void mix_psk(uint8_t psk[NOISE_SYMMETRIC_KEY_LEN], uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t chaining_key[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN]);
extern void derive_keys(uint8_t first_key[NOISE_SYMMETRIC_KEY_LEN], uint8_t second_key[NOISE_SYMMETRIC_KEY_LEN], const uint8_t chaining_key[NOISE_HASH_LEN]);
	
#endif
