// HWU MSc project
/*
*	NFSv4 Data-In-Flight Encryption over Noise protocol Framework 
*
*	Axel Biegalski
*/

/*
	Libs
*/
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "blake2.h"
#include <sodium.h> //libsodium => need installation
#include <inttypes.h>
#include <errno.h>
#include "noise_crypto.h"
#include <endian.h>
#include <time.h>

//vars 
uint8_t handshake_init_hash[NOISE_HASH_LEN];
uint8_t handshake_init_chaining_key[NOISE_HASH_LEN];
/*
	Generate keypairs (x25519) with libsodium 
*/
void generate_ephemeral_secret(uint8_t ephemeral_private[NOISE_PUBLIC_KEY_LEN]){
	// /!\ Error handling
	randombytes_buf(ephemeral_private, NOISE_PUBLIC_KEY_LEN);
}
void generate_public(uint8_t pubkey[NOISE_PUBLIC_KEY_LEN], uint8_t privkey[NOISE_PUBLIC_KEY_LEN]){
	if (crypto_scalarmult_base(pubkey, privkey) < 0){
		perror("[x]error dh pubkey computation \n");
	}
}
/*
	Set static identity
*/
void set_static_identity(struct noise_static_identity *static_identity, const uint8_t private_key[NOISE_PUBLIC_KEY_LEN])
{
	memcpy(static_identity->static_private, private_key, NOISE_PUBLIC_KEY_LEN);
	//complete
}

/*
	Init function
*/
void ikpsk2_noise_init(void)
{
	/*
		handshake_init_chaining_key = C0
		handshake_init_hash = H0
	*/
	blake2s_state blake;
	if (blake2s(handshake_init_chaining_key, NOISE_HASH_LEN, handshake_name, 19, NULL, 0) < 0) {
    		perror("[x]C0 init error \n");
	}
	// /!\ order of parameters is different in user space blake2s(NULL, 0, handshake_name, sizeof(handshake_name),handshake_init_chaining_key, NOISE_HASH_LEN); 
		
	//DEBUG
	printf("[DEBUG] Handshake name (seed): ");
	for (int i = 0; i < sizeof(handshake_name); i++) {
    		printf("%02x", handshake_name[i]);
	}
	printf("\n");
	printf("[DEBUG] identifier name (seed): ");
	for (int i = 0; i < sizeof(identifier_name); i++) {
    		printf("%02x", identifier_name[i]);
	}
	printf("\n");
	//DEBUG
	
	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, handshake_init_chaining_key, NOISE_HASH_LEN);
	blake2s_update(&blake, identifier_name, sizeof(identifier_name));
	blake2s_final(&blake, handshake_init_hash, NOISE_HASH_LEN);
}

/*
	Update Hash Transcript
*/
//update hash transcript
void update_transcript(uint8_t hash[NOISE_HASH_LEN], uint8_t *src, size_t src_len)
{
	blake2s_state blake;
	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, hash, NOISE_HASH_LEN);
	blake2s_update(&blake, src, src_len);
	blake2s_final(&blake, hash, NOISE_HASH_LEN);
}

/*
	Handshake Init function
	H1 = Hash(H0, Remote Serve Pubkey (Static))
*/
void init_handshake(uint8_t chaining_key[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN], uint8_t remote_pubkey[NOISE_PUBLIC_KEY_LEN])
{
	memcpy(hash, handshake_init_hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake_init_chaining_key, NOISE_HASH_LEN); //update hanshake struct in client peer struct
	update_transcript(hash, remote_pubkey, NOISE_PUBLIC_KEY_LEN);
}

/*
	Message1 : e, es ,s ,ss 
	e:
		C1 = hkdf(C0, Ephemeral pub initiator)
		H2 = hash(H1, Ephermeral pub initiator)
		
	/!\ HKDF : only one expansion
*/
//e
void message_e(uint8_t dst[NOISE_PUBLIC_KEY_LEN], uint8_t ephemeral_pubkey_initiator[NOISE_PUBLIC_KEY_LEN],uint8_t chaining_key[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN]){
	
	if (ephemeral_pubkey_initiator != dst){
		memcpy(dst,ephemeral_pubkey_initiator, NOISE_PUBLIC_KEY_LEN);
	}
	//C1
	unsigned char prk[crypto_kdf_hkdf_sha256_KEYBYTES];
	//HKDF extract
	crypto_kdf_hkdf_sha256_extract(
		prk, 
		chaining_key, 
		NOISE_HASH_LEN,              
		dst, 
		NOISE_PUBLIC_KEY_LEN
	);
	//HKDF expand
	crypto_kdf_hkdf_sha256_expand(
		chaining_key, 	//C0 -> C1	
		NOISE_HASH_LEN, 
		"NFSv4_noise_C1", 
		14,                        
		prk                           
	);	
	update_transcript(hash, dst, NOISE_PUBLIC_KEY_LEN); //H2
}

/*
	Diffie Hellman shared secret mixing function
	C2 || K1 = hkdf(C1, dh(Ephemeral public initiator, Ephemeral private initiator)) 
*/
//es
void mix_dh(uint8_t chaining_key[NOISE_HASH_LEN], uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t  private_key[NOISE_PUBLIC_KEY_LEN], uint8_t  public_key[NOISE_PUBLIC_KEY_LEN])
{
	uint8_t dh_calculation[NOISE_PUBLIC_KEY_LEN];
	uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
	//diffie hellman share secret
	if (crypto_scalarmult(dh_calculation, private_key, public_key) < 0){
		printf("[ERROR] Value of errno: %d\n", errno);
        	perror("[x] Failed DH computation");
	}
	//extract
	crypto_kdf_hkdf_sha256_extract(
		prk, 
		chaining_key, 
		NOISE_HASH_LEN,             
		dh_calculation, 
		NOISE_PUBLIC_KEY_LEN
	);
	//first expand
	crypto_kdf_hkdf_sha256_expand(
		chaining_key, //C1 -> C2
		NOISE_HASH_LEN, 
		"NFSv4_noise_Ci", 
		14, 
		prk                           
	);
	//Second expand
	crypto_kdf_hkdf_sha256_expand(
		key, //key in ram K1
		NOISE_SYMMETRIC_KEY_LEN, 
		"NFSv4_noise_Ki", 
		14, 
		prk                           
	);
}

/* 
	Encryption function
	Static public initiator enc + H3
	H3 = hash(H2, Spubinitenc)
*/
//s
//client side
void message_encrypt(uint8_t *dst_ciphertext, uint8_t *src_plaintext, size_t src_len, uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t hash[NOISE_HASH_LEN])
{
	uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES] = { 0 }; //first message nonce init is 0
	unsigned long long ciphertext_len;
	//libsodium function 
	crypto_aead_chacha20poly1305_ietf_encrypt(
		dst_ciphertext, &ciphertext_len,
		src_plaintext, src_len,          
		hash, NOISE_HASH_LEN,            
		NULL,                            
		nonce,                           
		key                              // key
	);	
	update_transcript(hash, dst_ciphertext, ciphertext_len); //H3 or H4 or H7 depending step of the message 
}
//server side
void message_decrypt(uint8_t *dst_plaintext, uint8_t *src_ciphertext, size_t src_len, uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t hash[NOISE_HASH_LEN])
{
	uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES] = { 0 }; //first message nonce init is 0
	unsigned long long plaintext_len;
	//libsodium function 
	if (crypto_aead_chacha20poly1305_ietf_decrypt(
		dst_plaintext, &plaintext_len,
		NULL,
		src_ciphertext, src_len,          
		hash, NOISE_HASH_LEN,            
		nonce,                           
		key                              // key
	)< 0) {
		printf("[ERROR] Value of errno: %d\n", errno);
        	perror("[x] Failed to decrypt message");
	} 
	update_transcript(hash, src_ciphertext, src_len); //H3
}

/*
	12-bytes timestamp TAI64N equivalent 
*/
void get_userspace_timestamp(uint8_t output[NOISE_TIMESTAMP_LEN])
{
    struct timespec now;
    //clear buffer
    memset(output, 0, NOISE_TIMESTAMP_LEN);
    //now.tvsec => seconde, nsec => nano sec
    clock_gettime(CLOCK_REALTIME, &now);
    //bigendian
    uint64_t be_sec = htobe64((uint64_t)now.tv_sec);
    uint32_t be_nsec = htobe32((uint32_t)now.tv_nsec);
    //8 bytes => secondes
    memcpy(output, &be_sec, 8);
    // 4 bytes => nsec ==> 12 bytes
    memcpy(output + 8, &be_nsec, 4);
}

/*
	Message 2: e, ee, se, psk
*/
//e
//same function as message1
//ee
void message_ee(uint8_t ephemeral_public[NOISE_PUBLIC_KEY_LEN], uint8_t ephemeral_private[NOISE_PUBLIC_KEY_LEN] ,uint8_t chaining_key[NOISE_HASH_LEN]){
	//C5
	uint8_t dh_calculation[NOISE_PUBLIC_KEY_LEN];
	//diffie hellman share secret
	if (crypto_scalarmult(dh_calculation, ephemeral_private, ephemeral_public) < 0){
		printf("[ERROR] Value of errno: %d\n", errno);
        	perror("[x] Failed DH computation");
	}
	//HKDF extract
	crypto_kdf_hkdf_sha256_extract(
		prk, 
		chaining_key, 
		NOISE_HASH_LEN,              
		dh_calculation, 
		NOISE_PUBLIC_KEY_LEN
	);
	//HKDF expand
	crypto_kdf_hkdf_sha256_expand(
		chaining_key, 	//C4 -> C5	
		NOISE_HASH_LEN, 
		"NFSv4_noise_C5", 
		14,                        
		prk                           
	);	
	
}
//se
void message_se(uint8_t ephemeral_private_key[NOISE_PUBLIC_KEY_LEN], uint8_t remote_static[NOISE_PUBLIC_KEY_LEN] ,uint8_t chaining_key[NOISE_HASH_LEN]){
	//C1
	uint8_t dh_calculation[NOISE_PUBLIC_KEY_LEN];
	uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
	//diffie hellman share secret
	if (crypto_scalarmult(dh_calculation, ephemeral_private_key, remote_static) < 0){
		printf("[ERROR] Value of errno: %d\n", errno);
        perror("[x] Failed DH computation");
	}
	//HKDF extract
	crypto_kdf_hkdf_sha256_extract(
		prk, 
		chaining_key, 
		NOISE_HASH_LEN,              
		dh_calculation, 
		NOISE_PUBLIC_KEY_LEN
	);
	//HKDF expand
	crypto_kdf_hkdf_sha256_expand(
		chaining_key, 	//C5 -> C6	
		NOISE_HASH_LEN, 
		"NFSv4_noise_C6", 
		14,                        
		prk                           
	);		
}
//psk
void mix_psk(uint8_t psk[NOISE_SYMMETRIC_KEY_LEN], uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t chaining_key[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN])
{
	uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
	uint8_t pi[NOISE_HASH_LEN];
	//expand 
	crypto_kdf_hkdf_sha256_extract(
		prk,
		chaining_key,
		NOISE_HASH_LEN,
		psk,
		NOISE_SYMMETRIC_KEY_LEN
	);
	//extract 1 => chaining_key
	crypto_kdf_hkdf_sha256_expand(
		chaining_key,
		NOISE_HASH_LEN,
		"NFSv4_noise_C7",
		14,
		prk
	);
	//extract 2 => pi
	crypto_kdf_hkdf_sha256_expand(
		pi,
		NOISE_HASH_LEN,
		"NFSv4_noise_pi",
		14,
		prk
	);
	//extract 3 => key
	crypto_kdf_hkdf_sha256_expand(
		key,
		NOISE_SYMMETRIC_KEY_LEN,
		"NFSv4_noise_K5",
		14,
		prk
	);
	
	update_transcript(hash, pi, NOISE_HASH_LEN); //H6

}

//derivate keys
void derive_keys(uint8_t first_key[NOISE_SYMMETRIC_KEY_LEN], uint8_t second_key[NOISE_SYMMETRIC_KEY_LEN], const uint8_t chaining_key[NOISE_HASH_LEN])
{
	const unsigned char *ikm = (const unsigned char *)"";
	uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
	//extract
	crypto_kdf_hkdf_sha256_extract(
		prk,
		chaining_key,
		NOISE_HASH_LEN,
		ikm,           
		0               
	);
	// Expand 1 = > first key
	crypto_kdf_hkdf_sha256_expand(
		first_key,
		NOISE_SYMMETRIC_KEY_LEN,
		"NFSv4_transport_key1",
		20,
		prk
	);
	// Expand 2 => second key
	crypto_kdf_hkdf_sha256_expand(
		second_key,
		NOISE_SYMMETRIC_KEY_LEN,
		"NFSv4_transport_key2",
		20,
		prk
	);
}


