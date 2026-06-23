#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

void encode_and_print_b64(const uint8_t *bin, size_t bin_len) {
    size_t b64_size = sodium_base64_ENCODED_LEN(bin_len, sodium_base64_VARIANT_ORIGINAL);
    char b64_buffer[b64_size];
    //sodium encode
    sodium_bin2base64(
        b64_buffer, 
        b64_size, 
        bin, 
        bin_len, 
        sodium_base64_VARIANT_ORIGINAL
    );
    printf("%s\n", b64_buffer);
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "[x] failed initiating sodium\n");
        return EXIT_FAILURE;
    }
    uint8_t server_priv[crypto_scalarmult_curve25519_SCALARBYTES];
    uint8_t server_pub[crypto_scalarmult_curve25519_BYTES];
    
    uint8_t client_priv[crypto_scalarmult_curve25519_SCALARBYTES];
    uint8_t client_pub[crypto_scalarmult_curve25519_BYTES];
    
    uint8_t psk[crypto_auth_hmacsha256_KEYBYTES];
    //first priv then cruve scalar mult to get the pubkey
    randombytes_buf(server_priv, sizeof(server_priv));
    crypto_scalarmult_base(server_pub, server_priv);
    randombytes_buf(client_priv, sizeof(client_priv));
    crypto_scalarmult_base(client_pub, client_priv);
    randombytes_buf(psk, sizeof(psk));
    
    printf("==================================================\n");
    printf("         SERVER\n");
    printf("==================================================\n");
    printf("[Server]\n");
    printf("PrivateKey = ");
    encode_and_print_b64(server_priv, sizeof(server_priv));
    printf("\n");
    printf("PublicKey = ");
    encode_and_print_b64(server_pub, sizeof(server_pub));
    printf("\n");
    printf("PresharedKey = ");
    encode_and_print_b64(psk, sizeof(psk));
    printf("==================================================\n");

    printf("\n");

    printf("==================================================\n");
    printf("         CLIENT\n");
    printf("==================================================\n");
    printf("[Client]\n");
    printf("PrivateKey = ");
    encode_and_print_b64(client_priv, sizeof(client_priv));
    printf("\n");
    printf("PublicKey = ");
    encode_and_print_b64(client_pub, sizeof(client_pub));
    printf("\n");
    printf("PresharedKey = ");
    encode_and_print_b64(psk, sizeof(psk));
    printf("==================================================\n");

    return EXIT_SUCCESS;
}