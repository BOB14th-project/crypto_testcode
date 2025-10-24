#include <sodium.h>
#include <stdio.h>

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char server_sk[crypto_kx_SECRETKEYBYTES];

    crypto_kx_keypair(client_pk, client_sk);
    crypto_kx_keypair(server_pk, server_sk);

    unsigned char rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];

    if (crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk) != 0) {
        fprintf(stderr, "client session key derivation failed\n");
        return 1;
    }
    if (crypto_kx_server_session_keys(tx, rx, server_pk, server_sk, client_pk) != 0) {
        fprintf(stderr, "server session key derivation failed\n");
        return 1;
    }

    printf("libsodium crypto_kx client rx first 8 bytes:\n");
    for (int i = 0; i < 8; ++i) {
        printf("%02x", rx[i]);
    }
    printf("\n");
    return 0;
}
