#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include <stdio.h>

int main(void) {
    int ret;
    ecc_key key;

    wc_ecc_init(&key);
    ret = wc_ecc_make_key(NULL, 32, &key); // 256-bit
    if (ret != 0) {
        printf("wc_ecc_make_key failed: %d\n", ret);
        wc_ecc_free(&key);
        return 1;
    }

    printf("wolfSSL ECC key generated (size: %d bits)\n", key.dp->size * 8);

    wc_ecc_free(&key);
    return 0;
}
