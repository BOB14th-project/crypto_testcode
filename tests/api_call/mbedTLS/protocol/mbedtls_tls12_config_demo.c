#include "mbedtls/ssl.h"

#include <stdio.h>

int main(void) {
    mbedtls_ssl_config conf;
    mbedtls_ssl_config_init(&conf);

    if (mbedtls_ssl_config_defaults(&conf,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        printf("ssl_config_defaults failed\n");
        mbedtls_ssl_config_free(&conf);
        return 1;
    }

    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                 MBEDTLS_SSL_MINOR_VERSION_1); // TLS 1.0
    mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                 MBEDTLS_SSL_MINOR_VERSION_3); // TLS 1.2

    mbedtls_ssl_conf_ciphersuites(&conf, (const int[]){
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
        0
    });

    printf("mbedTLS configured for TLS 1.0-1.2 with AES-256-GCM ciphersuites.\n");

    mbedtls_ssl_config_free(&conf);
    return 0;
}
