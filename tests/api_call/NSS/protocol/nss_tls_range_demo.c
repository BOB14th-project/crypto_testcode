#include <nss.h>
#include <ssl.h>
#include <sslproto.h>
#include <secerr.h>
#include <stdio.h>

static const char* version_name(PRUint16 v) {
    switch (v) {
        case SSL_LIBRARY_VERSION_TLS_1_0: return "TLS 1.0";
        case SSL_LIBRARY_VERSION_TLS_1_1: return "TLS 1.1";
        case SSL_LIBRARY_VERSION_TLS_1_2: return "TLS 1.2";
        case SSL_LIBRARY_VERSION_TLS_1_3: return "TLS 1.3";
        default: return "UNKNOWN";
    }
}

int main(void) {
    if (NSS_NoDB_Init(NULL) != SECSuccess) {
        fprintf(stderr, "NSS init failed: %d\n", PR_GetError());
        return 1;
    }

    SSLVersionRange range;
    if (SSL_VersionRangeGetDefault(ssl_variant_stream, &range) != SECSuccess) {
        fprintf(stderr, "VersionRangeGetDefault failed: %d\n", PR_GetError());
        NSS_Shutdown();
        return 1;
    }

    printf("Default TLS version range: %s - %s\n",
           version_name(range.min), version_name(range.max));

    range.max = SSL_LIBRARY_VERSION_TLS_1_2;
    if (SSL_VersionRangeSetDefault(ssl_variant_stream, &range) != SECSuccess) {
        fprintf(stderr, "VersionRangeSetDefault failed: %d\n", PR_GetError());
        NSS_Shutdown();
        return 1;
    }

    printf("Adjusted TLS max to %s for classical-only testing.\n", version_name(range.max));

    NSS_Shutdown();
    return 0;
}
