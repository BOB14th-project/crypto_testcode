#include <crypto/cryptodev.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifndef caddr_t
typedef char* caddr_t;
#endif

int main(void) {
    int fd = open("/dev/crypto", O_RDWR);
    if (fd < 0) {
        perror("open /dev/crypto");
        return 0;
    }

    unsigned char modulus[] = {0xc7, 0x53, 0x6b, 0x89, 0x51};
    unsigned char exponent[] = {0x01, 0x00, 0x01};
    unsigned char signature[] = {0x10, 0x20, 0x30, 0x40, 0x50};

    struct crypt_kop kop;
    memset(&kop, 0, sizeof(kop));
    kop.crk_op = CRK_MOD_EXP;
    kop.crk_iparams = 3;
    kop.crk_param[0].crp_p = (caddr_t)signature;
    kop.crk_param[0].crp_nbits = sizeof(signature) * 8;
    kop.crk_param[1].crp_p = (caddr_t)exponent;
    kop.crk_param[1].crp_nbits = sizeof(exponent) * 8;
    kop.crk_param[2].crp_p = (caddr_t)modulus;
    kop.crk_param[2].crp_nbits = sizeof(modulus) * 8;

    if (ioctl(fd, CIOCKEY, &kop) == -1) {
        perror("CIOCKEY verify");
    } else {
        printf("RSA verify modular exponentiation status=%d\n", kop.crk_status);
    }

    close(fd);
    return 0;
}
