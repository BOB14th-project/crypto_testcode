#include <crypto/cryptodev.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void) {
    int fd = open("/dev/crypto", O_RDWR);
    if (fd < 0) {
        perror("open /dev/crypto");
        return 0;
    }

    unsigned char key[16] = {0};
    struct session_op sess;
    memset(&sess, 0, sizeof(sess));
    sess.cipher = CRYPTO_AES_ECB;
    sess.key = key;
    sess.keylen = sizeof(key);

    if (ioctl(fd, CIOCGSESSION, &sess) == -1) {
        perror("CIOCGSESSION");
        close(fd);
        return 1;
    }

    struct session_info_op info;
    memset(&info, 0, sizeof(info));
    info.ses = sess.ses;
    if (ioctl(fd, CIOCGSESSINFO, &info) == -1) {
        perror("CIOCGSESSINFO");
    } else {
        printf("Session info: cipher=%u (align mask=0x%x, flags=0x%x)\n",
               info.cipher, info.alignmask, info.flags);
    }

    if (ioctl(fd, CIOCFSESSION, &sess.ses) == -1) {
        perror("CIOCFSESSION");
    }
    close(fd);
    return 0;
}
