#include <fcntl.h>
#include <linux/random.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void) {
    int fd = open("/dev/random", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/random");
        return 1;
    }

    int ent = 0;
    if (ioctl(fd, RNDGETENTCNT, &ent) == -1) {
        perror("RNDGETENTCNT");
        close(fd);
        return 1;
    }

    printf("Kernel entropy pool: %d bits available\n", ent);

    unsigned char sample[32];
    ssize_t n = read(fd, sample, sizeof(sample));
    if (n < 0) {
        perror("read /dev/random");
        close(fd);
        return 1;
    }

    printf("Read %zd bytes from /dev/random:\n", n);
    for (ssize_t i = 0; i < n; ++i) {
        printf("%02x", sample[i]);
    }
    printf("\n");

    close(fd);
    return 0;
}
