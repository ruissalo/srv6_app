#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <limits.h>
#ifndef __u8
#define __u8 uint8_t
#endif

struct ipv6_sr_hdr {
        __u8    nexthdr;
        __u8    hdrlen;
        __u8    type;
        __u8    segments_left;
        __u8    first_segment;
        __u8    flag_1;
        __u8    flag_2;
        __u8    reserved;

        struct in6_addr segments[0];
};

int test_sr(const char *dst, short port, const char *segment)
{
    int fd, err, srh_len;
    struct ipv6_sr_hdr *srh;
    struct sockaddr_in6 sin6, sin6_bind;

    srh_len = sizeof(*srh) + 2 * sizeof(struct in6_addr);
    srh = malloc(srh_len);
    if (!srh)
        return -1;

    srh->nexthdr = 0;
    srh->hdrlen = 4;
    srh->type = 4;
    srh->segments_left = 1;
    srh->first_segment = 1;
    srh->flag_1 = 0;
    srh->flag_2 = 0;
    srh->reserved = 0;

    memset(&srh->segments[0], 0, sizeof(struct in6_addr));
    inet_pton(AF_INET6, segment, &srh->segments[1]);

    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    err = setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, srh, srh_len);
    if (err < 0) {
        perror("setsockopt");
        close(fd);
        return -1;
    }

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(port);
    inet_pton(AF_INET6, dst, &sin6.sin6_addr);

    static char buffer[] = "Hello, I'm here\n";
    int buffer_size;
    buffer_size = strlen(buffer);

    int n;
    n = sendto(fd, buffer, buffer_size, 0, (struct sockaddr *) &sin6, sizeof(sin6));
    if (n < 0) {
        perror("Error sending UDP message");
        return -1;
    }
return 0;
}

int main(int ac, char **av)
{
    if (ac < 4) {
        fprintf(stderr, "Usage: %s dst port segment\n", av[0]);
        return -1;
    }

    return test_sr(av[1], atoi(av[2]), av[3]);
}
