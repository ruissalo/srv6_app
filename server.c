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

#define MAXLINE 8094

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

void
srh_print(int sockfd)
{
   int    rc;
   struct msghdr  msg;
   struct cmsghdr *cmsg;

  int iov_number;
  struct iovec iov_data[1];
  char buffer[1024];
  
  bzero(&msg, sizeof(msg));
  iov_data[0].iov_base = buffer;
  iov_data[0].iov_len = 1024;
  iov_number = 1;

  char control[1024];

  struct sockaddr_in6 client_address;

  msg.msg_iov = iov_data;
  msg.msg_iovlen = iov_number;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  msg.msg_name = NULL;

   char *data;
   rc = recvmsg(sockfd, &msg, 0);
   char str[INET6_ADDRSTRLEN] = {0};
   char str1[INET6_ADDRSTRLEN] = {0};


  if (rc < 0) { 
        perror("error reading socket");
        }
  else {
         for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
              cmsg = CMSG_NXTHDR (&msg, cmsg))  {
             if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                 cmsg->cmsg_type == IPV6_RTHDR)  {
                  data = CMSG_DATA(cmsg);
                  struct ipv6_sr_hdr *rthdr = (struct ipv6_sr_hdr *) data;
                  printf("header len is %d\n", rthdr->hdrlen);
                  printf("header type is %d\n", rthdr->type);
                  printf("next header %d\n", rthdr->nexthdr);
                  printf("first segment is %d\n", rthdr->first_segment);
                  printf("reserved is %d\n", rthdr->reserved);
                  inet_ntop(AF_INET6, &rthdr->segments[0], str, sizeof(str));
                  inet_ntop(AF_INET6, &rthdr->segments[1], str1, sizeof(str1));
                  printf("%s \n", str);
                  printf("%s \n", str1);
                 if (msg.msg_flags & MSG_CTRUNC)
                     printf(" (control info truncated)");
             }
        }
  }
  
}

int sr_server(const char *bindaddr, short port)
{
    int fd, err, connfd;
    struct sockaddr_in6 sin6_bind;
    int on;
    on =1;
  
    struct sockaddr_in6	cliaddr;
    int clilen;

    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    err = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVRTHDR, &on, sizeof(on));
    if (err < 0) {
        perror("setsockopt");
        close(fd);
        return -1;
    }

    bzero(&sin6_bind, sizeof(sin6_bind));
    sin6_bind.sin6_family = AF_INET6;
    inet_pton(AF_INET6, bindaddr, &sin6_bind.sin6_addr);
    sin6_bind.sin6_port = htons(port);    

    
    err = bind(fd, (struct sockaddr *)&sin6_bind, sizeof(sin6_bind));
    if (err < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
  srh_print(fd);
}

int main(int ac, char **av)
{
    if (ac < 3) {
        fprintf(stderr, "Usage: %s bindaddr port\n", av[0]);
        return -1;
    }

    return sr_server(av[1], atoi(av[2]));
}

