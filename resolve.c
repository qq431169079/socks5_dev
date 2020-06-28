//
// Created by User on 2020/6/25.
//

#include "resolve.h"
#include <uv.h>
#include <string.h>

void *lmalloc(size_t size)
{
    void *p = malloc(size);
    memset(p,0,size);
    if (!p)
    {
        fprintf(stderr, "malloc failed for: %lu\n", size);
        exit(1);
    }
    return p;
}

void *lrealloc(void *p,size_t size)
{
    void *p2 = realloc(p,size);
    if (!p){
        fprintf(stderr, "realloc failed for: %lu\n", size);
        exit(1);
    }
    return p2;
}

int resolve_addr(struct sockaddr *addr,int port,char * ipstr, int ipstr_len, struct addrinfo *ai)
{
    if (ai->ai_family ==AF_INET)
    {
        struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
        memcpy(addr4,ai->ai_addr, sizeof(struct sockaddr_in));
        addr4->sin_port = (in_port_t) port;
        uv_inet_ntop(addr4->sin_family, &addr4->sin_addr, ipstr, (size_t) ipstr_len);
    } else if (ai->ai_family == AF_INET6)
    {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        memcpy(addr6, ai->ai_addr, sizeof(struct sockaddr_in6));
        addr6->sin6_port = (in_port_t) port;
        uv_inet_ntop(addr6->sin6_family, &addr6->sin6_addr, ipstr, (size_t) ipstr_len);
    } else{
        printf("resolve error");
        return -1;
    }
    return 0;
}
