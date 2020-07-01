//
// Created by User on 2020/6/25.
//

#ifndef SOCKS5_DEV_RESOLVE_H
#define SOCKS5_DEV_RESOLVE_H

#include <uv.h>
#include <string.h>
#include <stdlib.h>

void *lmalloc(size_t size);
void *lrealloc(void *p,size_t size);

int resolve_addr(struct sockaddr *addr,int port,char * ipstr, int ipstr_len, struct addrinfo *ai);
void do_check(int resolve);
void log_ipv4_and_port(void *ipv4, int port, const char *msg);
char * resolve_print_stream(char *,ssize_t);

#endif //SOCKS5_DEV_RESOLVE_H
