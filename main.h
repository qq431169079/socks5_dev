//
// Created by User on 2020/6/22.
//

#ifndef SOCKS5_DEV_MAIN_H
#define SOCKS5_DEV_MAIN_H


typedef struct {
    char *host;
    int port;
    int backlog;
}server_cfg_t;

typedef enum {
    IPV4,
    IPV6
}ip_version_t;

typedef struct {
    uv_getaddrinfo_t addrinfo_req;
    uv_tcp_t server_tcp;
    server_cfg_t server_cfg;
    ip_version_t ip_version;
    uint8_t bound_ip[16];
}server_info_t;

#endif //SOCKS5_DEV_MAIN_H
