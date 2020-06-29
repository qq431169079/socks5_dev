

#ifndef SOCKS5_DEV_DEFS_H
#define SOCKS5_DEV_DEFS_H

#include <uv.h>
#include "socks5.h"

#define SESSION_TCP_BUFSIZ 8192
#define SESSION_UDP_BUFSIZ 4096

typedef enum {
    S5_METHOD_IDENTIFICATION,   //s5_method_identification
    S5_REQUEST,                 //s5_request
    S5_FINISHING_HANDSHAKE,     //s5_finishing_handshake 结束握手
    S5_STREAMING,               //s5_streaming
    S5_STREAMING_END,           //s5_streaming_end       结束传输
    S5_CLOSING,                 //s5_closing
} session_state_t;
typedef enum {
    SESSION_TYPE_UNKNOWN,       //session_type_unknown
    SESSION_TYPE_TCP,           //session_type_tcp
    SESSION_TYPE_UDP            //session_type_udp
} session_type_t;

typedef struct {
    uv_tcp_t *client_tcp;
    uv_write_t client_write_req;
    char client_buf[SESSION_TCP_BUFSIZ];
    session_state_t state;
    socks5_info_t socks5_info;
    session_type_t type;
    int8_t heap_obj_count;
}session_fields_t;

typedef struct {
    session_fields_t  session_fields;
    uv_tcp_t * upstream_tcp;
    uv_write_t upstream_write_req;
    uv_getaddrinfo_t upstream_addrinfo_req;
    uv_connect_t upstream_connect_req;
    char upstream_buf[SESSION_TCP_BUFSIZ];
}tcp_session_t;

typedef struct {
    session_fields_t  session_fields;
    uv_udp_t *client_udp_recv;
    char clinet_udp_recv_buf[SESSION_UDP_BUFSIZ];

    uv_udp_t *upstream_udp;
    uv_udp_send_t upstream_udp_send_req;
    uv_getaddrinfo_t upstream_udp_addrinfo_req;
    char upstream_udp_buf[SESSION_UDP_BUFSIZ];

    uv_udp_t *client_udp_send;
    uv_udp_send_t client_udp_send_req;
    uv_getaddrinfo_t client_udp_addrinfo_req;
} udp_session_t;

typedef struct {
    session_fields_t  session_fields;
}session_t;

#endif
