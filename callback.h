#ifndef SOCKS5_DEV_CALLBACK_H
#define SOCKS5_DEV_CALLBACK_H

#include "defs.h"
#define KEEPALIVE 60


int init_tcp_handle(session_t *session, uv_tcp_t ** tcp_handler,uv_loop_t *);
int client_tcp_read_start(uv_stream_t *handle);
void on_client_tcp_alloc(uv_handle_t* handle,size_t suggested_size,uv_buf_t* buf);
void on_client_tcp_read_done(uv_stream_t* stream,ssize_t nread,const uv_buf_t* buf);

int client_tcp_write_string(uv_stream_t *handle, const char *data, int len);
int client_tcp_write_start(uv_stream_t *handle, const uv_buf_t *buf);
void on_client_tcp_write_done(uv_write_t *req, int status);


void handle_socks5_method_identification(uv_stream_t *handle,ssize_t nread, const uv_buf_t *buf,session_t *session);
void handle_socks5_request(uv_stream_t *handle,ssize_t nread, const uv_buf_t *buf,session_t *session);

int upstream_tcp_connect(uv_connect_t *req, struct sockaddr *addr);
void upstream_tcp_connect_cb(uv_connect_t* req, int status);
void finish_socks5_tcp_handshake(session_t *session);
void finish_socks5_handshake(session_t *session, struct sockaddr *addr);
int upstream_tcp_read_start(uv_stream_t *handle);
int upstream_tcp_write_start(uv_stream_t *handle, const uv_buf_t *buf);
void on_upstream_tcp_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
void on_upstream_tcp_read_done(uv_stream_t *handle, ssize_t nread,const uv_buf_t *buf);
int client_tcp_write_error(uv_stream_t *handle,int err);
void on_upstream_tcp_write_done(uv_write_t *req, int status);

void upstream_tcp_connect_log(session_t *session, int status);






#endif
