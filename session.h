//
// Created by User on 2020/6/27.
//

#ifndef SOCKS5_DEV_SESSION_H
#define SOCKS5_DEV_SESSION_H

#include "defs.h"

session_t *create_session();
void close_session(session_t *session);
void close_handle(session_t *session, uv_handle_t *handle);
void handle_close_cb(uv_handle_t *handle);


#endif //SOCKS5_DEV_SESSION_H
