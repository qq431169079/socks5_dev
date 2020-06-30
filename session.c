
#include "session.h"
#include "defs.h"
#include "resolve.h"
#include "logger.h"

session_t *create_session()
{
    session_t *session = lmalloc(sizeof(session_t));
    //初始化socks5识别
    session->session_fields.state = S5_METHOD_IDENTIFICATION;
    //初始化请求类型
    session->session_fields.type = SESSION_TYPE_UNKNOWN;
    return session;
}

void close_session(session_t *session)
{
    if (session->session_fields.state == S5_CLOSING)
    {
        return;
    }
    //设置关闭
    session->session_fields.state = S5_CLOSING;
    logger_trace("now will close session: %p \n",session);
    if (session->session_fields.type == SESSION_TYPE_TCP)
    {
        session->session_fields.heap_obj_count = 2;
        tcp_session_t *tcp_session = (tcp_session_t *) session;
        close_handle(session,tcp_session->upstream_tcp);
    } else if (session->session_fields.type == SESSION_TYPE_UDP)
    {
        session->session_fields.heap_obj_count = 4;
    }

}

void close_handle(session_t *session, uv_handle_t *handle) {
    if (handle == NULL) {
        --session->session_fields.heap_obj_count;
        return;
    }

    if (handle->type == UV_TCP) {
        uv_read_stop((uv_stream_t *)handle);
    } else if (handle->type == UV_UDP) {
        uv_udp_recv_stop((uv_udp_t *)handle);
    }

    if (!uv_is_closing(handle)) {
        uv_close(handle, handle_close_cb);
    }
}

void handle_close_cb(uv_handle_t *handle)
{
    session_t *session = handle->data;
    --session->session_fields.heap_obj_count;
    free(handle);

    if (session->session_fields.heap_obj_count == 0) {
        logger_info("now will free the session object: %p \n", session);
        free(session);
    }
}
