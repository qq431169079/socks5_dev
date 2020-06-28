#include <uv.h>
#include "callback.h"
#include "defs.h"
#include "resolve.h"
#include "main.h"
#include "socks5.h"

static uv_loop_t *g_u_loop;

int client_tcp_read_start(uv_stream_t *handle)
{
    session_t *session = handle->data;
    if (session == NULL)
    {
        return -1;
    }
    uv_read_start(handle, on_client_tcp_alloc, on_client_tcp_read_done);
    return 1;
}

void on_client_tcp_alloc(uv_handle_t* handle,size_t suggested_size,uv_buf_t* buf){
    session_t *session = handle->data;
    buf->base = session->session_fields.client_buf;
    buf->len = sizeof(session->session_fields.client_buf);
}

/**
 * 初始化tcp处理
 * @param session
 * @param tcp_handler
 * @return
 */
int init_tcp_handle(session_t *session, uv_tcp_t ** tcp_handler,uv_loop_t *g_loop)
{
    g_u_loop = g_loop;
    *tcp_handler = lmalloc(sizeof(uv_tcp_t));
    (*tcp_handler)->data = session;
    uv_tcp_init(g_u_loop,*tcp_handler);

    //uv_tcp_keepalive(uv_tcp_t *  handle，int  enable，unsigned int  delay )
    // 启用/禁用TCP保持活动状态。delay是以秒为单位的初始延迟,默认60s，当使能为零时将被忽略。
    uv_tcp_keepalive(*tcp_handler,1,KEEPALIVE);
    return 0;
}

void handle_socks5_method_identification(uv_stream_t *handle,ssize_t nread, const uv_buf_t *buf,session_t *session)
{

    socks5_info_t *socks5_info = &session->session_fields.socks5_info;
    //验证socks5
    socks5_result_t result = socks5_parse_method_identification(socks5_info, buf->base, (int) nread);
    if (socks5_info->state == FINISH)
    {
        //无密码验证
        if(socks5_info->methods & S5_AUTH_NONE)
        {
            session->session_fields.state = S5_REQUEST;
            //认证结束后客户端就可以发送请求信息
            client_tcp_write_string(handle, "\5\0", 2);
            printf("socks5 method identification passed \n");
        } else{
            session->session_fields.state = S5_STREAMING_END;
            client_tcp_write_string(handle, "\5\xff", 2);
            printf("socks5 method not supported \n");
        }

    } else{
        client_tcp_read_start((uv_stream_t *)handle);
    }

}

void on_client_tcp_read_done(uv_stream_t* stream,ssize_t nread,const uv_buf_t* buf){
    if (nread == 0)
    {
        return;
    }
    session_t *session = stream->data;
    //正在关闭
    if (session == NULL || session->session_fields.state == S5_CLOSING)
    {
        return;
    }
    //停止读取，使buf可以重复使用而不会溢出
    uv_read_stop(stream);
    if (session->session_fields.state == S5_METHOD_IDENTIFICATION)
    {
        printf("S5_METHOD_IDENTIFICATION\n");
        handle_socks5_method_identification(stream,nread,buf,session);
    } else if (session->session_fields.state == S5_REQUEST){
        //socks5客户端通过验证后，开始发送请求
        printf("S5_REQUEST\n");
        handle_socks5_request(stream,nread,buf,session);
    } else{
        printf("unexpected state : %d",session->session_fields.state);
    }

}

int client_tcp_write_string(uv_stream_t *handle, const char *data, int len)
{
    uv_buf_t buf;
    buf.base = (char *)data;
    buf.len = (size_t) len;
    return client_tcp_write_start(handle,&buf);
}
int client_tcp_write_start(uv_stream_t *handle, const uv_buf_t *buf){
    session_t *session = handle->data;
    if (session == NULL)
    {
        return -1;
    }
    return uv_write(&session->session_fields.client_write_req,handle,buf,1,on_client_tcp_write_done);
}
void on_client_tcp_write_done(uv_write_t *req, int status){
    //req的地址强转为session地址
    session_t *session = ((session_t *) ((char *) (req) - ((char *) &((session_t *) 0)->session_fields.client_write_req)));
    if (session->session_fields.state > S5_STREAMING)
    {
        return;
    }
    if (status <0 || session->session_fields.state == S5_STREAMING_END)
    {
        printf("status=%d, now will close session", status);
    } else{
        if (session->session_fields.state < S5_STREAMING){
            //结束握手
            if (session->session_fields.state == S5_FINISHING_HANDSHAKE)
            {
                session->session_fields.state = S5_STREAMING;
            }
            //socks5验证通过，客户端读取服务端回复消息后，客户端发送请求
            printf("status=%d, now client pass verification ，client get msg then send request \n", session->session_fields.state);
            client_tcp_read_start((uv_stream_t *) session->session_fields.client_tcp);
        }
        if (session->session_fields.type == SESSION_TYPE_TCP && session->session_fields.state == S5_STREAMING)
        {
            //TODO
            printf("gggggg\n");
        }

    }
}

void handle_socks5_request(uv_stream_t *handle,ssize_t nread, const uv_buf_t *buf,session_t *session){
    socks5_info_t *socks5_info = &session->session_fields.socks5_info;
    socks5_result_t result = socks5_parse_request(socks5_info, buf->base, (int) nread);
    if (result != S5_OK)
    {
        printf("socks5_parse_request failed");
        return;
    }
    //判断请求类型
    session->session_fields.type = (socks5_info->cmd == S5_CMD_UDP_ASSOCIATE? SESSION_TYPE_UDP:SESSION_TYPE_TCP);

    if (session->session_fields.type == SESSION_TYPE_UDP)
    {
        printf("received a UDP request\n");
        //TODO
    }
    //为session重新开辟内存空间，并初始化
    session = lrealloc(session, sizeof(tcp_session_t));
    memset(((char *)session)+ sizeof(session_t),0, sizeof(tcp_session_t) - sizeof(session_t));
    handle->data = session;

    init_tcp_handle(session,&((tcp_session_t *)session)->upstream_tcp,g_u_loop);
    if (socks5_info->atyp == S5_ATYP_IPV4)
    {
       struct sockaddr_in addr4;
       addr4.sin_family = AF_INET;
       addr4.sin_port = htons(socks5_info->dst_port);
       memcpy(&addr4.sin_addr.s_addr,socks5_info->dst_addr,4);
       //连接接客户端
       printf("CONNECT\n");
       upstream_tcp_connect(&((tcp_session_t*)session)->upstream_connect_req, (struct sockaddr *) &addr4);
    } else if (socks5_info->atyp == S5_ATYP_DOMAIN){
        struct addrinfo hint;
        memset(&hint, 0, sizeof(hint));
        hint.ai_family = AF_UNSPEC;
        hint.ai_socktype = SOCK_STREAM;
        hint.ai_protocol = IPPROTO_TCP;
        //TODO


    }
    //TODO
}
/**
 * 客户端连接
 * @param req
 * @param addr
 * @return
 */
int upstream_tcp_connect(uv_connect_t *req, struct sockaddr *addr)
{
    tcp_session_t *session = ((tcp_session_t *) ((char *) (req) - ((char *) &((tcp_session_t *) 0)->upstream_connect_req)));
    uv_tcp_connect(req,session->upstream_tcp,addr,upstream_tcp_connect_cb);
    return 0;
}

void upstream_tcp_connect_cb(uv_connect_t* req, int status){
    tcp_session_t *session = ((tcp_session_t *) ((char *) (req) - ((char *) &((tcp_session_t *) 0)->upstream_connect_req)));
    if (session == NULL)
    {
        return;
    }if (status <0)
    {
        int keep_session_alive = (int) req->data;
        printf("keep_session_alive %d\n", (int) req->data);
    } else{
        //完成握手
        finish_socks5_tcp_handshake((session_t *) session);
    }

}


/**
 * 完成握手
 * @param session
 */
void finish_socks5_tcp_handshake(session_t *session) {
    session->session_fields.state = S5_FINISHING_HANDSHAKE;
    
}