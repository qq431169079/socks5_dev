#include <uv.h>
#include "callback.h"
#include "defs.h"
#include "resolve.h"
#include "main.h"
#include "socks5.h"
#include "logger.h"
#include "session.h"

static uv_loop_t *g_u_loop;

int client_tcp_read_start(uv_stream_t *handle)
{
    session_t *session = handle->data;
    if (session == NULL)
    {
        return -1;
    }
    int err;
    //读取流数据
    err = uv_read_start(handle, on_client_tcp_alloc, on_client_tcp_read_done);
    if (err!= 0)
    {
        logger_error("uv_read_start failed %s",uv_strerror(err));
        close_session(session);
    }
    return err;
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
    int err;
    err = uv_tcp_init(g_u_loop,*tcp_handler);
    if (err != 0){
        logger_error("uv_tcp_init failed :%s \n",uv_strerror(err));
        return err;
    }

    //uv_tcp_keepalive(uv_tcp_t *  handle，int  enable，unsigned int  delay )
    // 启用/禁用TCP保持活动状态。delay是以秒为单位的初始延迟,默认60s，当使能为零时将被忽略。
    err = uv_tcp_keepalive(*tcp_handler,1,KEEPALIVE);
    if (err !=0)
    {
        logger_error("uv_tcp_keepalive failed: %s \n",uv_strerror(err));
        return err;
    }
    return 0;
}

void handle_socks5_method_identification(uv_stream_t *handle,ssize_t nread, const uv_buf_t *buf,session_t *session)
{

    socks5_info_t *socks5_info = &session->session_fields.socks5_info;
    //验证socks5
    socks5_result_t result = socks5_parse_method_identification(socks5_info, buf->base, (int) nread);
    if (result != S5_OK)
    {
        logger_error("socks5_parse_method_identification failed\n");
        close_session(session);
        return;
    }
    //验证METHODS后
    if (socks5_info->state == FINISH)
    {
        //无密码验证
        if(socks5_info->methods & S5_AUTH_NONE)
        {
            session->session_fields.state = S5_REQUEST;
            //认证结束后客户端就可以发送请求信息
            client_tcp_write_string(handle, "\5\0", 2);
            logger_trace("socks5 method identification passed \n");
        } else{
            session->session_fields.state = S5_STREAMING_END;
            client_tcp_write_string(handle, "\5\xff", 2);
            logger_trace("socks5 method not supported \n");
        }

    } else{
        client_tcp_read_start((uv_stream_t *)handle);
    }

}

void on_client_tcp_read_done(uv_stream_t* handle,ssize_t nread,const uv_buf_t* buf){

    if (nread == 0)
    {
        return;
    }
    session_t *session = handle->data;
    //正在关闭
    if (session == NULL || session->session_fields.state == S5_CLOSING)
    {
        return;
    }
    //停止读取，使buf可以重复使用而不会溢出
    uv_read_stop(handle);

    if (nread <0)
    {
        if (nread != UV_EOF)
        {
            logger_error("client read failed:%s",uv_strerror(nread));
        }
        close_session(session);
        return;
    }
    if (session->session_fields.state == S5_METHOD_IDENTIFICATION)
    {
        resolve_print_stream(buf->base, nread,"s5 method identification");
        handle_socks5_method_identification(handle,nread,buf,session);
    } else if (session->session_fields.state == S5_REQUEST){
        //socks5客户端通过验证后，服务端开始发送请求
        resolve_print_stream(buf->base, nread,"s5 request");
        handle_socks5_request(handle,nread,buf,session);
    } else{
        if (session->session_fields.state == S5_STREAMING)
        {
            ((uv_buf_t *)buf)->len = nread;
            upstream_tcp_write_start((uv_stream_t *)((tcp_session_t *)session)->upstream_tcp,buf);
        } else{
            logger_warn("unexpected state : %d \n",session->session_fields.state);
            close_session(session);
        }
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
    int err;
    err = uv_write(&session->session_fields.client_write_req,handle,buf,1,on_client_tcp_write_done);
    if (err!= 0)
    {
        logger_error("uv_write failed:%s \n",uv_strerror(err));
        close_session(session);
    }
    return err;
}
void on_client_tcp_write_done(uv_write_t *req, int status){
    session_t *session = ((session_t *) ((char *) (req) - ((char *) &((session_t *) 0)->session_fields.client_write_req)));
    if (session->session_fields.state > S5_STREAMING)
    {
        return;
    }
    if (status <0 || session->session_fields.state == S5_STREAMING_END)
    {
        logger_trace("status=%d, now will close session \n", status);
    } else{
        if (session->session_fields.state < S5_STREAMING){
            if (session->session_fields.state == S5_FINISHING_HANDSHAKE)
            {
                session->session_fields.state = S5_STREAMING;
            }
            //socks5验证通过，客户端读取服务端回复消息后，客户端发送请求
            client_tcp_read_start((uv_stream_t *) session->session_fields.client_tcp);
        }
        if (session->session_fields.type == SESSION_TYPE_TCP && session->session_fields.state == S5_STREAMING)
        {
            //完成握手认证后，客户端读取 服务器读取数据后回应客户端的请求
            upstream_tcp_read_start((uv_stream_t *)((tcp_session_t *)session)->upstream_tcp);
        }

    }
}

void handle_socks5_request(uv_stream_t *handle,ssize_t nread, const uv_buf_t *buf,session_t *session){
    socks5_info_t *socks5_info = &session->session_fields.socks5_info;
    //封装请求
    socks5_result_t result = socks5_parse_request(socks5_info, buf->base, (int) nread);
    if (result != S5_OK)
    {
        logger_error("socks5_parse_request failed\n");
        client_tcp_write_error(handle,result);
        return;
    }
    //判断请求类型
    session->session_fields.type = (socks5_info->cmd == S5_CMD_UDP_ASSOCIATE? SESSION_TYPE_UDP:SESSION_TYPE_TCP);

    if (session->session_fields.type == SESSION_TYPE_UDP)
    {
        logger_warn("UDP Request not supported temporarily\n");
        return;
        //TODO
    }
    //为session重新开辟内存空间，并初始化
    session = lrealloc(session, sizeof(tcp_session_t));
    //tcp_session_t 指针 右移session_t大小
    memset(((char *)session)+ sizeof(session_t),0, sizeof(tcp_session_t) - sizeof(session_t));
    handle->data = session;

    int err;
    err = init_tcp_handle(session,&((tcp_session_t *)session)->upstream_tcp,g_u_loop);
    if (err <0)
    {
        client_tcp_write_error(handle,err);
        return;
    }
    if (socks5_info->atyp == S5_ATYP_IPV4)
    {
       struct sockaddr_in addr4;
       addr4.sin_family = AF_INET;
       addr4.sin_port = htons(socks5_info->dst_port);
       memcpy(&addr4.sin_addr.s_addr,socks5_info->dst_addr,4);
       err = upstream_tcp_connect(&((tcp_session_t*)session)->upstream_connect_req, (struct sockaddr *) &addr4);
       if (err !=0)
       {
           log_ipv4_and_port(socks5_info->dst_addr, socks5_info->dst_port,"upstream connect failed");
           client_tcp_write_error((uv_stream_t *) session->session_fields.client_tcp, err);
       }
    } else if (socks5_info->atyp == S5_ATYP_DOMAIN){
        //TODO
    } else if(socks5_info->atyp == S5_ATYP_IPV6){
        //TODO
    } else{
        logger_error("unknown ATYP: %d \n",socks5_info->atyp);
        client_tcp_write_error(handle,20000);
    }


}
int client_tcp_write_error(uv_stream_t *handle,int err)
{
    session_t *session = handle->data;
    if (session = NULL)
    {
        return -1;
    }
    char buf[] = { 5, 1, 0, 1, 0, 0, 0, 0, 0, 0 };
    session->session_fields.state = S5_STREAMING_END;
    switch (err)
    {
        case UV_ENETUNREACH: buf[1] = 3;
            break;//网络无法访问
        case UV_EHOSTUNREACH: buf[1] = 4;
            break;//主机不能到达
        case UV_ECONNREFUSED: buf[1] = 5;
            break;//主机拒绝
        case S5_UNSUPPORTED_CMD: buf[1] = 7;
            break;//不支持命令
        case S5_BAD_ATYP: buf[1] = 8;
            break;//错误ATYP
        default:buf[1] = 1;
            break;//通用socks错误
    }
    return client_tcp_write_string(handle,buf,10);

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
    int err;
    err = uv_tcp_connect(req,session->upstream_tcp,addr,upstream_tcp_connect_cb);
    if(err != 0 )
    {
        logger_warn("uv_tcp_connect failed: %s \n", uv_strerror(err));
    }
    return err;
}



void upstream_tcp_connect_cb(uv_connect_t* req, int status){
    tcp_session_t *session = ((tcp_session_t *) ((char *) (req) - ((char *) &((tcp_session_t *) 0)->upstream_connect_req)));
    if (session == NULL)
    {
        return;
    }
    upstream_tcp_connect_log((session_t *)session, status);
    if (status <0)
    {
        int keep_session_alive = (int) req->data;
        if (!keep_session_alive) {
            client_tcp_write_error((uv_stream_t *)session->session_fields.client_tcp, status);
        }
    } else{
        //完成握手
        finish_socks5_tcp_handshake((session_t *) session);
    }

}


/**
 * socks5tcp完成握手
 * @param session
 */
void finish_socks5_tcp_handshake(session_t *session) {
    session->session_fields.state = S5_FINISHING_HANDSHAKE;
    struct sockaddr_storage addr;
    //不能直接强转，否则内存抛出错误
    int err;
    err = uv_tcp_getsockname(((tcp_session_t*)session)->upstream_tcp, (struct sockaddr *)&addr,(int[]){ sizeof(struct sockaddr)});
    if (err <0)
    {
        logger_warn("uv_tcp_getsockname failed: %s \n", uv_strerror(err));
        client_tcp_write_error((uv_stream_t *) session->session_fields.client_tcp, err);
        return;
    }
    finish_socks5_handshake(session, (struct sockaddr *)&addr);
}
/**
 * socks5完成握手
 * @param session
 * @param addr
 */
void finish_socks5_handshake(session_t *session, struct sockaddr *addr) {
    uv_buf_t buf;
    buf.base = session->session_fields.client_buf;
    memcpy(buf.base, "\5\0\0\1", 4);
    uint16_t local_port = 0;
    if (addr->sa_family == AF_INET)
    {
        local_port = ((struct sockaddr_in *)addr)->sin_port;
        buf.len = 10;
        memcpy(buf.base + 4,&((struct sockaddr_in *)addr)->sin_addr.s_addr, 4);
        memcpy(buf.base + 8,&local_port,2);
    } else{
        local_port = ((struct sockaddr_in6 *)addr)->sin6_port;
        buf.len = 22;
        memcpy(buf.base+4, ((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr, 16);
        memcpy(buf.base+20, &local_port, 2);
    }
    logger_info("new connection bound to local port: %d \n", ntohs(local_port));
    client_tcp_write_start((uv_stream_t *) session->session_fields.client_tcp, &buf);
}

/**
 * 开始读取连接客户端后的数据
 * @param handle
 * @return
 */
int upstream_tcp_read_start(uv_stream_t *handle)
{
    session_t *session = handle->data;
    if (session == NULL)
    {
        return -1;
    }
    int err;
    err = uv_read_start(handle,on_upstream_tcp_alloc,on_upstream_tcp_read_done);
    if (err != 0)
    {
        logger_error("uv_read_start failed: %s \n", uv_strerror(err));
        close_session(session);
    }
    return err;
}

void on_upstream_tcp_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    tcp_session_t *sess = (tcp_session_t *)handle->data;
    buf->base = sess->upstream_buf;
    buf->len = sizeof(sess->upstream_buf);
}

void on_upstream_tcp_read_done(uv_stream_t *handle, ssize_t nread,const uv_buf_t *buf){
    if(nread == 0)
    {
        return;
    }
    session_t *session = handle->data;
    if (session == NULL || session->session_fields.state == S5_CLOSING)
    {
        return;
    }
    //停止读取，这样buf就可以被重用而不会溢出
    uv_read_stop(handle);
    if (nread <0 || session->session_fields.state == S5_STREAMING_END)
    {
        if (nread != UV_EOF)
        {
            logger_error("upstream read failed: %s \n", uv_strerror(nread));
        }
        close_session(session);
        return;
    }
    ((uv_buf_t*)buf)->len = (size_t) nread;
    client_tcp_write_start((uv_stream_t *) session->session_fields.client_tcp, buf);

}


int upstream_tcp_write_start(uv_stream_t *handle, const uv_buf_t *buf) {
    tcp_session_t *session = (tcp_session_t *)handle->data;
    if (session == NULL) {
        return -1;
    }
    int err;
    err =uv_write(&session->upstream_write_req, (uv_stream_t *)handle,buf, 1, on_upstream_tcp_write_done);
    if ((err != 0) ){
        logger_error("uv_write failed: %s \n", uv_strerror(err));
        close_session((session_t *)session);
    }
    return err;
}

void on_upstream_tcp_write_done(uv_write_t *req, int status) {
    tcp_session_t *session =  ((tcp_session_t *) ((char *) (req) - ((char *) &((tcp_session_t *) 0)->upstream_write_req)));
    if (status < 0 || session->session_fields.state == S5_STREAMING_END) {
        logger_error("upstream write failed: %s\n", uv_strerror(status));
        close_session((session_t *)session);
    } else {
        client_tcp_read_start((uv_stream_t *)session->session_fields.client_tcp);
    }
}

void upstream_tcp_connect_log(session_t *session, int status) {

    if (session->session_fields.socks5_info.atyp == S5_ATYP_IPV4) {
        char ipstr[INET_ADDRSTRLEN];
        uv_inet_ntop(AF_INET, session->session_fields.socks5_info.dst_addr, ipstr, INET_ADDRSTRLEN);
        logger_info("uv_tcp_connect: %s:%d, status: %s \n",
              ipstr, session->session_fields.socks5_info.dst_port,
              status ? uv_strerror(status) : "CONNECTED");

    } else if (session->session_fields.socks5_info.atyp == S5_ATYP_IPV6) {
        char ipstr[INET6_ADDRSTRLEN];
        uv_inet_ntop(AF_INET6, session->session_fields.socks5_info.dst_addr, ipstr, INET6_ADDRSTRLEN);
        logger_info("uv_tcp_connect: %s:%d, status: %s \n",
              ipstr, session->session_fields.socks5_info.dst_port,
              status ? uv_strerror(status) : "CONNECTED");

    } else {
        logger_info("uv_tcp_connect: %s:%d, status: %s \n",
                    session->session_fields.socks5_info.dst_addr, session->session_fields.socks5_info.dst_port,
                    status ? uv_strerror(status) : "CONNECTED");
    }

}

