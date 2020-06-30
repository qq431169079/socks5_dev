
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <uv.h>

#include "main.h"
#include "resolve.h"
#include "defs.h"
#include "session.h"
#include "socks5.h"
#include "callback.h"
#include "logger.h"

#define SERVER_BACKLOG 256




static server_info_t *g_server_info;
static uv_loop_t *g_loop;

void on_connection_new(uv_stream_t* server, int status)
{
    if (status <0)
    {
        logger_error("uv_accept fail: %s \n",uv_strerror(status));
        return;
    }
    logger_info("socket accept new connection\n");
    //初始化socks5代理服务器状态
    session_t *session = create_session();
    //初始化客户端uv_tcp_t
    if (init_tcp_handle(session, &session->session_fields.client_tcp, g_loop)<0){
        close_session(session);
        return;
    }
    //接受客户端
    int err;
    err = uv_accept(server, (uv_stream_t *) session->session_fields.client_tcp);
    if (err !=0)
    {
        logger_error("uv_accept failed :%s",uv_strerror(err));
        close_session(session);
        return;
    }

    //客户端开始读取
    client_tcp_read_start((uv_stream_t *) session->session_fields.client_tcp);
}
void bind_and_listen(uv_getaddrinfo_t* req,int status,struct addrinfo* res){
    if (status <0)
    {
        logger_error("getaddrinfo(\"%s\"):%s \n",g_server_info->server_cfg.host,uv_strerror(status));
        uv_freeaddrinfo(res);
        return;
    }
    struct sockaddr_storage addr;
    char ipstr[INET6_ADDRSTRLEN];

    do_check(uv_tcp_init(g_loop,&g_server_info->server_tcp) == 0);

    for (struct addrinfo *ai = res; ai != NULL ; ai = ai->ai_next) {
        if (resolve_addr((struct sockaddr *) &addr, htons((uint16_t) g_server_info->server_cfg.port), ipstr, sizeof(ipstr), ai) != 0){
            continue;
        }
        if (ai->ai_family == AF_INET)
        {
            g_server_info->ip_version = IPV4;
            memcpy(g_server_info->bound_ip, &((struct sockaddr_in *)&addr)->sin_addr.s_addr, 4);
        } else if (ai->ai_family == AF_INET6)
        {
            g_server_info->ip_version = IPV6;
            memcpy(g_server_info->bound_ip,((struct sockaddr_in6 *)&addr)->sin6_addr.s6_addr, 16);
        }

        //绑定
        int err;
        err = uv_tcp_bind(&g_server_info->server_tcp, (const struct sockaddr *) &addr, 0);
        if (err!=0){
            logger_warn("uv_tcp_bind on %s: %d failed : %s \n",ipstr,g_server_info->server_cfg.port,uv_strerror(err));
            continue;
        };
        //监听
        err = uv_listen((uv_stream_t *) &g_server_info->server_tcp, g_server_info->server_cfg.backlog, on_connection_new);
        if (err!=0)
        {
            logger_warn("uv_tcp_listen on %s: %d failed : %s \n",ipstr,g_server_info->server_cfg.port,uv_strerror(err));
            continue;
        }
        logger_info("server listening on %s:%d \n",ipstr,g_server_info->server_cfg.port);
        uv_freeaddrinfo(res);
        return;
    }
    logger_error("fail to bind on local_port : %d \n",g_server_info->server_cfg.port);
    exit(EXIT_FAILURE);

}

int main(int argc ,char *argv[]){

    //初始化logger日志
    logger_init("test.log", LOGGER_LEVEL_TRACE);
    

    char *localhost;
    int local_port;
    //监听地址,端口
    localhost = "127.0.0.1";
    local_port = 1082;


    g_loop = uv_default_loop();
    server_info_t info;

    memset(&info,0, sizeof(server_info_t));
    info.server_cfg.host = localhost;
    info.server_cfg.port = local_port;
    info.server_cfg.backlog = SERVER_BACKLOG;
    g_server_info = &info;

    struct addrinfo hint;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;
    do_check(uv_getaddrinfo(g_loop,&info.addrinfo_req,bind_and_listen,localhost,NULL,&hint) == 0);
    uv_run(g_loop,UV_RUN_DEFAULT);
    uv_loop_close(g_loop);



    logger_close();
    
    return 0;
}