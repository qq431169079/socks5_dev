
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

#define SERVER_BACKLOG 256




static server_info_t *g_server_info;
static uv_loop_t *g_loop;

void on_connection_new(uv_stream_t* server, int status)
{
    //初始化socks5代理服务器状态
    session_t *session = create_session();
    //初始化客户端uv_tcp_t
    init_tcp_handle(session, &session->session_fields.client_tcp, g_loop);
    printf("accept stream data\n");
    uv_accept(server, (uv_stream_t *) session->session_fields.client_tcp);
    //客户端开始读取
    client_tcp_read_start((uv_stream_t *) session->session_fields.client_tcp);
}
void bind_and_listen(uv_getaddrinfo_t* req,int status,struct addrinfo* res){
    struct sockaddr_storage addr;
    char ipstr[INET6_ADDRSTRLEN];

    uv_tcp_init(g_loop,&g_server_info->server_tcp);

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
        uv_tcp_bind(&g_server_info->server_tcp, (const struct sockaddr *) &addr, 0);
        //监听
        uv_listen((uv_stream_t *) &g_server_info->server_tcp, g_server_info->server_cfg.backlog, on_connection_new);
    }

}

int main(int argc ,char *argv[]){
    char *localhost;
    int local_port;
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

    uv_getaddrinfo(g_loop,&info.addrinfo_req,bind_and_listen,localhost,NULL,&hint);
    uv_run(g_loop,UV_RUN_DEFAULT);
    uv_loop_close(g_loop);
    
    return 0;
}