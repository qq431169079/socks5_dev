

#ifndef SOCKS5_DEV_SOCKS5_H
#define SOCKS5_DEV_SOCKS5_H

#include <stdint.h>

#define SOCKS5_VERSION 5

typedef enum{
    VERSION,            //version
    NMETHODS,           //nmethods
    METHODS,            //methods
    REQ_VERSION,        //req_version
    REQ_CMD,            //req_cmd
    REQ_RSV,            //req_rsv
    REQ_ATYP,           //req_atyp
    REQ_DST_ADDR_LEN,   //req_dst_addr_len
    REQ_DST_ADDR,       //req_dst_addr
    REQ_DST_PORT,       //req_dst_port
    FINISH              //finish
}socks5_state_t;

typedef enum {
    S5_AUTH_NONE = 1 << 0,   //10进制 1
    S5_AUTH_GSSAPI = 1 << 1, //10进制 2
    S5_AUTH_PASSWD = 1 << 2  //10进制 4
}socks5_auth_method_t;

typedef enum {
    S5_ATYP_IPV4 = 1,
    S5_ATYP_DOMAIN = 3,
    S5_ATYP_IPV6 = 4
} socks5_atyp;
typedef enum {
    S5_CMD_CONNECT = 1,
    S5_CMD_BIND = 2,
    S5_CMD_UDP_ASSOCIATE = 3
}socks5_command_t;


typedef enum {
    S5_OK = 0,                      //s5_ok
    S5_BAD_VERSION = 1,             //s5_bad_version
    S5_JUNK_DATA_IN_HANDSHAKE = 2,  //s5_junk_data_in_handshake
    S5_JUN_DATA_IN_REQUEST = 3,     //s5_jun_data_in_request
    S5_UNSUPPORTED_CMD = 4,         //s5_unsupported_cmd
    S5_BAD_ATYP = 5,                //s5_bad_atyp
    S5_BAD_UDP_REQUEST = 6,         //s5_bad_udp_request
}socks5_result_t;

typedef struct {
    socks5_state_t state;
    uint8_t arg_index;
    uint8_t arg_count;
    uint8_t methods;
    uint8_t cmd;
    uint8_t atyp;
    uint8_t dst_addr[257];//256位，多一位结束符
    uint16_t dst_port;
}socks5_info_t;

socks5_result_t socks5_parse_method_identification(socks5_info_t *socks5_info, const char *data,int size);
socks5_result_t socks5_parse_request(socks5_info_t *socks5_ctx, const char *data, int size);
socks5_result_t socks5_parse_addr_and_port(socks5_info_t *socks5_info, const char *data,int size,int is_udp_req);


#endif
