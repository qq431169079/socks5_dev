
#include <stdio.h>
#include "socks5.h"
#include "logger.h"


/**
 * 创建与socks5服务器的TCP连接后，客户端需要先发送请求来协商版本及认证方式，格式为：
 * +-------------+--------------+--------------+
 * |   VER       +    NMETHODS  |   METHODS    |
 * +-------------+--------------+--------------+
 * |     1       +       1      |   1 to 255   |
 * +-------------+--------------+--------------+
 * VER：socks版本（在socks5中是0x05）；
 * NMETHODS：在METHODS字段中出现的方法的数目；
 * METHODS：客户端支持的认证方式列表，每个方法占1字节。
 * @param socks5_info
 * @param data
 * @param size
 * @return
 */

socks5_result_t socks5_parse_method_identification(socks5_info_t *socks5_info, const char *data,int size)
{

    socks5_info->state = VERSION;
    int i = 0;

    //验证socks5
    while(i < size)
    {
        unsigned char da = (unsigned char) data[i];
        switch(socks5_info->state){

            //验证版本VERSION
            case VERSION:

                if (da != SOCKS5_VERSION){
                    logger_error("socks version bad\n");
                    return S5_BAD_VERSION;
                }
                socks5_info->state = NMETHODS;
                break;
            //验证在METHODS字段中出现的方法的数目
            case NMETHODS:
                socks5_info->arg_index = 0;
                socks5_info->arg_count = da;
                socks5_info->state = METHODS;
                break;
            //验证客户端支持的认证方式列表，每个方法占1字节。
            case METHODS:
                switch(da)
                {
                    case 0:
                        socks5_info->methods |=S5_AUTH_NONE;
                        break;
                    case 1:
                        socks5_info->methods |=S5_AUTH_GSSAPI;
                        break;
                    case 2:
                        socks5_info->methods |=S5_AUTH_PASSWD;
                        break;
                    default:
                        break;
                }
                if (++socks5_info->arg_index == socks5_info->arg_count){
                    socks5_info->state = FINISH;
                }
                break;
            case FINISH:
                logger_error("junk in handshake: %d - %d", i + 1, size);
                return S5_JUNK_DATA_IN_HANDSHAKE;
                break;
            default:
                break;
        }
        ++i;
    }
    return S5_OK;
}


/**
 * 封装请求
 * 　+----+-----+-------+------+----------+----------+
 *　|VER  | CMD |　RSV　| ATYP | DST.ADDR   | DST.PORT  |
 *　+----+-----+-------+------+----------+----------+
 *　| 1　 | 　1 | X'00' | 　1　| Variable |　　 2　　  |
 *　+----+-----+-------+------+----------+----------+
 *封装客户端请求
 * @param socks5_ctx
 * @param data
 * @param size
 * @return
 */

socks5_result_t socks5_parse_request(socks5_info_t *socks5_ctx, const char *data, int size){
    socks5_ctx->state = REQ_VERSION;

    int i = 0;
    while (i <size)
    {
        unsigned char da = (unsigned char) data[i];
        ++i;
        switch (socks5_ctx->state)
        {
            case REQ_VERSION:
                if (da != SOCKS5_VERSION) {
                    logger_error("bad version: %d", da);
                    return S5_BAD_VERSION;
                }
                socks5_ctx->state = REQ_CMD;
                break;
            case REQ_CMD:
                if (da!= S5_CMD_CONNECT && da != S5_CMD_UDP_ASSOCIATE){
                    logger_error("unsuppord cmd : %d",da);
                    return S5_UNSUPPORTED_CMD;
                }
                socks5_ctx->cmd = da;
                socks5_ctx->state = REQ_RSV;
                break;
            case REQ_RSV:
                //指针右移i位，size减小i位
                return socks5_parse_addr_and_port(socks5_ctx,data + i,size - i,0);
            default:
                break;
        }

    }
    return S5_OK;
}


socks5_result_t socks5_parse_addr_and_port(socks5_info_t *socks5_info, const char *data,int size,int is_udp_req){

    /**
     * REQ_ATYP
     * IP V4 address: X'01'
　   * DOMAINNAME: X'03'
　   * IP V6 address: X'04'
     */
    socks5_info->state = REQ_ATYP;
    int i = 0;
    while (i < size){
        unsigned char da = (unsigned char) data[i];
        ++i;
        switch (socks5_info->state)
        {
            case REQ_ATYP:
                socks5_info->atyp = da;
                socks5_info->arg_index = 0;
                if (da == S5_ATYP_IPV4)
                {
                    //该地址是IPv4地址，长4个八位组。
                    socks5_info->arg_count = 4;
                    socks5_info->state = REQ_DST_ADDR;
                } else if (da == S5_ATYP_DOMAIN){
                    socks5_info->state = REQ_DST_ADDR_LEN;
                } else if (da == S5_ATYP_IPV6) {
                    //该地址是IPv6地址，长16个八位组。
                    socks5_info->arg_count = 16;
                    socks5_info->state = REQ_DST_ADDR;
                } else{
                    printf("bad atyp %d \n",da);
                    return S5_BAD_ATYP;
                }
                break;
            case REQ_DST_ADDR_LEN:
                socks5_info->arg_index = 0;
                socks5_info->arg_index = da;
                socks5_info->state = REQ_DST_ADDR;
                break;
            case REQ_DST_ADDR:
                socks5_info->dst_addr[socks5_info->arg_index] = da;

                if (++socks5_info->arg_index == socks5_info->arg_count){
                    socks5_info->dst_addr[socks5_info->arg_index] = '\0';
                    socks5_info->state = REQ_DST_PORT;
                    socks5_info->arg_index = 0;
                    socks5_info->arg_count = 2;//port占用2byte
                }
                break;
            case REQ_DST_PORT:
                if (socks5_info->arg_index == 0) {
                    socks5_info->dst_port = da << 8;
                    ++socks5_info->arg_index;
                } else{
                    socks5_info->dst_port |=da;
                    if (is_udp_req)
                    {
                        return S5_OK;
                    }
                    socks5_info->state = FINISH;
                }
                break;
            case FINISH:
                logger_error("junk in handshake: %d - %d",i+1,size);
                return S5_JUN_DATA_IN_REQUEST;
                break;
            default:
                break;
        }
    }
    return S5_OK;

}
