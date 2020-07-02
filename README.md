
**socks5协议支持**

RFC地址：

Ⅰ.[socks5协议规范rfc1928](https://www.ietf.org/rfc/rfc1928.txt)

Ⅱ.[socks5账号密码鉴权规范rfc1929](https://www.ietf.org/rfc/rfc1929.txt)


**socks5代理服务基本过程**


**1.认证过程**

客户端发送认证信息给代理服务器

**2.命令过程**

认证成功后，客户端会发送连接命令给代理服务器，代理服务器会连接目标服务器，并返回连接结果

**3.通信过程**

经过认证与命令过程后，客户端与代理服务器进入正常通信，客户端发送需要请求到目标服务器的数据给代理服务器，代理服务器转发这些数据，并把目标服务器的响应转发给客户端，起到一个“透明代理”的功能。

默认请求地址：127.0.0.1:1082，根据需求，请在main.c文件中自行更改，此处无getopt()选项处理方式

**测试：**

测试命令：`curl --socks5 127.0.0.1:1082 https://example.com`

测试环境：Ubuntu 18.04, Ubuntu 16.04,   Debian 7



libuv版本 ：1.18.0    
https://github.com/libuv/libuv

logger版本：0.1.0     
https://github.com/shiffthq/logger