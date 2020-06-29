cmake_minimum_required(VERSION 3.10)
project(socks5_dev C)

set(CMAKE_C_STANDARD 99)

#################################
#编译环境：
#libuv版本 ：1.18.0    offical-site: https://github.com/libuv/libuv
#logger版本：0.1.0     logger-site: https://github.com/shiffthq/logger
#################################


add_executable(socks5_dev
        main.c main.h resolve.c resolve.h defs.h session.c session.h socks5.c socks5.h callback.c callback.h logger.c logger.h)

#Openssl
#find_package(OpenSSL REQUIRED)
#target_link_libraries(socks5_dev OpenSSL::SSL)

#添加编译选项
TARGET_LINK_LIBRARIES(socks5_dev uv)
set(CMAKE_C_FLAGS_DEBUG "-luv")

#curl --socks5 127.0.0.1:1080 https://baidu.com/
