//
// Created by fang on 20-8-9.
//

#ifndef SSL_PROXY_REQUEST_H
#define SSL_PROXY_REQUEST_H

typedef struct request {
    void *data; //数据指针
    int len; //已经读取的长度
    int needLen; //总长度
} request;

//服务器端socket连接池
typedef struct poolSockets {
    int count;
    int max;
} poolSockets;

/**
 * 服务器端写入缓存
 */
typedef struct writeBuffer {
    void *data;
    int totalLen;
    int writedLen;
} writeBuffer;

#endif //SSL_PROXY_REQUEST_H
