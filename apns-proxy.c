/*
  This example code shows how to write an (optionally encrypting) SSL proxy
  with Libevent's bufferevent layer.

  XXX It's a little ugly and should probably be cleaned up.
 */

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <time.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "adlist.h"
#include "request.h"
#include "simplog.h"

static struct event_base *base;
static struct sockaddr_storage listen_on_addr;
static struct sockaddr_storage connect_to_addr;
static int connect_to_addrlen;
static const char *program_name = NULL;
static list* dataList;
static poolSockets* poolSocket;

static SSL_CTX *ssl_ctx = NULL;

static void eventcb(struct bufferevent *bev, short what, void *ctx);
static void serverWriteCallback(struct bufferevent *bev, void *ctx);

//reset request
static void resetRequest(request *r)
{
    r->data = malloc(sizeof(char) * 1024 * 5);
    r->len = r->needLen = 0;
}

//解决黏包,循环读取消息内容插入队列
static void
clientReadCallback(struct bufferevent *bev, void *ctx)
{
    request *r = ctx;
    struct evbuffer *src;
    size_t len;
    src = bufferevent_get_input(bev);

    do {
        len = evbuffer_get_length(src);
        if(len<1) break;
        //解决黏包问题确定读取长度
        size_t n = 0;
        if(r->needLen > 0) {
            n = r->needLen - r->len;
        } else {
            n = 37 - r->len;
        }
        len = bufferevent_read(bev, (r->data + r->len), n);
        r->len += len;
        //头部最少长度
        if(r->len >= 37 && r->needLen == 0) {
            //检查设置数据长度
            char *tmp = (char*)r->data;
            r->needLen = 37 + (uint16_t)(tmp[35] <<8 | tmp[36]);
        }
        //检查是否完成读取操作
        if(r->needLen == r->len) {
            simplog.writeLog(SIMPLOG_INFO, "push message to list, len: %d", r->needLen);
            listAddNodeHead(dataList, r->data);
            r->data = NULL;
            r->len = 0;
            r->needLen = 0;
            //完成当前消息读取,为下一次消息读取做准备,复位 request
            resetRequest(r);
        }
    } while(1);
}

/**
 * 写回调
 *
 * @param bev
 * @param ctx
 */
static void serverWriteCallback(struct bufferevent *bev, void *ctx)
{
    writeBuffer *wb = ctx;
    listIter* iter = listGetIterator(dataList, AL_START_TAIL);
    listNode* node;
    size_t len = 0, dataLen = 0;
    char *tmp;

    simplog.writeLog(SIMPLOG_DEBUG, "start server write callback, %s", __func__);

    do {
        //读取buffer消息写
        if(wb->totalLen > wb->writedLen) {
            len = bufferevent_get_max_to_write(bev);
            len = len < (wb->totalLen - wb->writedLen) ? len : wb->totalLen - wb->writedLen;
            //写不了 推出
            if(len < 1) {
                return;
            }

            //足够空间写入
            bufferevent_write(bev, (wb->data + wb->writedLen), len);
            wb->writedLen += len;
            //没写完返回
            if(wb->totalLen > wb->writedLen) {
                return;
            }

            //写完了进行资源回收
            free(wb->data);
            wb->data = NULL;
        }

        //读取新消息写
        if ((node = listNext(iter)) != NULL) {
            tmp = (char*)node->value;
            dataLen = 37 + (uint16_t)(tmp[35] <<8 | tmp[36]);
            simplog.writeLog(SIMPLOG_INFO, "send message len %ld", dataLen);
            //free
            if(wb->data) free(wb->data);
            //从队列弹出数据到写缓存上下文
            wb->data = node->value;
            wb->totalLen = dataLen;
            wb->writedLen = 0;
            //free
            listDelNode(dataList, node);
            continue;
        }
        //no message return
        simplog.writeLog(SIMPLOG_DEBUG, "no more message return %s", __func__);
        bufferevent_free(bev);
        poolSocket->count -= 1;
        return;
    } while(1);

}

//服务器端错误回调
static void
eventcb2(struct bufferevent *bev, short what, void *ctx)
{
    writeBuffer *wb = ctx;
    if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_ERROR) {
            unsigned long err;
            while ((err = (bufferevent_get_openssl_error(bev)))) {
                const char *msg = (const char*)
                        ERR_reason_error_string(err);
                const char *lib = (const char*)
                        ERR_lib_error_string(err);
                const char *func = (const char*)
                        ERR_func_error_string(err);
                simplog.writeLog(SIMPLOG_DEBUG,
                        "%s in %s %s\n", msg, lib, func);
            }
            if (errno)
                perror("connection error");
        }
        bufferevent_free(bev);
        if(wb->data && wb->writedLen < wb->totalLen) {
            listAddNodeHead(dataList, wb->data);
            wb->data = NULL;
        };
        free(wb);
		poolSocket->count -= 1;
    } else if(what & BEV_EVENT_CONNECTED) {
        simplog.writeLog(SIMPLOG_DEBUG, "server socket connected");
        serverWriteCallback(bev, ctx);
    } else if(what & (BEV_EVENT_READING | BEV_EVENT_WRITING)) {
        simplog.writeLog(SIMPLOG_DEBUG, "server socket write/read error");
        bufferevent_free(bev);
        if(wb->data && wb->writedLen < wb->totalLen) {
            listAddNodeHead(dataList, wb->data);
            wb->data = NULL;
        };
        free(wb);
        poolSocket->count -= 1;
    } else if(what & BEV_EVENT_TIMEOUT) {
        simplog.writeLog(SIMPLOG_DEBUG, "server socket timeout");
		bufferevent_free(bev);
		if(wb->data && wb->writedLen < wb->totalLen) {
			listAddNodeHead(dataList, wb->data);
			wb->data = NULL;
		};
        free(wb);
        poolSocket->count -= 1;
    }
}

//客户端错误回调
static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
	request *r = ctx;
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (what & BEV_EVENT_ERROR) {
			unsigned long err;
			while ((err = (bufferevent_get_openssl_error(bev)))) {
				const char *msg = (const char*)
				    ERR_reason_error_string(err);
				const char *lib = (const char*)
				    ERR_lib_error_string(err);
				const char *func = (const char*)
				    ERR_func_error_string(err);
				fprintf(stderr,
				    "%s in %s %s\n", msg, lib, func);
			}
			if (errno)
				perror("connection error");
		}

		bufferevent_free(bev);
        if(r->data) free(r->data);
        free(r);
	}
}

static void
syntax(void)
{
	fputs("Syntax:\n", stderr);
	fprintf(stderr, "   %s [-cert certificate_chain_file -key private_key_file] <listen-on-addr> <connect-to-addr>\n", program_name);
	fputs("Example:\n", stderr);
	fprintf(stderr, "   %s -d -server-connect-max 100 -cert cer.pem -key private.key 0.0.0.0:8443 17.188.137.190:2195\n", program_name);

	exit(1);
}

static void
accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *a, int slen, void *p)
{
	struct bufferevent *b_out, *b_in;
	SSL *ssl = SSL_new(ssl_ctx);

    b_in = bufferevent_socket_new(base, fd,
        BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

    //init request
    request* r = malloc(sizeof(request));
    resetRequest(r);

	bufferevent_setcb(b_in, clientReadCallback, NULL, eventcb, r);
	bufferevent_enable(b_in, EV_READ|EV_WRITE);

    //打印服务器端连接情况
    simplog.writeLog(SIMPLOG_DEBUG, "server pool max: %d, current count: %d", poolSocket->max, poolSocket->count);

    //检查初始化服务器端连接池, 当前连接小于最大连接的时候就创建连接
    if(poolSocket->count < poolSocket->max) {
		poolSocket->count += 1;

        b_out = bufferevent_openssl_socket_new(base, -1, ssl,
                                               BUFFEREVENT_SSL_CONNECTING,
                                               BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

        if (bufferevent_socket_connect(b_out,
                                       (struct sockaddr*)&connect_to_addr, connect_to_addrlen)<0) {
            simplog.writeLog(SIMPLOG_DEBUG, "bufferevent_socket_connect");
            bufferevent_free(b_out);
            return;
        }

        //init write buffer
        writeBuffer *wr = malloc(sizeof(writeBuffer));
        wr->data = NULL;
        wr->writedLen = 0;
        wr->totalLen = 0;

        bufferevent_setcb(b_out, NULL, serverWriteCallback, eventcb2, wr);
        struct timeval tv = {1,0};
        bufferevent_set_timeouts(b_out, NULL, &tv);
        bufferevent_setwatermark(b_out, EV_WRITE|EV_PERSIST, 0, 0);
        bufferevent_enable(b_out, EV_WRITE);
    }
}

static int
init_ssl(const char *certificate_chain_file, const char *private_key_file)
{
	int r;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
#define TLS_method SSLv23_method
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
#endif
	r = RAND_poll();
	if (r == 0) {
		fprintf(stderr, "RAND_poll() failed.\n");
		return 1;
	}
	ssl_ctx = SSL_CTX_new(TLS_method());
	SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv3);

	SSL_CTX_set_verify_depth(ssl_ctx, 1);
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, (void*)"123456");

	if (!SSL_CTX_use_certificate_chain_file(ssl_ctx, certificate_chain_file) ||
		!SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key_file, SSL_FILETYPE_PEM)) {
		fprintf(stderr, "Couldn't read %s or %s.\n", certificate_chain_file, private_key_file);
		return 2;
	}
	return 0;
}

//init daemon
int init_daemon(void)
{
	int pid;
	int i;

	//忽略终端I/O信号，STOP信号
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
	signal(SIGHUP,SIG_IGN);

	pid = fork();
	if(pid > 0) {
		exit(0); //结束父进程，使得子进程成为后台进程
	}
	else if(pid < 0) {
		return -1;
	}
	//建立一个新的进程组,在这个新的进程组中,子进程成为这个进程组的首进程,以使该进程脱离所有终端
	setsid();
	//再次新建一个子进程，退出父进程，保证该进程不是进程组长，同时让该进程无法再打开一个新的终端
	pid=fork();
	if( pid > 0) {
		exit(0);
	}
	else if( pid< 0) {
		return -1;
	}

	//关闭所有从父进程继承的不再需要的文件描述符
	for(i=0;i< NOFILE;close(i++));
	//改变工作目录，使得进程不与任何文件系统联系
	//chdir("/");
	//将文件当时创建屏蔽字设置为0
	umask(0);
	//忽略SIGCHLD信号
	signal(SIGCHLD,SIG_IGN);
	return 0;
}

//写入pid file
int write_pid_file(const char *pidfile)
{
    int pidfd = 0;
    char val[16];
    int len = snprintf(val, sizeof(val), "%"PRIuMAX"\n", (uintmax_t)getpid());
    if(len<0) {
        simplog.writeLog(SIMPLOG_ERROR, "pid error (%s)", strerror(errno));
        return -1;
    }

    pidfd = open(pidfile,  O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
    if(pidfd < 0) {
        simplog.writeLog(SIMPLOG_ERROR, "unable to set pidfile '%s': %s", pidfile, strerror(errno));
        return -1;
    }

    size_t r = write(pidfd, val, (unsigned int)len);
    if(r == -1 || r != len) {
        simplog.writeLog(SIMPLOG_ERROR, "unable to write pidfile '%s': %s", pidfile, strerror(errno));
        close(pidfd);
        return -1;
    }

    close(pidfd);
    return(0);
}

int
main(int argc, char **argv)
{
	int i;
	int socklen;
    int daemon = 0, server_max_connect = 1;
	const char *certificate_chain_file = NULL;
	const char *private_key_file = NULL;

	struct evconnlistener *listener;

	program_name = argv[0];

    simplog.writeLog(SIMPLOG_INFO, "start apns proxy server");

	if (argc < 3)
		syntax();

	for (i=1; i < argc; ++i) {
        if (!strcmp(argv[i], "-server-connect-max")) {
            if (i + 1 >= argc) {
                syntax();
            }
            server_max_connect = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "-d")) {
            //守护进程方式运行
            daemon = 1;
            simplog.writeLog(SIMPLOG_DEBUG, "arg daemon");
        } else if (!strcmp(argv[i], "-cert")) {
			if (i + 1 >= argc) {
				syntax();
			}
			certificate_chain_file = argv[++i];
		} else if (!strcmp(argv[i], "-key")) {
			if (i + 1 >= argc) {
				syntax();
			}
			private_key_file = argv[++i];
		} else if (argv[i][0] == '-') {
			syntax();
		} else
			break;
	}


	if (i+2 != argc)
		syntax();

    if(daemon) {
        init_daemon();
    }
    write_pid_file("apns-proxy.pid");

    //init data list
    dataList = listCreate();
    //init pool sockets
    poolSocket = malloc(sizeof(poolSockets));
    poolSocket->count = 0;
    poolSocket->max = server_max_connect;

	memset(&listen_on_addr, 0, sizeof(listen_on_addr));
	socklen = sizeof(listen_on_addr);
	if (evutil_parse_sockaddr_port(argv[i],
		(struct sockaddr*)&listen_on_addr, &socklen)<0) {
		int p = atoi(argv[i]);
		struct sockaddr_in *sin = (struct sockaddr_in*)&listen_on_addr;
		if (p < 1 || p > 65535)
			syntax();
		sin->sin_port = htons(p);
		//这里需要设置正确的服务器地址
		sin->sin_addr.s_addr = htonl(0x7f000001);
		sin->sin_family = AF_INET;
		socklen = sizeof(struct sockaddr_in);
	}

	memset(&connect_to_addr, 0, sizeof(connect_to_addr));
	connect_to_addrlen = sizeof(connect_to_addr);
	if (evutil_parse_sockaddr_port(argv[i+1],
		(struct sockaddr*)&connect_to_addr, &connect_to_addrlen)<0)
		syntax();

	base = event_base_new();
	if (!base) {
        simplog.writeLog(SIMPLOG_ERROR, "create event base error");
		return 1;
	}

    if (init_ssl(certificate_chain_file, private_key_file) != 0) {
		return 1;
	}

	listener = evconnlistener_new_bind(base, accept_cb, NULL,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr*)&listen_on_addr, socklen);

	if (! listener) {
		simplog.writeLog(SIMPLOG_ERROR, "Couldn't open listener.");
		event_base_free(base);
		return 1;
	}
	event_base_dispatch(base);

	evconnlistener_free(listener);
	event_base_free(base);

	return 0;
}
