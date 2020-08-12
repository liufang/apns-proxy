CFLAGS = -g -O2 -Wall
LDFLAGS = -levent_openssl -levent_core -lssl -lcrypto

apns-proxy: adlist.h adlist.c simplog.h simplog.c apns-proxy.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	-rm -f apns-proxy
