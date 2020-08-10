# apns-proxy
A apple apns proxy using libevent.

This is a fork of [le-proxy.c](https://github.com/libevent/libevent/blob/master/sample/le-proxy.c)
from [libevent](https://github.com/libevent/libevent).

# Build

libevent and OpenSSL are required. On Ubuntu, you can install them using the code below:

```
sudo apt-get install libevent-dev libssl-dev
```

Then just type `make` to build.

# Usage

./apns-proxy -cert xx.pem -key xx.pem 0.0.0.0:8443 17.188.129.31:2195
