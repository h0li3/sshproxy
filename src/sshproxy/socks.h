#pragma once
#include <libssh2.h>

#define SOCKS5_STAGE_GREETING 0
#define SOCKS5_STAGE_REQUEST 1
#define SOCKS5_STAGE_CONNECT 2

#define SOCKS5_VERSION 5
#define SOCKS5_NO_AUTH 0

#define SOCKS5_CMD_CONNECT 1
#define SOCKS5_CMD_BIND 2
#define SOCKS5_CMD_UDP 3

#define SOCKS5_ADDR_IPv4 1
#define SOCKS5_ADDR_DOMAIN  3
#define SOCKS5_ADDR_IPv6 4

#define SOCKS5_REP_SUCCEEDED 0
#define SOCKS5_REP_GENFAIL 1
#define SOCKS5_REP_NOT_ALLOWED 2
#define SOCKS5_REP_NETWORK_UNREACHABLE 3
#define SOCKS5_REP_HOST_UNREACHABLE 4
#define SOCKS5_REP_CONN_REFUSED 5
#define SOCKS5_REP_TTL_EXPIRED 6
#define SOCKS5_REP_CMD_NOT_SUPPORTED 7
#define SOCKS5_REP_ADDR_NOT_SUPPORTED 8

typedef struct socks5_greeting_t {
    uint8_t version;
    uint8_t nmethods;
    uint8_t methods[255];
} socks5_greeting_t;

typedef struct socks5_request_t {
    uint8_t version;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
    uint8_t dstaddr[255];
    uint16_t dstport;
} socks5_request_t;

typedef struct socks5_reply_t {
    uint8_t version;
    uint8_t code;
    uint8_t rsv;
    uint8_t atyp;
    uint32_t ipv4;
    uint16_t port;
} socks5_reply_t;
