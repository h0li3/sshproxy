/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <libssh2.h>

#ifdef WIN32
#include <ws2tcpip.h>   
#define recv(s, b, l, f)  recv((s), (b), (int)(l), (f))
#define send(s, b, l, f)  send((s), (b), (int)(l), (f))
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "socks.h"

static char recv_buf[4096];

enum {
    AUTH_NONE = 0,
    AUTH_PASSWORD = 1,
    AUTH_PUBLICKEY = 2,
    AUTH_KBDINT = 3
};

enum SSHPROXY_DBG_LEVEL {
    SSHPROXY_DBG_ERR,
    SSHPROXY_DBG_INF,
    SSHPROXY_DBG_DBG,
};

typedef struct socks_server_t
{
    LIBSSH2_POLLFD* fds;
    int fds_array_size;
    int fds_num;
    LIBSSH2_SESSION* ssh_session;
    LIBSSH2_LISTENER* ssh_listener;
    const char* password;
    int remote_listenport;

} socks_server_t;

typedef int (*poll_callback_t)(LIBSSH2_POLLFD* fd);

#define POLLFD_EXECUTE_CALLBACK(fd) ((poll_callback_t)(fd)->callback)(fd)

#define POLLFD_ADDR_TO_INDEX(addr) ((int)((addr - socks_server.fds)))

LIBSSH2_POLLFD* add_poll(int type, void* fd, int events, void* user_data, poll_callback_t cb);

static socks_server_t socks_server;
static enum SSHPROXY_DBG_LEVEL dbg_level;
static CRITICAL_SECTION dbg_lock;

#ifdef _DEBUG
static void __dbgprint_internal(const char* format, enum SSHPROXY_DBG_LEVEL level, va_list args)
{
#define BUF_SIZE 2000
    static char fmt_buf[BUF_SIZE + 100];
    char time_str[32];

    if (level > dbg_level) {
        return;
    }

    assert(strlen(format) < BUF_SIZE);

    struct tm t;
    SYSTEMTIME st;
    GetLocalTime(&st);
    t.tm_year = st.wYear - 1900;
    t.tm_mon = st.wMonth - 1;
    t.tm_mday = st.wDay;
    t.tm_hour = st.wHour;
    t.tm_min = st.wMinute;
    t.tm_sec = st.wSecond;
    t.tm_isdst = -1;
    strftime(time_str, 32, "%Y/%m/%d %H:%M:%S", &t);

    const char* level_name = NULL;
    switch (level) {
    case SSHPROXY_DBG_ERR:
        level_name = "ERR";
        break;
    case SSHPROXY_DBG_INF:
        level_name = "INF";
        break;
    case SSHPROXY_DBG_DBG:
        level_name = "DBG";
        break;
    }

    EnterCriticalSection(&dbg_lock);
    sprintf_s(fmt_buf, BUF_SIZE + 100, "[%s.%03u] %s - %s \n", time_str, st.wMilliseconds, level_name, format);
    vprintf(fmt_buf, args);
    LeaveCriticalSection(&dbg_lock);
}

static void dbg_init(enum SSHPROXY_DBG_LEVEL level)
{
    InitializeCriticalSection(&dbg_lock);
    dbg_level = level;
}

static void dbg_println(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    __dbgprint_internal(format, SSHPROXY_DBG_DBG, args);
    va_end(args);
}

static void err_println(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    __dbgprint_internal(format, SSHPROXY_DBG_ERR, args);
    va_end(args);
}

static void info_println(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    __dbgprint_internal(format, SSHPROXY_DBG_INF, args);
    va_end(args);
}
#else
#define dbg_init(x) do{} while (0)
#define dbg_println(x, ...) do{} while(0)
#define err_println(x, ...) do{} while(0)
#define info_println(x, ...) do{} while(0)
#endif

#ifndef _WIN32
static int closesocket(int sock)
{
    return close(sock);
}
#endif

static LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC(keyboard_int_callback)
{
    if (responses == NULL) {
        return;
    }

    size_t length = strlen(socks_server.password);
    responses[0].length = (unsigned)length;
    responses[0].text = malloc(length);
    if (!responses[0].text) {
        return;
    }
    memcpy(responses[0].text, socks_server.password, length);
}

static LIBSSH2_POLLFD* add_poll(int type, void* fd, int events, void* user_data, poll_callback_t cb)
{
    if (socks_server.fds_num == socks_server.fds_array_size) {
        err_println("socks server poll array is full (%d)", socks_server.fds_num);
        return NULL;
    }
    LIBSSH2_POLLFD* pf = &socks_server.fds[socks_server.fds_num++];
    pf->type = type;
    pf->events = events;
    *(size_t*)&pf->fd.channel = (size_t)fd;
    pf->user_data = user_data;
    pf->callback = cb;

    return pf;
}

static void socks_stop_relay(LIBSSH2_POLLFD* pf)
{
    LIBSSH2_POLLFD* ssh_node = NULL, * sock_node = NULL;

    if (pf->type == LIBSSH2_POLLFD_CHANNEL) {
        ssh_node = pf;
        sock_node = (LIBSSH2_POLLFD*)ssh_node->user_data;
        if (sock_node && sock_node->user_data != pf) {
            sock_node = NULL;
        }
    }
    else {
        sock_node = pf;
        ssh_node = (LIBSSH2_POLLFD*)sock_node->user_data;
        if (ssh_node && ssh_node->user_data != pf) {
            ssh_node = NULL;
        }
    }

    if (ssh_node) {
        if (ssh_node->fd.channel) {
            libssh2_channel_free(ssh_node->fd.channel);
        }
        ssh_node->events = 0;
    }
    if (sock_node) {
        if (sock_node->fd.socket != LIBSSH2_INVALID_SOCKET) {
            int rc = closesocket(sock_node->fd.socket);
        }
        sock_node->events = 0;
    }
}

static int socks_relay_tcp_cb(LIBSSH2_POLLFD* pf)
{
    LIBSSH2_POLLFD* ssh_node = (LIBSSH2_POLLFD*)pf->user_data;
    libssh2_socket_t sock = pf->fd.socket;

    if (ssh_node->user_data != pf) {
        goto cleanup;
    }

    // TODO: make sure all data is handled.
    ssize_t n = recv(sock, recv_buf, 4096, 0);
    if (n > 0) {
        ssize_t n1 = libssh2_channel_write_ex(ssh_node->fd.channel, 0, recv_buf, n);
        if (n1 != n) {
            err_println("read != write: r=%lu w=%lu bytes\n", n, n1);
        }
        if (n1 > 0) {
            return 0;
        }

        libssh2_channel_send_eof(ssh_node->fd.channel);
        libssh2_channel_flush_ex(ssh_node->fd.channel, 0);
    }

cleanup:
    dbg_println("stop ssh channel relay due to the socket being closed.");
    socks_stop_relay(pf);
    return -1;
}

static int socks_relay_ssh_cb(LIBSSH2_POLLFD* pf)
{
    LIBSSH2_POLLFD* sock_node = (LIBSSH2_POLLFD*)pf->user_data;
    LIBSSH2_CHANNEL* channel = pf->fd.channel;

    if (sock_node->user_data != pf) {
        goto cleanup;
    }

    ssize_t n = libssh2_channel_read_ex(channel, 0, recv_buf, 4096);
    if (n > 0) {
        n = send(sock_node->fd.socket, recv_buf, n, 0);
        if (n > 0) {
            return 0;
        }
    }

cleanup:
    dbg_println("stop ssh channel relay due to the channel being closed.");
    socks_stop_relay(pf);
    return -1;
}

static int socks_connect_cb(LIBSSH2_POLLFD* sock_node)
{
    socks5_reply_t resp_buf;
    BOOL reject = TRUE;
    struct sockaddr_in sin;
    LIBSSH2_POLLFD* ssh_node = (LIBSSH2_POLLFD*)sock_node->user_data;

    resp_buf.version = SOCKS5_VERSION;
    resp_buf.code = ERROR_GEN_FAILURE;
    resp_buf.rsv = 0;
    resp_buf.atyp = SOCKS5_ADDR_IPv4;

    if (sock_node->revents & LIBSSH2_POLLFD_POLLEX) {
        int error = 0;
        int len = sizeof(error);
        if (0 == getsockopt(sock_node->fd.socket, SOL_SOCKET, SO_ERROR, (char*)&error, &len)) {
            if (error == WSAENETUNREACH) {
                resp_buf.code = SOCKS5_REP_NETWORK_UNREACHABLE;
            }
            else if (error == WSAECONNREFUSED) {
                resp_buf.code = SOCKS5_REP_CONN_REFUSED;
            }
        }
        reject = TRUE;
    }
    else if (sock_node->revents & LIBSSH2_POLLFD_POLLOUT) {
        socklen_t slen = sizeof(sin);
#ifdef _DEBUG
        if (getpeername(sock_node->fd.socket, (struct sockaddr*)&sin, &slen) == 0) {
            dbg_println("has connected to the target %s:%u", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
        }
#endif
        if (getsockname(sock_node->fd.socket, (struct sockaddr*)&sin, &slen) == SOCKET_ERROR) {
            err_println("getsockname() failed: %lu", WSAGetLastError());
        }
        else {
            resp_buf.ipv4 = sin.sin_addr.s_addr;
            resp_buf.port = sin.sin_port;
            sock_node->callback = socks_relay_tcp_cb;
            sock_node->events = LIBSSH2_POLLFD_POLLIN;
            resp_buf.code = SOCKS5_REP_SUCCEEDED;
            reject = FALSE;
        }
    }

    libssh2_channel_write_ex(ssh_node->fd.channel, 0, (char*)&resp_buf, 10);
    libssh2_channel_flush_ex(ssh_node->fd.channel, 0);

    if (reject) {
        socks_stop_relay(sock_node);
        return -1;
    }

    return 0;
}

static int socks_request_cb(LIBSSH2_POLLFD* pf)
{
    int reject = TRUE, code = SOCKS5_REP_GENFAIL;
    ssize_t nbytes = 0;
    libssh2_socket_t sock = LIBSSH2_INVALID_SOCKET;
    struct sockaddr_in sin;
    socklen_t sinlen = sizeof(sin);
    char buf[280];
    socks5_reply_t* reply = (socks5_reply_t*)buf;
    LIBSSH2_CHANNEL* channel = pf->fd.channel;
    LIBSSH2_POLLFD* new_fd;

    nbytes = libssh2_channel_read_ex(channel, 0, buf, 280);
    int len = buf[4];
    if (nbytes < 8 || buf[0] != SOCKS5_VERSION || buf[1] != SOCKS5_CMD_CONNECT) {
        err_println("invalid socks request header of %d bytes, ver=%u, cmd=%u", nbytes, buf[0], buf[1]);
        goto _cleanup;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;

    char atype = buf[3];
    if (atype == SOCKS5_ADDR_IPv4 && nbytes == 4 + 4 + 2) {
        sin.sin_addr.s_addr = *(int*)(buf + 4);
        sin.sin_port = *(short*)(buf + 8);
    }
    else if (atype == SOCKS5_ADDR_DOMAIN && len > 0 && len < 256) {
        sin.sin_port = *(short*)(buf + 5 + len);
        char* host = buf + 4 + 1;
        host[len] = 0;
        struct hostent* hent = gethostbyname(host);
        if (!hent) {
            code = SOCKS5_REP_HOST_UNREACHABLE;
            goto _response;
        }
        sin.sin_addr.s_addr = *(int*)hent->h_addr_list[0];
    }
    else {
        code = SOCKS5_REP_ADDR_NOT_SUPPORTED;
    }

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == LIBSSH2_INVALID_SOCKET) {
        err_println("failed to create socket: %lu", WSAGetLastError());
        code = SOCKS5_REP_GENFAIL;
        goto _response;
    }

    int opt = 1;
    if (ioctlsocket(sock, FIONBIO, &opt) != 0) {
        err_println("failed to set socket to non-blocking: %lu", WSAGetLastError());
        code = SOCKS5_REP_GENFAIL;
        goto _response;
    }
    {
        char opt = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }

    dbg_println("connecting to the target %s:%u", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
    
    if (connect(sock, (struct sockaddr*)&sin, sizeof(sin)) == -1
            && WSAGetLastError() != WSAEWOULDBLOCK) {
        err_println("failed to connect the target: %d", WSAGetLastError());
        closesocket(sock);
        code = SOCKS5_REP_NETWORK_UNREACHABLE;
        goto _response;
    }

    new_fd = add_poll(LIBSSH2_POLLFD_SOCKET,
        (void*)(size_t)sock, LIBSSH2_POLLFD_POLLOUT | LIBSSH2_POLLFD_POLLEX, pf, socks_connect_cb);
    if (new_fd) {
        pf->user_data = new_fd;
        pf->callback = socks_relay_ssh_cb;
        reject = FALSE;
        code = SOCKS5_REP_SUCCEEDED;
        // the response will be sent in socks_connect_cb()
        goto _cleanup;
    }
    else {
        code = SOCKS5_REP_GENFAIL;
    }

_response:
    reply->version = SOCKS5_VERSION;
    reply->code = code;
    reply->rsv = 0;
    reply->atyp = SOCKS5_ADDR_IPv4;
    reply->ipv4 = 0;
    reply->port = 0;
    libssh2_channel_write_ex(channel, 0, buf, 10);
    libssh2_channel_flush_ex(channel, 0);

_cleanup:
    if (reject) {
        libssh2_channel_free(channel);
        if (sock != LIBSSH2_INVALID_SOCKET) {
            closesocket(sock);
        }
        return -1;
    }

    return 0;
}

static int socks_handshake_cb(LIBSSH2_POLLFD* pf)
{
    char buf[10];
    ssize_t nbytes;
    BOOL reject = TRUE;
    LIBSSH2_CHANNEL* channel = pf->fd.channel;

    nbytes = libssh2_channel_read_ex(channel, 0, buf, 10);
    if (nbytes < 3 || buf[0] != SOCKS5_VERSION || buf[1] > 8) {
        err_println("invalid socks5 handshake header of %d bytes, ver=%u, methods=%u.", nbytes, buf[0], buf[1]);
        goto _end;
    }
    for (int n = 0; n < buf[1]; ++n) {
        if (buf[n + 2] == SOCKS5_NO_AUTH) {
            buf[0] = SOCKS5_VERSION;
            buf[1] = SOCKS5_NO_AUTH;
            nbytes = libssh2_channel_write_ex(channel, 0, buf, 2);
            if (nbytes == 2) {
                libssh2_channel_flush_ex(channel, 0);
                reject = FALSE;
                goto _end;
            }
        }
    }

_end:
    if (reject) {
        libssh2_channel_free(channel);
        return -1;
    }

    pf->callback = socks_request_cb;
    return 0;
}

static int accept_channel_cb(LIBSSH2_POLLFD* pf)
{
    LIBSSH2_CHANNEL* channel = NULL;
    channel = libssh2_channel_forward_accept(pf->fd.listener);

    if (!channel) {
        err_println("failed to accept new channel: %d.", libssh2_session_last_errno(socks_server.ssh_session));
        return -1;
    }

    if (!add_poll(LIBSSH2_POLLFD_CHANNEL, channel, LIBSSH2_POLLFD_POLLIN, NULL, socks_handshake_cb)) {
        libssh2_channel_free(channel);
        return -1;
    }

    return 0;
}

static int ssh_forward_listen(LIBSSH2_SESSION* session, int port)
{
    int bound_port = -1;
    LIBSSH2_LISTENER* listener = NULL;
    listener = libssh2_channel_forward_listen_ex(session, NULL, port, &bound_port, 32);
    if (listener == NULL) {
        dbg_println("failed to bind ssh forward port: %d.", libssh2_session_last_errno(session));
        return -1;
    }
    info_println("server is listening on port %u.", bound_port);
    socks_server.ssh_listener = listener;
    return 0;
}

static int ssh_loop(LIBSSH2_SESSION* session, int fwd_port)
{
    int rc = 0;
    int nfds;

    socks_server.ssh_session = session;
    if (ssh_forward_listen(session, fwd_port)) {
        return -1;
    }

    socks_server.fds_num = 0;
    socks_server.fds_array_size = 1024;
    socks_server.fds = (LIBSSH2_POLLFD*)malloc(sizeof(LIBSSH2_POLLFD) * socks_server.fds_array_size);
    if (!socks_server.fds) {
        err_println("out of memory.");
        goto shutdown;
    }
    memset(socks_server.fds, 0, sizeof(LIBSSH2_POLLFD) * socks_server.fds_array_size);

    libssh2_session_set_blocking(session, 0);
    add_poll(LIBSSH2_POLLFD_LISTENER, socks_server.ssh_listener, LIBSSH2_POLLFD_POLLIN, NULL, accept_channel_cb);

    while (1) {
#if _DEBUG
        if (socks_server.fds_num > 800) {
            dbg_println("status of the fds array usage: %d / %d", socks_server.fds_num, socks_server.fds_array_size);
        }
#endif
        nfds = libssh2_poll((LIBSSH2_POLLFD*)socks_server.fds, socks_server.fds_num, 5000);
        if (nfds == -1) {
            err_println("libssh2_poll() failed.");
            break;
        }
        else if (nfds == 0) {
            // TODO: When the select() times out, iterate through the fds array to clean up any invalid nodes.
            continue;
        }

        for (int i = 0; i < socks_server.fds_num; ++i) {
            LIBSSH2_POLLFD* pf = &socks_server.fds[i];

            if (pf->revents) {
                if (pf->revents & LIBSSH2_POLLFD_CHANNEL_EOF) {
                    dbg_println("stop relay due to the channel has been closed");
                    socks_stop_relay(pf);
                }
                else {
                    if (POLLFD_EXECUTE_CALLBACK(pf) == -1) {
                        if (pf->type == LIBSSH2_POLLFD_LISTENER) {
                            goto shutdown;
                        }
                        pf->events = 0;
                    }
                }
            }
        }

        for (int i = 0; i < socks_server.fds_num; ++i) {
            LIBSSH2_POLLFD* pf = &socks_server.fds[i];

            if (pf->events == 0 && pf->fd.socket != 0) {
                dbg_println("remove a poll fd node (type=%d) at <%d>", pf->type, i);
                LIBSSH2_POLLFD* peer = (LIBSSH2_POLLFD*)pf->user_data;
                if (peer) {
                    peer->user_data = NULL;
                }

                LIBSSH2_POLLFD* last = &socks_server.fds[--socks_server.fds_num];
                if (pf != last) {
                    *pf = *last;
                    i = i - 1;
                    peer = (LIBSSH2_POLLFD*)last->user_data;
                    if (peer && peer != pf && peer->events) {
                        dbg_println("update node:<%d>'s peer node:<%d> to <%d>", POLLFD_ADDR_TO_INDEX(peer), POLLFD_ADDR_TO_INDEX((LIBSSH2_POLLFD*)peer->user_data), POLLFD_ADDR_TO_INDEX(pf));
                        peer->user_data = pf;
                    }
                }
                last->callback = 0;
                last->fd.channel = 0;
                last->revents = 0;
            }
        }
    }

shutdown:
    libssh2_session_set_blocking(session, 1);
    libssh2_channel_forward_cancel(socks_server.ssh_listener);
    free(socks_server.fds);
    return rc;
}

static int ssh_login(LIBSSH2_SESSION* session, const char* username, const char* password)
{
    int rc, auth = AUTH_NONE;
    char* userauthlist;

    /* check what authentication methods are available */
    userauthlist = libssh2_userauth_list(session, username,
        (unsigned int)strlen(username));

    if (userauthlist) {
        info_println("authentication methods: %s.", userauthlist);
        if (strstr(userauthlist, "keyboard"))
            auth |= AUTH_KBDINT;
        if (strstr(userauthlist, "password"))
            auth |= AUTH_PASSWORD;
        //if (strstr(userauthlist, "publickey"))
            //auth |= AUTH_PUBLICKEY;

        if (auth & AUTH_KBDINT) {
            socks_server.password = password;
            if (libssh2_userauth_keyboard_interactive(session, username, keyboard_int_callback)) {
                err_println("authentication by keyboard interact failed.");
            }
            else {
                goto auth_ok;
            }
        }
        if (auth & AUTH_PASSWORD) {
            if (libssh2_userauth_password(session, username, password)) {
                err_println("authentication by password failed.");
            }
            else {
                goto auth_ok;
            }
        }
        /*if (auth & AUTH_PUBLICKEY) {
            if (libssh2_userauth_publickey_frommemory(session, username, strlen(username),
                NULL, 0, private_key, strlen(private_key), NULL
            )) {
                dbgprint("Authentication by public key failed.");
            }
            else {
                dbgprint("Authentication by public key succeeded.");
                goto auth_ok;
            }
        }*/
        else {
            err_println("no supported authentication methods found.");
        }
    }

    rc = LIBSSH2_ERROR_AUTHENTICATION_FAILED;

auth_ok:
    return 0;
}

static int ssh_connect(LIBSSH2_SESSION** session, libssh2_socket_t* _sock, const char* server, int port)
{
    int rc = -1;
    libssh2_socket_t sock;
    struct sockaddr_in sin;
    socklen_t sinlen = sizeof(sin);

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == LIBSSH2_INVALID_SOCKET) {
        err_println("failed to create socket: %lu.", WSAGetLastError());
        goto shutdown;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(server);
    if (INADDR_NONE == sin.sin_addr.s_addr) {
        err_println("incorrect IP address: %s.", server);
        goto shutdown;
    }
    sin.sin_port = htons(22);
    if (connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in))) {
        err_println("failed to connect to %s:%u.", server, port);
        goto shutdown;
    }

    /* Create a session instance */
    *session = libssh2_session_init();

    if (!*session) {
        err_println("could not initialize SSH session.");
        goto shutdown;
    }

    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
    rc = libssh2_session_handshake(*session, sock);

    if (rc) {
        err_println("error when starting up SSH session: %d.", rc);
        goto shutdown;
    }

    *_sock = sock;

    return 0;

shutdown:
    if (sock != LIBSSH2_INVALID_SOCKET) {
        shutdown(sock, 2);
#ifdef WIN32
        closesocket(sock);
#else
        close(sock);
#endif
    }

    return rc;
}

static int ssh_init()
{
#ifdef WIN32
    WSADATA wsadata;

    int rc = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if (rc) {
        err_println("WSAStartup() failed with error: %d.", rc);
        return 1;
    }
#endif

    rc = libssh2_init(0);
    if (rc) {
        err_println("libssh2 initialization failed: %d.", rc);
        return 1;
    }

    return 0;
}

static int ssh_main(const char* server, int ssh_port, int fwd_port, const char* username, const char* password)
{
    LIBSSH2_SESSION* session = NULL;
    libssh2_socket_t server_sock = LIBSSH2_INVALID_SOCKET;

    if (ssh_init()) {
        return -1;
    }

    if (ssh_connect(&session, &server_sock, server, ssh_port)) {
        return -1;
    }

    if (ssh_login(session, username, password)) {
        goto shutdown;
    }

    if (ssh_loop(session, fwd_port)) {
        err_println("ran ssh proxy loop failed.");
    }

shutdown:

    if (session) {
        libssh2_session_disconnect(session, "Normal Shutdown");
        libssh2_session_free(session);
    }

    if (server_sock != LIBSSH2_INVALID_SOCKET) {
        closesocket(server_sock);
    }

    libssh2_exit();

    return 0;
}

int main(int argc, char* argv[])
{
    if (argc == 5) {
        const char* server_ip = argv[1];
        int ssh_port = 22;
        int fwd_port = atoi(argv[4]);
        const char* username = argv[2];
        const char* password = argv[3];

        dbg_init(SSHPROXY_DBG_DBG);
        //libssh2_trace(session, LIBSSH2_TRACE_CONN);

        return ssh_main(server_ip, ssh_port, fwd_port, username, password);
    }
    return 0;
}