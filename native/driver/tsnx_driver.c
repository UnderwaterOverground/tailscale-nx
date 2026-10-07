// See tsnx_driver.h.
#include "tsnx_driver.h"

#include "tsnx_dns.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef TSNX_NO_STDIO
// Builds without newlib's printf (the sysmodule) supply this instead.
int tsnx_snprintf(char *dst, size_t size, const char *fmt, ...);
#define snprintf tsnx_snprintf
#endif

#define MAX_CONNS (TSNX_DRIVER_MAX_FDS - 1)
#define RECV_CHUNK 16384

typedef struct {
    uint32_t id;  // 0 = free slot
    int fd;
    int connecting;
    uint8_t *wbuf;  // bytes accepted from the engine but not yet written
    size_t wlen, wcap;
} Conn;

struct TsnxDriver {
    TsnxEngine *engine;
    tsnx_event_fn on_event;
    void *ctx;
    Conn conns[MAX_CONNS];
    uint8_t rbuf[RECV_CHUNK];
    char *connect_map;
    int udp_fd;
    uint16_t udp_port;
    // Bookkeeping between prepare and dispatch (slots can be reused mid-dispatch).
    Conn *poll_owners[MAX_CONNS];
    uint32_t poll_ids[MAX_CONNS];
    int poll_conns, poll_udp;
};

uint64_t tsnx_driver_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

TsnxDriver *tsnx_driver_new(TsnxEngine *engine, tsnx_event_fn on_event, void *ctx) {
    TsnxDriver *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->engine = engine;
    d->on_event = on_event;
    d->ctx = ctx;
    d->udp_fd = -1;
    for (int i = 0; i < MAX_CONNS; i++) d->conns[i].fd = -1;
    return d;
}

static void conn_free(Conn *c) {
    if (c->fd >= 0) close(c->fd);
    free(c->wbuf);
    memset(c, 0, sizeof *c);
    c->fd = -1;
}

void tsnx_driver_set_connect_map(TsnxDriver *d, const char *map) {
    free(d->connect_map);
    d->connect_map = map ? strdup(map) : NULL;
}

// Applies the connect map: rewrites host/port in place if an entry matches.
static void map_target(TsnxDriver *d, char *host, size_t host_cap, uint16_t *port) {
    if (!d->connect_map) return;
    char key[300];
    snprintf(key, sizeof key, "%s:%u=", host, *port);
    const char *hit = strstr(d->connect_map, key);
    if (!hit || (hit != d->connect_map && hit[-1] != ',')) return;
    const char *to = hit + strlen(key);
    const char *colon = strchr(to, ':');
    if (!colon) return;
    size_t hlen = (size_t)(colon - to);
    if (hlen >= host_cap) return;
    memcpy(host, to, hlen);
    host[hlen] = 0;
    *port = (uint16_t)atoi(colon + 1);
}

void tsnx_driver_free(TsnxDriver *d) {
    if (!d) return;
    free(d->connect_map);
    if (d->udp_fd >= 0) close(d->udp_fd);
    for (int i = 0; i < MAX_CONNS; i++)
        if (d->conns[i].id) conn_free(&d->conns[i]);
    free(d);
}

static Conn *conn_find(TsnxDriver *d, uint32_t id) {
    for (int i = 0; i < MAX_CONNS; i++)
        if (d->conns[i].id == id) return &d->conns[i];
    return NULL;
}

// Tells the engine a connection is gone and frees the slot.
static void conn_closed(TsnxDriver *d, Conn *c) {
    uint32_t id = c->id;
    conn_free(c);
    tsnx_engine_closed(d->engine, id, tsnx_driver_now_ns());
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void to_tsnx_addr(const struct sockaddr_in *sin, TsnxAddr *out) {
    memset(out, 0, sizeof *out);
    out->family = 4;
    memcpy(out->ip, &sin->sin_addr, 4);
    out->port = ntohs(sin->sin_port);
}

// The source IP the OS would use towards the internet (no packets sent).
static int local_ipv4(struct in_addr *out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    dst.sin_addr.s_addr = htonl(0x01010101);  // 1.1.1.1
    struct sockaddr_in me = {0};
    socklen_t len = sizeof me;
    int rc = connect(fd, (struct sockaddr *)&dst, sizeof dst);
    if (rc == 0) rc = getsockname(fd, (struct sockaddr *)&me, &len);
    close(fd);
    if (rc != 0 || me.sin_addr.s_addr == 0) return -1;
    *out = me.sin_addr;
    return 0;
}

void tsnx_driver_refresh_endpoints(TsnxDriver *d) {
    if (d->udp_fd < 0) return;
    struct in_addr ip;
    TsnxAddr ep;
    size_t n = 0;
    if (local_ipv4(&ip) == 0) {
        struct sockaddr_in sin = {0};
        sin.sin_family = AF_INET;
        sin.sin_addr = ip;
        sin.sin_port = htons(d->udp_port);
        to_tsnx_addr(&sin, &ep);
        n = 1;
    }
    tsnx_engine_set_local_endpoints(d->engine, &ep, n, tsnx_driver_now_ns());
}

int tsnx_driver_open_udp(TsnxDriver *d, uint16_t port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    socklen_t len = sizeof sin;
    if (bind(fd, (struct sockaddr *)&sin, sizeof sin) != 0 || set_nonblocking(fd) != 0 ||
        getsockname(fd, (struct sockaddr *)&sin, &len) != 0) {
        close(fd);
        return -1;
    }
    d->udp_fd = fd;
    d->udp_port = ntohs(sin.sin_port);
    tsnx_driver_refresh_endpoints(d);
    return 0;
}

void tsnx_driver_suspend(TsnxDriver *d) {
    for (int i = 0; i < MAX_CONNS; i++)
        if (d->conns[i].id) conn_closed(d, &d->conns[i]);
    if (d->udp_fd >= 0) {
        close(d->udp_fd);
        d->udp_fd = -1;
    }
}

int tsnx_driver_resume(TsnxDriver *d) {
    if (d->udp_fd >= 0 || !d->udp_port) return 0;
    // Same port as before, so peers' notion of our endpoint stays valid.
    return tsnx_driver_open_udp(d, d->udp_port) == 0 ? 0 : tsnx_driver_open_udp(d, 0);
}

static void udp_send(TsnxDriver *d, const TsnxAddr *to, const uint8_t *data, size_t len) {
    if (d->udp_fd < 0 || to->family != 4) return;  // IPv6 underlay: not yet
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    memcpy(&sin.sin_addr, to->ip, 4);
    sin.sin_port = htons(to->port);
    // Best effort, like any UDP send: a full socket buffer drops the datagram.
    sendto(d->udp_fd, data, len, 0, (struct sockaddr *)&sin, sizeof sin);
}

static void udp_receive(TsnxDriver *d) {
    for (;;) {
        struct sockaddr_in from;
        socklen_t flen = sizeof from;
        ssize_t got = recvfrom(d->udp_fd, d->rbuf, sizeof d->rbuf, 0, (struct sockaddr *)&from, &flen);
        if (got < 0) return;
        if (from.sin_family != AF_INET) continue;
        TsnxAddr src;
        to_tsnx_addr(&from, &src);
        tsnx_engine_udp(d->engine, &src, d->rbuf, (size_t)got, tsnx_driver_now_ns());
    }
}

static void do_connect(TsnxDriver *d, uint32_t id, const char *target, uint16_t port) {
    char host[256];
    snprintf(host, sizeof host, "%s", target);
    map_target(d, host, sizeof host, &port);
    Conn *c = conn_find(d, 0);
    if (!c) {
        tsnx_engine_closed(d->engine, id, tsnx_driver_now_ns());
        return;
    }
    uint32_t ip;
    // Blocking resolve: acceptable for the few control/DERP connections.
    if (tsnx_resolve_ipv4(host, &ip) != 0) {
        tsnx_engine_closed(d->engine, id, tsnx_driver_now_ns());
        return;
    }
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip;
    sin.sin_port = htons(port);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0 || set_nonblocking(fd) != 0) {
        if (fd >= 0) close(fd);
        tsnx_engine_closed(d->engine, id, tsnx_driver_now_ns());
        return;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    int rc = connect(fd, (struct sockaddr *)&sin, sizeof sin);
    if (rc != 0 && errno != EINPROGRESS) {
        close(fd);
        tsnx_engine_closed(d->engine, id, tsnx_driver_now_ns());
        return;
    }
    memset(c, 0, sizeof *c);
    c->id = id;
    c->fd = fd;
    c->connecting = 1;
}

// Writes as much buffered data as the socket takes. Returns -1 on error.
static int conn_flush(Conn *c) {
    while (c->wlen > 0) {
        ssize_t n = send(c->fd, c->wbuf, c->wlen, 0);
        if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? 0 : -1;
        memmove(c->wbuf, c->wbuf + n, c->wlen - (size_t)n);
        c->wlen -= (size_t)n;
    }
    return 0;
}

static int conn_queue(Conn *c, const uint8_t *data, size_t len) {
    if (c->wlen + len > c->wcap) {
        size_t cap = c->wcap ? c->wcap : 4096;
        while (cap < c->wlen + len) cap *= 2;
        // malloc+copy, not realloc: libstratosphere's realloc corrupts the
        // heap when growing small blocks (see platform.rs in tsnx-ffi).
        uint8_t *nb = malloc(cap);
        if (!nb) return -1;
        if (c->wlen) memcpy(nb, c->wbuf, c->wlen);
        free(c->wbuf);
        c->wbuf = nb;
        c->wcap = cap;
    }
    memcpy(c->wbuf + c->wlen, data, len);
    c->wlen += len;
    return 0;
}

// Drains engine I/O requests and events.
static void pump_engine(TsnxDriver *d) {
    TsnxIo io;
    while (tsnx_engine_poll_io(d->engine, &io)) {
        Conn *c;
        switch (io.kind) {
            case TSNX_IO_CONNECT:
                do_connect(d, io.id, io.host, io.port);
                break;
            case TSNX_IO_SEND:
                c = conn_find(d, io.id);
                if (c && (conn_queue(c, io.data, io.len) != 0 || (!c->connecting && conn_flush(c) != 0)))
                    conn_closed(d, c);
                break;
            case TSNX_IO_CLOSE:
                c = conn_find(d, io.id);
                if (c) conn_free(c);  // engine-initiated: no callback
                break;
            case TSNX_IO_SEND_UDP:
                udp_send(d, &io.addr, io.data, io.len);
                break;
        }
    }
    TsnxEvent ev;
    while (tsnx_engine_poll_event(d->engine, &ev))
        if (d->on_event) d->on_event(d->ctx, &ev);
}

void tsnx_driver_pump(TsnxDriver *d) { pump_engine(d); }

int tsnx_driver_prepare(TsnxDriver *d, struct pollfd *fds, int cap, int max_wait_ms, int *wait_ms) {
    uint64_t now = tsnx_driver_now_ns();
    if (now >= tsnx_engine_next_deadline(d->engine)) tsnx_engine_timeout(d->engine, now);
    pump_engine(d);

    int n = 0;
    for (int i = 0; i < MAX_CONNS && n < cap; i++) {
        Conn *c = &d->conns[i];
        if (!c->id) continue;
        fds[n].fd = c->fd;
        fds[n].events = POLLIN;
        if (c->connecting || c->wlen > 0) fds[n].events |= POLLOUT;
        fds[n].revents = 0;
        d->poll_ids[n] = c->id;
        d->poll_owners[n++] = c;
    }
    d->poll_conns = n;
    // The UDP socket, if open, goes last.
    d->poll_udp = -1;
    if (d->udp_fd >= 0 && n < cap) {
        d->poll_udp = n;
        fds[n].fd = d->udp_fd;
        fds[n].events = POLLIN;
        fds[n++].revents = 0;
    }

    uint64_t deadline = tsnx_engine_next_deadline(d->engine);
    now = tsnx_driver_now_ns();
    int wait = max_wait_ms;
    if (deadline <= now) {
        wait = 0;
    } else if ((deadline - now) / 1000000 < (uint64_t)wait) {
        wait = (int)((deadline - now) / 1000000) + 1;
    }
    *wait_ms = wait;
    return n;
}

void tsnx_driver_dispatch(TsnxDriver *d, const struct pollfd *fds) {
    if (d->poll_udp >= 0 && (fds[d->poll_udp].revents & POLLIN)) {
        udp_receive(d);
        pump_engine(d);
    }
    for (int i = 0; i < d->poll_conns; i++) {
        Conn *c = d->poll_owners[i];
        uint32_t id = d->poll_ids[i];
        short re = fds[i].revents;
        if (!re || c->id != id) continue;
        if (c->connecting && (re & (POLLOUT | POLLERR | POLLHUP))) {
            int err = 0;
            socklen_t len = sizeof err;
            getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err != 0) {
                conn_closed(d, c);
                continue;
            }
            c->connecting = 0;
            tsnx_engine_connected(d->engine, c->id, tsnx_driver_now_ns());
            pump_engine(d);
            if (c->id != id) continue;
        }
        if (re & POLLIN) {
            for (;;) {
                ssize_t got = recv(c->fd, d->rbuf, sizeof d->rbuf, 0);
                if (got > 0) {
                    tsnx_engine_data(d->engine, c->id, d->rbuf, (size_t)got, tsnx_driver_now_ns());
                    pump_engine(d);
                    if (c->id != id) break;
                    continue;
                }
                if (got == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) conn_closed(d, c);
                break;
            }
            if (c->id != id) continue;
        } else if (re & (POLLERR | POLLHUP)) {
            conn_closed(d, c);
            continue;
        }
        if (!c->connecting && c->wlen > 0 && conn_flush(c) != 0) conn_closed(d, c);
    }
    pump_engine(d);
}

int tsnx_driver_run_once(TsnxDriver *d, int max_wait_ms) {
    struct pollfd fds[TSNX_DRIVER_MAX_FDS];
    int wait;
    int n = tsnx_driver_prepare(d, fds, TSNX_DRIVER_MAX_FDS, max_wait_ms, &wait);
    int rc = poll(fds, (nfds_t)n, wait);
    if (rc < 0 && errno != EINTR) return -1;
    if (rc > 0) tsnx_driver_dispatch(d, fds);
    return 0;
}
