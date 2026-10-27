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

#ifdef __SWITCH__
#include <switch.h>
#include <switch/services/bsd.h>
#include <sys/iosupport.h>
#endif

#ifdef TSNX_NO_STDIO
// Builds without newlib's printf (the sysmodule) supply this instead.
int tsnx_snprintf(char *dst, size_t size, const char *fmt, ...);
#define snprintf tsnx_snprintf
#endif

#define MAX_CONNS (TSNX_DRIVER_MAX_FDS - 1)
// Datagrams read per readiness report: the rest wait for the next round, so
// a socket that keeps "returning" something can't hold the loop.
#define UDP_RECV_BATCH 64
// Datagrams are read UDP_STAGED at a time into sbuf (page-aligned: on the
// Switch it is also the socket service's message buffer), UDP_SLOT bytes
// each (underlay datagrams fit), and handed to the engine from there.
#define UDP_STAGED 16
#define UDP_SLOT 2048
#define SBUF_SIZE (UDP_STAGED * UDP_SLOT)

static const char *volatile g_step;
#define STEP(s) (g_step = (s))
const char *tsnx_driver_step(void) { return g_step; }
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
    short poll_events[MAX_CONNS];
    int poll_conns, poll_udp, poll_udp_fd;
    uint64_t poll_deadline;  // the engine's next deadline when prepared
    TsnxDropSink drop;
    uint32_t drop_id;  // transfer being written, 0 = none
    int in_drop;
    // Datagrams read but not yet handed to the engine (in sbuf).
    uint8_t *sbuf;
    struct {
        const uint8_t *data;
        size_t len;
        TsnxAddr src;
    } staged[UDP_STAGED];
    int n_staged, staged_all;  // staged_all: the socket was drained
    int prefetched;            // staged by tsnx_driver_prefetch, without the caller's lock
    // Batched receive (Switch): 1 works, 0 not known yet, -1 off (and the
    // socket service's errno, if a call failed); misses: batches that came
    // back empty while recvfrom then found a datagram.
    int mmsg_state, mmsg_errno, mmsg_misses;
};

uint64_t tsnx_driver_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

TsnxDriver *tsnx_driver_new(TsnxEngine *engine, tsnx_event_fn on_event, void *ctx) {
    TsnxDriver *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->sbuf = aligned_alloc(0x1000, SBUF_SIZE);
    if (!d->sbuf) {
        free(d);
        return NULL;
    }
#ifdef __SWITCH__
    if (hosversionBefore(7, 0, 0)) d->mmsg_state = -1;  // its RecvMMsg is 7.0.0+
#else
    d->mmsg_state = -1;
#endif
    d->engine = engine;
    d->on_event = on_event;
    d->ctx = ctx;
    d->udp_fd = -1;
    d->poll_udp_fd = -1;
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
    if (d->drop_id) {
        char ignored[8];
        d->drop.close(d->drop.ctx, 0, ignored, sizeof ignored);
    }
    free(d->connect_map);
    free(d->sbuf);
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

// The Switch's socket service gives a UDP socket 48 KB of receive buffer,
// about one video frame's burst of datagrams, and drops what arrives while
// it's full before we can read it: under a 15.5 Mbit/s Artemis stream that
// was 1-12% of packets. Ask for more, as much as it allows (a little over
// 160 KB). It only lets this socket hold more of the buffer pool, which is
// our own transfer memory, not new memory.
#define UDP_RCVBUF (160 * 1024)

static void grow_rcvbuf(int fd) {
    for (int size = UDP_RCVBUF; size > 48 * 1024; size -= 32 * 1024) {
        int got = 0;
        socklen_t len = sizeof got;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof size) == 0 &&
            getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &got, &len) == 0 && got >= size)
            return;
    }
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
    grow_rcvbuf(fd);
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
    STEP("UDP send");
    if (d->udp_fd < 0 || to->family != 4) return;  // IPv6 underlay: not yet
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    memcpy(&sin.sin_addr, to->ip, 4);
    sin.sin_port = htons(to->port);
    // Best effort, like any UDP send: a full socket buffer drops the datagram.
    sendto(d->udp_fd, data, len, 0, (struct sockaddr *)&sin, sizeof sin);
}

// Reads one datagram into buf. Returns its length, or -1 when there's
// nothing (more) to read.
static ssize_t udp_read(TsnxDriver *d, uint8_t *buf, size_t cap, TsnxAddr *src) {
    struct sockaddr_in from;
    socklen_t flen = sizeof from;
    memset(&from, 0, sizeof from);
    ssize_t got = recvfrom(d->udp_fd, buf, cap, 0, (struct sockaddr *)&from, &flen);
    if (got < 0 || from.sin_family != AF_INET) return -1;
    to_tsnx_addr(&from, src);
    return got;
}

// Reads datagrams one call each into sbuf's slots. Returns how many.
static int stage_each(TsnxDriver *d) {
    int n = 0;
    while (n < UDP_STAGED) {
        uint8_t *slot = d->sbuf + (size_t)n * UDP_SLOT;
        ssize_t got = udp_read(d, slot, UDP_SLOT, &d->staged[n].src);
        if (got < 0) break;
        d->staged[n].data = slot;
        d->staged[n++].len = (size_t)got;
    }
    return n;
}

#ifdef __SWITCH__
// One bsdRecvMMsg for up to UDP_STAGED datagrams. libnx's recvmmsg mallocs,
// which libstratosphere's shim aborts on, so this does what it does with
// sbuf (page-aligned, like libnx's buffer): a 0x08 byte, then per message
// u32 namelen, name, s32 iovlen, iovlen x (u64 len, data), u32 controllen,
// control, s32 flags, s32 msg_len, rewritten by the reply with the actual
// lengths. Returns how many, or -1 with the socket service's errno in *err.
#define MMSG_HEAD (4 + 16 + 4 + 8)
#define MMSG_TAIL (4 + 4 + 4)
#define MMSG_CAP ((SBUF_SIZE - 1) / UDP_STAGED - MMSG_HEAD - MMSG_TAIL)
_Static_assert(MMSG_CAP >= 1500, "batched receive slots must hold a full datagram");
#define BSD_EAGAIN 11  // the socket service's errno numbering (Linux's)

static void put(uint8_t **p, const void *v, size_t n) {
    memcpy(*p, v, n);
    *p += n;
}

static int stage_batch(TsnxDriver *d, int *err) {
    __handle *h = __get_handle(d->udp_fd);
    if (!h || !h->fileStruct) {
        *err = 0;
        return -1;
    }
    const int fd = *(const int *)h->fileStruct;  // as libnx's own fd lookup
    uint8_t *p = d->sbuf;
    *p++ = 0x08;
    for (int i = 0; i < UDP_STAGED; i++) {
        const uint32_t namelen = 16, controllen = 0;
        const int32_t iovlen = 1, zero = 0;
        const uint64_t cap = MMSG_CAP;
        put(&p, &namelen, 4);
        memset(p, 0, 16);
        p += 16;
        put(&p, &iovlen, 4);
        put(&p, &cap, 8);
        p += MMSG_CAP;
        put(&p, &controllen, 4);
        put(&p, &zero, 4);
        put(&p, &zero, 4);
    }
    struct timespec no_timeout = {0};  // read unconditionally
    int n = bsdRecvMMsg(fd, d->sbuf, SBUF_SIZE, UDP_STAGED, MSG_DONTWAIT, &no_timeout);
    if (n < 0) {
        *err = g_bsdErrno;
        return -1;
    }
    const size_t size = SBUF_SIZE;
    size_t off = 1;
    int got = 0;
    for (int i = 0; i < n && i < UDP_STAGED; i++) {
        uint32_t namelen, controllen;
        int32_t iovlen;
        struct sockaddr_in from;
        memset(&from, 0, sizeof from);
        if (off + 4 > size) break;
        memcpy(&namelen, d->sbuf + off, 4);
        off += 4;
        if (namelen > size - off) break;
        memcpy(&from, d->sbuf + off, namelen < sizeof from ? namelen : sizeof from);
        off += namelen;
        if (off + 4 > size) break;
        memcpy(&iovlen, d->sbuf + off, 4);
        off += 4;
        const uint8_t *data = NULL;
        uint64_t len = 0;
        int ok = iovlen >= 0;
        for (int32_t v = 0; v < iovlen && ok; v++) {
            uint64_t l;
            if (off + 8 > size) {
                ok = 0;
                break;
            }
            memcpy(&l, d->sbuf + off, 8);
            off += 8;
            if (l > size - off) {
                ok = 0;
                break;
            }
            if (v == 0) {
                data = d->sbuf + off;
                len = l;
            }
            off += (size_t)l;
        }
        if (!ok || off + 4 > size) break;
        memcpy(&controllen, d->sbuf + off, 4);
        off += 4;
        if (controllen > size - off || off + controllen + 8 > size) break;
        int32_t msg_len;
        memcpy(&msg_len, d->sbuf + off + controllen + 4, 4);
        off += controllen + 8;  // control, flags, msg_len
        // The datagram's size is msg_len: the reply can leave the iovec at
        // its full capacity.
        if (msg_len >= 0 && (uint64_t)msg_len < len) len = (uint64_t)msg_len;
        if (!data || from.sin_family != AF_INET) continue;
        to_tsnx_addr(&from, &d->staged[got].src);
        d->staged[got].data = data;
        d->staged[got++].len = (size_t)len;
    }
    return got;
}
#endif

// Reads up to UDP_STAGED datagrams into d->staged (called when the socket
// was reported readable). Returns how many.
static int stage(TsnxDriver *d) {
#ifdef __SWITCH__
    if (d->mmsg_state >= 0) {
        int err = 0;
        int n = stage_batch(d, &err);
        if (n > 0) {
            d->mmsg_state = 1;
            return n;
        }
        if (n < 0 && err != BSD_EAGAIN) {
            d->mmsg_state = -1;  // unsupported here: one datagram per call
            d->mmsg_errno = err;
        } else if (d->mmsg_state == 0) {
            // Empty though poll said readable: check that it isn't the
            // batch that's broken (then recvfrom finds a datagram).
            n = stage_each(d);
            if (n > 0 && ++d->mmsg_misses >= 3) d->mmsg_state = -1;
            return n;
        } else {
            return 0;
        }
    }
#endif
    return stage_each(d);
}

void tsnx_driver_prefetch(TsnxDriver *d, const struct pollfd *fds) {
    d->n_staged = 0;
    d->staged_all = 0;
    d->prefetched = 1;
    if (d->poll_udp < 0 || !(fds[d->poll_udp].revents & POLLIN)) return;
    STEP("UDP prefetch");
    d->n_staged = stage(d);
    d->staged_all = d->n_staged < UDP_STAGED;
}

// Hands the staged datagrams to the engine, then reads and hands over more
// until the socket is drained (or UDP_RECV_BATCH, so it can't hold the loop).
// After a prefetch it reads no more: the caller holds its lock now, and an
// app reading what we deliver would wait out every read. A video frame
// arrives as a burst of datagrams, and delivered all at once it overflows
// the app's socket queue; the rest is read by the next round's prefetch.
static void udp_receive(TsnxDriver *d) {
    int handled = 0;
    const int prefetched = d->prefetched;
    d->prefetched = 0;
    for (;;) {
        for (int i = 0; i < d->n_staged; i++)
            tsnx_engine_udp(d->engine, &d->staged[i].src, d->staged[i].data, d->staged[i].len, tsnx_driver_now_ns());
        handled += d->n_staged;
        const int drained = d->staged_all;
        d->n_staged = 0;
        d->staged_all = 0;
        if (drained || prefetched || handled >= UDP_RECV_BATCH) return;
        STEP("UDP receive");
        d->n_staged = stage(d);
        d->staged_all = d->n_staged < UDP_STAGED;
    }
}

int tsnx_driver_batched_receive(TsnxDriver *d, int *bsd_errno) {
    if (bsd_errno) *bsd_errno = d->mmsg_errno;
    return d->mmsg_state;
}

static void do_connect(TsnxDriver *d, uint32_t id, const char *target, uint16_t port) {
    STEP("TCP connect");
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
    STEP("TCP send");
    while (c->wlen > 0) {
        ssize_t n = send(c->fd, c->wbuf, c->wlen, 0);
        if (n == 0) return 0;  // nothing taken: try when it's writable again
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

static void pump_taildrop(TsnxDriver *d);

// Drains engine I/O requests and events.
static void pump_engine(TsnxDriver *d) {
    STEP("engine I/O");
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
    pump_taildrop(d);
}

int tsnx_driver_set_taildrop(TsnxDriver *d, const TsnxDropSink *sink, uint16_t port) {
    if (!sink || !sink->open || !sink->write || !sink->close) return -1;
    d->drop = *sink;
    return tsnx_taildrop_enable(d->engine, port) == 0 ? 0 : -1;
}

// Ends the transfer being written: the sink saves or discards it, and the
// sender gets the outcome (status 0 = saved).
static void drop_end(TsnxDriver *d, int saved_ok, int status, const char *why) {
    uint32_t id = d->drop_id;
    char msg[160];
    snprintf(msg, sizeof msg, "%s", why ? why : "");
    d->drop_id = 0;
    if (saved_ok) {
        status = d->drop.close(d->drop.ctx, 1, msg, sizeof msg);
    } else {
        char ignored[8];
        d->drop.close(d->drop.ctx, 0, ignored, sizeof ignored);
    }
    tsnx_taildrop_finish(d->engine, id, (uint16_t)(status ? status : 200), msg, tsnx_driver_now_ns());
}

// Moves Taildrop data from the engine to the sink: answers offers, then
// reads the body (into rbuf, free between socket reads) and writes it out.
static void pump_taildrop(TsnxDriver *d) {
    if (!d->drop.open || d->in_drop) return;
    d->in_drop = 1;  // finish/accept pump the engine, which calls back here
    char why[160];
    for (;;) {
        int had_event = 0;
        TsnxDropEvent ev;
        while (tsnx_taildrop_poll(d->engine, &ev)) {
            had_event = 1;
            uint64_t now = tsnx_driver_now_ns();
            why[0] = 0;
            if (ev.kind == TSNX_DROP_OFFER) {
                if (d->drop_id) {
                    tsnx_taildrop_finish(d->engine, ev.id, 503, "busy receiving another file", now);
                    continue;
                }
                int st = d->drop.open(d->drop.ctx, ev.name, ev.size, ev.text, why, sizeof why);
                if (st == 0) {
                    d->drop_id = ev.id;
                    tsnx_taildrop_accept(d->engine, ev.id, now);
                } else {
                    tsnx_taildrop_finish(d->engine, ev.id, (uint16_t)st, why, now);
                }
            } else if (ev.id == d->drop_id && ev.kind == TSNX_DROP_COMPLETE) {
                drop_end(d, 1, 0, NULL);
            } else if (ev.id == d->drop_id && ev.kind == TSNX_DROP_ABORTED) {
                d->drop_id = 0;
                d->drop.close(d->drop.ctx, 0, why, sizeof why);
            }
        }
        if (!d->drop_id) break;
        size_t n = tsnx_taildrop_read(d->engine, d->drop_id, d->rbuf, sizeof d->rbuf, tsnx_driver_now_ns());
        if (n > 0) {
            why[0] = 0;
            int st = d->drop.write(d->drop.ctx, d->rbuf, n, why, sizeof why);
            if (st != 0) drop_end(d, 0, st, why);
        } else if (!had_event) {
            break;  // nothing more for now (an ending shows up as an event)
        }
    }
    d->in_drop = 0;
}

void tsnx_driver_pump(TsnxDriver *d) { pump_engine(d); }

static short conn_events(const Conn *c) { return POLLIN | (c->connecting || c->wlen > 0 ? POLLOUT : 0); }

int tsnx_driver_prepare(TsnxDriver *d, struct pollfd *fds, int cap, int max_wait_ms, int *wait_ms) {
    uint64_t now = tsnx_driver_now_ns();
    if (now >= tsnx_engine_next_deadline(d->engine)) tsnx_engine_timeout(d->engine, now);
    pump_engine(d);

    int n = 0;
    for (int i = 0; i < MAX_CONNS && n < cap; i++) {
        Conn *c = &d->conns[i];
        if (!c->id) continue;
        fds[n].fd = c->fd;
        fds[n].events = conn_events(c);
        fds[n].revents = 0;
        d->poll_ids[n] = c->id;
        d->poll_events[n] = fds[n].events;
        d->poll_owners[n++] = c;
    }
    d->poll_conns = n;
    // The UDP socket, if open, goes last.
    d->poll_udp = -1;
    d->poll_udp_fd = -1;
    if (d->udp_fd >= 0 && n < cap) {
        d->poll_udp = n;
        d->poll_udp_fd = d->udp_fd;
        fds[n].fd = d->udp_fd;
        fds[n].events = POLLIN;
        fds[n++].revents = 0;
    }

    uint64_t deadline = tsnx_engine_next_deadline(d->engine);
    d->poll_deadline = deadline;
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

int tsnx_driver_poll_stale(TsnxDriver *d, uint64_t until_ns) {
    int n = 0;
    for (int i = 0; i < MAX_CONNS; i++) {
        const Conn *c = &d->conns[i];
        if (!c->id) continue;
        if (n >= d->poll_conns || d->poll_owners[n] != c || d->poll_ids[n] != c->id || d->poll_events[n] != conn_events(c))
            return 1;
        n++;
    }
    if (n != d->poll_conns || d->udp_fd != d->poll_udp_fd) return 1;
    // The poll's timeout is rounded up past the deadline it was set for, so
    // only a deadline earlier than that one is news.
    const uint64_t deadline = tsnx_engine_next_deadline(d->engine);
    return deadline < d->poll_deadline && deadline < until_ns;
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
                STEP("TCP receive");
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
