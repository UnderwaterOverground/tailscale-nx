// See tsnx_update.h.
#include "tsnx_update.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "tsnx.h"
#include "tsnx_dns.h"

#ifdef TSNX_NO_STDIO
// Builds without newlib's printf (the sysmodule) supply this instead.
int tsnx_snprintf(char *dst, size_t size, const char *fmt, ...);
#define snprintf tsnx_snprintf
#endif

#define HOST "github.com"

struct TsnxUpdate {
    int fd;
    TsnxTls *tls;
    int connecting;
    int result;
    uint64_t deadline_ns;
    char current[24];
    char latest[24];
    char error[96];
    uint8_t out[1024];  // ciphertext taken from TLS, not yet sent
    size_t out_off, out_len;
    char head[1024];    // the response's start; the Location header is early
    size_t head_len;
};

static int fail(TsnxUpdate *u, const char *what, const char *detail) {
    snprintf(u->error, sizeof u->error, "%s%s%s", what, detail ? ": " : "", detail ? detail : "");
    u->result = TSNX_UPDATE_FAILED;
    return u->result;
}

// No strerror: its message table would grow the sysmodule.
static int fail_errno(TsnxUpdate *u, const char *what, int err) {
    char detail[24];
    snprintf(detail, sizeof detail, "errno %d", err);
    return fail(u, what, detail);
}

TsnxUpdate *tsnx_update_start(const char *repo, const char *current, uint64_t now_ns, uint32_t timeout_ms) {
    TsnxUpdate *u = (TsnxUpdate *)calloc(1, sizeof *u);
    if (!u) return NULL;
    u->fd = -1;
    u->deadline_ns = now_ns + (uint64_t)timeout_ms * 1000000ull;
    snprintf(u->current, sizeof u->current, "%s", current);

    uint32_t ip;
    if (tsnx_resolve_ipv4(HOST, &ip) != 0) {
        fail(u, "cannot resolve " HOST, NULL);
        return u;
    }
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip;
    sin.sin_port = htons(443);
    u->fd = socket(AF_INET, SOCK_STREAM, 0);
    int flags = u->fd < 0 ? -1 : fcntl(u->fd, F_GETFL, 0);
    if (flags < 0 || fcntl(u->fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        fail_errno(u, "no socket", errno);
        return u;
    }
    // We send a few hundred bytes: keep our share of the socket buffer pool small.
    const int snd = 0x2000;
    setsockopt(u->fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof snd);
    if (connect(u->fd, (struct sockaddr *)&sin, sizeof sin) != 0 && errno != EINPROGRESS) {
        fail_errno(u, "connect", errno);
        return u;
    }
    u->connecting = 1;

    u->tls = tsnx_tls_new(HOST);
    if (!u->tls) {
        fail(u, "TLS setup failed", NULL);
        return u;
    }
    // Sent once the handshake is done.
    char req[256];
    const int n = snprintf(req, sizeof req,
                           "GET /%s/releases/latest HTTP/1.1\r\n"
                           "Host: " HOST "\r\n"
                           "User-Agent: tailscale-nx/%s\r\n"
                           "Connection: close\r\n\r\n",
                           repo, current);
    if (n <= 0 || (size_t)n >= sizeof req || tsnx_tls_write(u->tls, (const uint8_t *)req, (size_t)n) != 0) {
        fail(u, "TLS write failed", NULL);
    }
    return u;
}

// Finds header `name` (with the colon, any case) in the response head.
static const char *find_header(const char *head, const char *name) {
    const size_t len = strlen(name);
    for (const char *p = strstr(head, "\r\n"); p; p = strstr(p + 2, "\r\n")) {
        if (strncasecmp(p + 2, name, len) == 0) return p + 2 + len;
    }
    return NULL;
}

// The head is complete (or as much as we keep): read the redirect.
static int parse_head(TsnxUpdate *u) {
    if (strncmp(u->head, "HTTP/1.1 302", 12) != 0 && strncmp(u->head, "HTTP/1.0 302", 12) != 0) {
        const char *eol = strstr(u->head, "\r\n");
        char status[40];
        snprintf(status, sizeof status, "%.*s", eol ? (int)(eol - u->head) : 0, u->head);
        return fail(u, "unexpected answer", status);
    }
    const char *loc = find_header(u->head, "Location:");
    const char *tag = loc ? strstr(loc, "/releases/tag/") : NULL;
    const char *eol = loc ? strstr(loc, "\r\n") : NULL;
    if (!tag || (eol && tag > eol)) return fail(u, "no release tag in the redirect", NULL);  // e.g. no releases yet
    tag += strlen("/releases/tag/");
    if (*tag == 'v' || *tag == 'V') tag++;
    size_t n = 0;
    // Only what a version contains: it ends up in a JSON toast.
    while (n + 1 < sizeof u->latest && ((tag[n] >= '0' && tag[n] <= '9') || tag[n] == '.' || tag[n] == '-' ||
                                        (tag[n] >= 'a' && tag[n] <= 'z') || (tag[n] >= 'A' && tag[n] <= 'Z'))) {
        u->latest[n] = tag[n];
        n++;
    }
    u->latest[n] = 0;
    if (n == 0 || u->latest[0] < '0' || u->latest[0] > '9') return fail(u, "unexpected release tag", NULL);
    u->result = tsnx_version_compare(u->latest, u->current) > 0 ? TSNX_UPDATE_NEWER : TSNX_UPDATE_CURRENT;
    return u->result;
}

int tsnx_update_step(TsnxUpdate *u, uint64_t now_ns) {
    if (u->result != TSNX_UPDATE_PENDING) return u->result;
    if (now_ns > u->deadline_ns) return fail(u, "timed out", NULL);

    if (u->connecting) {
        struct pollfd pfd = {u->fd, POLLOUT, 0};
        if (poll(&pfd, 1, 0) <= 0) return TSNX_UPDATE_PENDING;
        int err = 0;
        socklen_t len = sizeof err;
        if (getsockopt(u->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) err = errno;
        if (err) return fail_errno(u, "connect", err);
        u->connecting = 0;
    }

    for (int progressed = 1; progressed;) {
        progressed = 0;
        // Send what TLS has for the server.
        for (;;) {
            if (u->out_off == u->out_len) {
                u->out_off = 0;
                u->out_len = tsnx_tls_take_outgoing(u->tls, u->out, sizeof u->out);
                if (u->out_len == 0) break;
            }
            const ssize_t n = send(u->fd, u->out + u->out_off, u->out_len - u->out_off, 0);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (n <= 0) return fail_errno(u, "send", n < 0 ? errno : 0);
            u->out_off += (size_t)n;
        }
        // Receive and decrypt.
        uint8_t buf[2048];
        const ssize_t got = recv(u->fd, buf, sizeof buf, 0);
        if (got < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return fail_errno(u, "recv", errno);
        if (got > 0) {
            progressed = 1;
            if (tsnx_tls_feed(u->tls, buf, (size_t)got) != 0) return fail(u, "TLS", tsnx_tls_last_error(u->tls));
        }
        if (tsnx_tls_state(u->tls) & TSNX_TLS_FAILED) return fail(u, "TLS", tsnx_tls_last_error(u->tls));
        const size_t room = sizeof u->head - 1 - u->head_len;
        if (room > 0) {
            u->head_len += tsnx_tls_read(u->tls, (uint8_t *)u->head + u->head_len, room);
            u->head[u->head_len] = 0;
        }
        if (strstr(u->head, "\r\n\r\n") || u->head_len == sizeof u->head - 1) return parse_head(u);
        if (got == 0 || (tsnx_tls_state(u->tls) & TSNX_TLS_PEER_CLOSED)) {
            return u->head_len ? parse_head(u) : fail(u, "connection closed", NULL);
        }
    }
    return TSNX_UPDATE_PENDING;
}

const char *tsnx_update_latest(const TsnxUpdate *u) { return u->latest; }

const char *tsnx_update_error(const TsnxUpdate *u) { return u->error; }

void tsnx_update_free(TsnxUpdate *u) {
    if (!u) return;
    if (u->fd >= 0) close(u->fd);
    if (u->tls) tsnx_tls_free(u->tls);
    free(u);
}

int tsnx_version_compare(const char *a, const char *b) {
    for (;;) {
        unsigned long x = 0, y = 0;
        while (*a >= '0' && *a <= '9') x = x * 10 + (unsigned long)(*a++ - '0');
        while (*b >= '0' && *b <= '9') y = y * 10 + (unsigned long)(*b++ - '0');
        if (x != y) return x < y ? -1 : 1;
        const int more_a = *a == '.', more_b = *b == '.';
        if (!more_a && !more_b) return 0;
        if (more_a) a++;
        if (more_b) b++;
    }
}
