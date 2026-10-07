// See tsnx_dns.h.
#include "tsnx_dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int resolve_getaddrinfo(const char *host, uint32_t *out) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;
    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    return 0;
}

static tsnx_resolver_fn g_resolver = resolve_getaddrinfo;

void tsnx_set_resolver(tsnx_resolver_fn fn) { g_resolver = fn ? fn : resolve_getaddrinfo; }

int tsnx_resolve_ipv4(const char *host, uint32_t *out) {
    struct in_addr a;
    if (inet_pton(AF_INET, host, &a) == 1) {
        *out = a.s_addr;
        return 0;
    }
    return g_resolver(host, out);
}

int tsnx_dns_query_a(uint32_t server_be, const char *host, uint32_t *out, int timeout_ms) {
    // Header: id, flags (recursion desired), 1 question.
    unsigned char q[300];
    size_t n = 0;
    uint16_t id = (uint16_t)((uintptr_t)&q ^ (uintptr_t)host);
    q[n++] = (unsigned char)(id >> 8);
    q[n++] = (unsigned char)id;
    q[n++] = 0x01;
    q[n++] = 0x00;
    q[n++] = 0;
    q[n++] = 1;
    memset(q + n, 0, 6);
    n += 6;
    // QNAME as labels.
    const char *p = host;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len == 0 || len > 63 || n + len + 6 > sizeof q) return -1;
        q[n++] = (unsigned char)len;
        memcpy(q + n, p, len);
        n += len;
        p += len + (dot ? 1 : 0);
        if (!dot) break;
    }
    q[n++] = 0;
    q[n++] = 0;
    q[n++] = 1;  // QTYPE A
    q[n++] = 0;
    q[n++] = 1;  // QCLASS IN

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(53);
    to.sin_addr.s_addr = server_be;
    int rc = -1;
    int err = 0;
    if (sendto(fd, q, n, 0, (struct sockaddr *)&to, sizeof to) != (ssize_t)n) {
        err = errno;
    } else {
        struct pollfd pfd = {fd, POLLIN, 0};
        unsigned char r[1500];
        ssize_t got = 0;
        int ready = poll(&pfd, 1, timeout_ms);
        if (ready != 1) {
            err = ready == 0 ? ETIMEDOUT : errno;
        } else if ((got = recv(fd, r, sizeof r, 0)) <= 12) {
            err = got < 0 ? errno : EPROTO;
        } else if (r[0] != q[0] || r[1] != q[1] || (r[3] & 0x0f) != 0) {
            err = EPROTO;  // mismatched id or an error rcode (e.g. NXDOMAIN)
        } else {
            size_t an = ((size_t)r[6] << 8) | r[7];
            size_t off = n;  // answers follow the echoed question
            for (size_t i = 0; i < an && off + 12 <= (size_t)got; i++) {
                // NAME: a compression pointer or labels.
                if ((r[off] & 0xc0) == 0xc0) {
                    off += 2;
                } else {
                    while (off < (size_t)got && r[off]) off += r[off] + 1;
                    off++;
                }
                if (off + 10 > (size_t)got) break;
                uint16_t type = (uint16_t)((r[off] << 8) | r[off + 1]);
                uint16_t rdlen = (uint16_t)((r[off + 8] << 8) | r[off + 9]);
                off += 10;
                if (off + rdlen > (size_t)got) break;
                if (type == 1 && rdlen == 4) {
                    memcpy(out, r + off, 4);
                    rc = 0;
                    break;
                }
                off += rdlen;  // e.g. CNAME
            }
            if (rc != 0) err = ENOENT;  // no A record
        }
    }
    close(fd);
    errno = err;
    return rc;
}
