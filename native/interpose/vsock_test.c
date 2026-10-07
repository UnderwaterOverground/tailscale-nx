// Exercises the socket patterns real apps (Moonlight, curl, ENet, ...) use,
// against a tailnet peer running TCP+UDP echo on port 7. Plain POSIX: run it
// under the interpose shim to test the virtualization layer.
//
//   vsock_test <tailnet peer ip> [<non-tailnet ip:port for pass-through>]
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

static struct sockaddr_in peer;
static int failures;

#define CHECK(cond, what)                                                         \
    do {                                                                          \
        if (!(cond)) {                                                            \
            printf("  FAIL: %s (errno %d: %s)\n", what, errno, strerror(errno)); \
            return 0;                                                             \
        }                                                                         \
    } while (0)

static void report(const char *name, int ok) {
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) failures++;
}

static int wait_fd(int fd, short ev, int ms) {
    struct pollfd p = {fd, ev, 0};
    return poll(&p, 1, ms) == 1 ? p.revents : 0;
}

static int tcp_blocking(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0, "socket");
    CHECK(connect(fd, (struct sockaddr *)&peer, sizeof peer) == 0, "connect");
    CHECK(send(fd, "hello tcp", 9, 0) == 9, "send");
    char buf[32];
    size_t got = 0;
    while (got < 9) {
        ssize_t n = recv(fd, buf + got, sizeof buf - got, 0);
        CHECK(n > 0, "recv");
        got += (size_t)n;
    }
    CHECK(memcmp(buf, "hello tcp", 9) == 0, "echo content");

    struct sockaddr_in me, them;
    socklen_t ml = sizeof me, tl = sizeof them;
    CHECK(getsockname(fd, (struct sockaddr *)&me, &ml) == 0, "getsockname");
    CHECK((ntohl(me.sin_addr.s_addr) & 0xffc00000u) == 0x64400000u, "local address is a tailnet address");
    CHECK(getpeername(fd, (struct sockaddr *)&them, &tl) == 0 && them.sin_addr.s_addr == peer.sin_addr.s_addr &&
              them.sin_port == peer.sin_port,
          "getpeername");
    close(fd);
    return 1;
}

static int tcp_nonblocking(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0, "socket");
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    int rc = connect(fd, (struct sockaddr *)&peer, sizeof peer);
    CHECK(rc == 0 || errno == EINPROGRESS, "connect returns EINPROGRESS");
    CHECK(wait_fd(fd, POLLOUT, 10000) & POLLOUT, "poll POLLOUT");
    int err = -1;
    socklen_t el = sizeof err;
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0, "SO_ERROR == 0");
    CHECK(send(fd, "nonblocking", 11, 0) == 11, "send");
    char buf[32];
    size_t got = 0;
    while (got < 11) {
        CHECK(wait_fd(fd, POLLIN, 5000) & POLLIN, "poll POLLIN");
        ssize_t n = recv(fd, buf + got, sizeof buf - got, 0);
        CHECK(n > 0, "recv");
        got += (size_t)n;
    }
    CHECK(memcmp(buf, "nonblocking", 11) == 0, "echo content");
    errno = 0;
    CHECK(recv(fd, buf, sizeof buf, 0) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK), "empty recv -> EAGAIN");
    close(fd);
    return 1;
}

// Sends `msg` until an echo arrives (UDP may drop the first while paths form).
static int udp_roundtrip(int fd, int connected, const char *msg) {
    char buf[64];
    for (int attempt = 0; attempt < 10; attempt++) {
        ssize_t s = connected ? send(fd, msg, strlen(msg), 0)
                              : sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&peer, sizeof peer);
        CHECK(s == (ssize_t)strlen(msg), "send");
        if (!(wait_fd(fd, POLLIN, 1000) & POLLIN)) continue;
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        CHECK(n == (ssize_t)strlen(msg) && memcmp(buf, msg, (size_t)n) == 0, "echo content");
        CHECK(from.sin_addr.s_addr == peer.sin_addr.s_addr && from.sin_port == peer.sin_port, "source address");
        return 1;
    }
    CHECK(0, "no UDP echo after 10 attempts");
}

static int udp_unconnected(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0, "socket");
    int ok = udp_roundtrip(fd, 0, "udp unconnected");
    close(fd);
    return ok;
}

static int udp_connected(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0, "socket");
    CHECK(connect(fd, (struct sockaddr *)&peer, sizeof peer) == 0, "connect");
    int ok = udp_roundtrip(fd, 1, "udp connected");
    close(fd);
    return ok;
}

// Moonlight style: bind the wildcard address, then talk to the host.
static int udp_bound_any(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0, "socket");
    struct sockaddr_in any = {0};
    any.sin_family = AF_INET;
    CHECK(bind(fd, (struct sockaddr *)&any, sizeof any) == 0, "bind 0.0.0.0:0");
    int ok = udp_roundtrip(fd, 0, "udp bound any");
    close(fd);
    return ok;
}

// A server on 0.0.0.0 listens on the tailnet and the real network; poll()
// must report real-side connections too (sys-ftpd and ftpd accept only after
// poll says the listener is ready).
static int dual_listener_real_side(void) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(l >= 0, "socket");
    int one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in any = {0};
    any.sin_family = AF_INET;
    CHECK(bind(l, (struct sockaddr *)&any, sizeof any) == 0, "bind 0.0.0.0:0");
    CHECK(listen(l, 4) == 0, "listen");
    struct sockaddr_in me = {0};
    socklen_t ml = sizeof me;
    CHECK(getsockname(l, (struct sockaddr *)&me, &ml) == 0, "getsockname");
    fcntl(l, F_SETFL, O_NONBLOCK);
    // The listener has seen no real traffic yet when the connection arrives.
    CHECK(wait_fd(l, POLLIN, 300) == 0, "idle listener not ready");
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in lo = {0};
    lo.sin_family = AF_INET;
    lo.sin_port = me.sin_port;
    lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(connect(c, (struct sockaddr *)&lo, sizeof lo) == 0, "connect over loopback");
    CHECK(wait_fd(l, POLLIN, 3000) & POLLIN, "poll reports the real connection");
    int a = accept(l, NULL, NULL);
    CHECK(a >= 0, "accept");
    close(a);
    close(c);
    close(l);
    return 1;
}

// Servers bind to their tailnet address with port 0 and read the chosen port
// back (ftpd's passive mode).
static int tailnet_ephemeral_listener(void) {
    int c = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(c >= 0 && connect(c, (struct sockaddr *)&peer, sizeof peer) == 0, "connect to learn our address");
    struct sockaddr_in me = {0};
    socklen_t ml = sizeof me;
    CHECK(getsockname(c, (struct sockaddr *)&me, &ml) == 0, "getsockname");
    close(c);
    int l = socket(AF_INET, SOCK_STREAM, 0);
    me.sin_port = 0;
    CHECK(bind(l, (struct sockaddr *)&me, sizeof me) == 0, "bind tailnet address, port 0");
    CHECK(listen(l, 1) == 0, "listen");
    struct sockaddr_in got = {0};
    socklen_t gl = sizeof got;
    CHECK(getsockname(l, (struct sockaddr *)&got, &gl) == 0, "getsockname");
    CHECK(got.sin_port != 0 && got.sin_addr.s_addr == me.sin_addr.s_addr, "a real port on the tailnet address");
    close(l);
    return 1;
}

static int tcp_select(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0, "socket");
    CHECK(connect(fd, (struct sockaddr *)&peer, sizeof peer) == 0, "connect");
    CHECK(write(fd, "select", 6) == 6, "write");
    fd_set r;
    FD_ZERO(&r);
    FD_SET(fd, &r);
    struct timeval tv = {5, 0};
    CHECK(select(fd + 1, &r, NULL, NULL, &tv) == 1 && FD_ISSET(fd, &r), "select readable");
    char buf[16];
    ssize_t n = read(fd, buf, sizeof buf);
    CHECK(n > 0 && memcmp(buf, "select", (size_t)n) == 0, "read echo");
    close(fd);
    return 1;
}

static int passthrough(const char *target) {
    char host[64];
    int port;
    if (sscanf(target, "%63[^:]:%d", host, &port) != 2) return 0;
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, host, &a.sin_addr);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0, "socket");
    CHECK(connect(fd, (struct sockaddr *)&a, sizeof a) == 0, "connect to non-tailnet address");
    struct sockaddr_in me;
    socklen_t ml = sizeof me;
    CHECK(getsockname(fd, (struct sockaddr *)&me, &ml) == 0, "getsockname");
    CHECK((ntohl(me.sin_addr.s_addr) & 0xffc00000u) != 0x64400000u, "real (non-tailnet) local address");
    close(fd);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <peer ip> [passthrough ip:port]\n", argv[0]);
        return 2;
    }
    peer.sin_family = AF_INET;
    peer.sin_port = htons(7);
    if (inet_pton(AF_INET, argv[1], &peer.sin_addr) != 1) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);

    report("tcp blocking + addresses", tcp_blocking());
    report("tcp non-blocking + poll", tcp_nonblocking());
    report("tcp select + read/write", tcp_select());
    report("dual listener: poll sees real connections", dual_listener_real_side());
    report("tailnet listener on an ephemeral port", tailnet_ephemeral_listener());
    report("udp unconnected", udp_unconnected());
    report("udp connected", udp_connected());
    report("udp bound to wildcard", udp_bound_any());
    if (argc > 2) report("pass-through to non-tailnet", passthrough(argv[2]));
    printf(failures ? "%d test(s) failed\n" : "all vsock tests passed\n", failures);
    return failures ? 1 : 0;
}
