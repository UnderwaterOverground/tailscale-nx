// tailscale-nx speedtest: TCP and UDP throughput to tools/speedtest-server.py
// and the cost of single socket calls, once per server address (its LAN
// address, then its tailnet address), plus SD card write speed and the
// engine's crypto benchmark. Output goes to nxlink.
//
//   nxlink -s speedtest.nro [+bsct] <server ip> [<server ip> ...]
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <switch.h>

#include "tsnx.h"

#define PORT 5300
#define SECS 8
#define DGRAM 1200

void tsnx_platform_random(uint8_t *buf, size_t len) { randomGet(buf, len); }

_Noreturn void tsnx_platform_panic(const uint8_t *msg, size_t len) {
    printf("PANIC in tsnx core: %.*s\n", (int)len, (const char *)msg);
    abort();
}

static u8 g_buf[64 << 10];

static double now_s(void) { return (double)armTicksToNs(armGetSystemTick()) / 1e9; }

static struct sockaddr_in addr_of(const char *ip) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(PORT)};
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}

static int tcp_open(const char *ip, const char *cmd) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = addr_of(ip);
    if (s < 0 || connect(s, (struct sockaddr *)&a, sizeof a) != 0) {
        printf("  connect %s failed: %d\n", ip, errno);
        if (s >= 0) close(s);
        return -1;
    }
    send(s, cmd, strlen(cmd), 0);
    return s;
}

static void tcp_down(const char *ip) {
    char cmd[32];
    snprintf(cmd, sizeof cmd, "down %d\n", SECS);
    int s = tcp_open(ip, cmd);
    if (s < 0) return;
    double first = 0, last = 0;
    u64 bytes = 0;
    for (;;) {
        ssize_t n = recv(s, g_buf, sizeof g_buf, 0);
        if (n <= 0) break;
        last = now_s();
        if (!bytes) first = last;
        bytes += n;
    }
    close(s);
    printf("  TCP down: %6.1f Mbit/s (%llu bytes)\n", bytes * 8 / (last - first) / 1e6, (unsigned long long)bytes);
}

static void tcp_up(const char *ip) {
    int s = tcp_open(ip, "up\n");
    if (s < 0) return;
    double end = now_s() + SECS;
    while (now_s() < end)
        if (send(s, g_buf, sizeof g_buf, 0) <= 0) break;
    shutdown(s, SHUT_WR);
    char reply[64] = {0};
    ssize_t n = recv(s, reply, sizeof reply - 1, 0);
    close(s);
    unsigned long long bytes = 0;
    double secs = 0;
    if (n <= 0 || sscanf(reply, "%llu %lf", &bytes, &secs) != 2 || secs <= 0) {
        printf("  TCP up: no result\n");
        return;
    }
    printf("  TCP up:   %6.1f Mbit/s (%llu bytes)\n", bytes * 8 / secs / 1e6, bytes);
}

static int udp_open(const char *ip) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = addr_of(ip);
    if (s < 0 || connect(s, (struct sockaddr *)&a, sizeof a) != 0) {
        if (s >= 0) close(s);
        return -1;
    }
    int rcv = 256 << 10;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv);
    struct timeval tv = {0, 200000};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    return s;
}

// Server sends `mbit` Mbit/s of datagrams for SECS; returns the loss in %.
static double udp_down(const char *ip, int mbit) {
    int s = udp_open(ip);
    if (s < 0) return 100;
    u32 id = (u32)armGetSystemTick();
    char cmd[64];
    int n = snprintf(cmd, sizeof cmd, "D %u %d %d", id, mbit * 1000, SECS * 1000);
    send(s, cmd, n, 0);
    u64 got = 0, sent = 0;
    double first = 0, last = 0, idle_since = now_s();
    while (now_s() - idle_since < 2.0) {
        ssize_t r = recv(s, g_buf, sizeof g_buf, 0);
        if (r < 9) {
            if (!got && now_s() - idle_since > 1.0) {
                send(s, cmd, n, 0);  // request lost
                idle_since = now_s();
            }
            continue;
        }
        u32 rid;
        memcpy(&rid, g_buf + 1, 4);
        if (rid != id) continue;
        idle_since = now_s();
        if (g_buf[0] == 'E') {
            memcpy(&sent, g_buf + 5, 8);
            break;
        }
        last = idle_since;
        if (!got) first = last;
        got++;
    }
    close(s);
    if (!sent) sent = got;
    double loss = sent ? 100.0 * (double)(sent - got) / sent : 100;
    printf("  UDP down @%3d: %6.1f Mbit/s received, %5.1f%% loss\n", mbit,
           got > 1 ? got * DGRAM * 8 / (last - first) / 1e6 : 0.0, loss);
    return loss;
}

// Sends `mbit` Mbit/s of datagrams for SECS; returns the loss in %.
static double udp_up(const char *ip, int mbit) {
    int s = udp_open(ip);
    if (s < 0) return 100;
    u32 id = (u32)armGetSystemTick();
    memset(g_buf, 0, DGRAM);
    g_buf[0] = 'U';
    memcpy(g_buf + 1, &id, 4);
    double pps = mbit * 1e6 / 8 / DGRAM;
    double start = now_s();
    u64 sent = 0, errs = 0;
    for (;;) {
        double t = now_s() - start;
        if (t >= SECS) break;
        u64 due = (u64)(pps * t);
        if (sent >= due) {
            svcSleepThread(200000);
            continue;
        }
        if (send(s, g_buf, DGRAM, 0) != DGRAM) errs++;
        sent++;
    }
    double secs = now_s() - start;
    char cmd[32], reply[128];
    int n = snprintf(cmd, sizeof cmd, "R %u", id);
    unsigned long long got = 0;
    double rsecs = 0;
    for (int i = 0; i < 10; i++) {
        send(s, cmd, n, 0);
        ssize_t r = recv(s, reply, sizeof reply - 1, 0);
        if (r > 0) {
            reply[r] = 0;
            if (sscanf(reply, "%llu %lf", &got, &rsecs) == 2) break;
        }
    }
    close(s);
    double loss = sent ? 100.0 * (double)(sent - got) / sent : 100;
    printf("  UDP up   @%3d: %6.1f Mbit/s sent, %6.1f received, %5.1f%% loss (%llu send errors)\n",
           mbit, sent * DGRAM * 8 / secs / 1e6, rsecs > 0 ? got * DGRAM * 8 / rsecs / 1e6 : 0.0, loss,
           (unsigned long long)errs);
    return loss;
}

static void bench(void) {
    static const size_t sizes[] = {1280, 1400};
    for (int i = 0; i < 2; i++) {
        const u32 packets = 20000;
        double t = now_s();
        tsnx_bench_aead(sizes[i], packets);
        t = now_s() - t;
        printf("  chacha20poly1305, %zu-byte packets: %.1f Mbit/s\n", sizes[i],
               sizes[i] * packets * 8.0 / t / 1e6);
    }
    double t = now_s();
    tsnx_bench_x25519(200);
    printf("  x25519: %.0f ops/s\n", 200 / (now_s() - t));
}

// Microseconds per call of each socket operation the data path uses, on a
// UDP socket to `ip` (a tailnet address goes through the sysmodule's engine;
// any other only through the MITM's passthrough).
static void calls(const char *ip) {
    int s = udp_open(ip);
    if (s < 0) return;
    const int n = 2000;
    int v;
    socklen_t len = sizeof v;
    double t = now_s();
    for (int i = 0; i < n; i++) getsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, &len);
    double opt = (now_s() - t) / n * 1e6;
    t = now_s();
    for (int i = 0; i < n; i++) recv(s, g_buf, DGRAM, MSG_DONTWAIT);
    double rcv = (now_s() - t) / n * 1e6;
    memset(g_buf, 0, DGRAM);  // the server ignores datagrams starting with 0
    t = now_s();
    for (int i = 0; i < n; i++) send(s, g_buf, DGRAM, 0);
    double snd = (now_s() - t) / n * 1e6;
    close(s);
    printf("  per call: getsockopt %.0f us, recv (empty) %.0f us, send %d B %.0f us\n", opt, rcv, DGRAM, snd);
}

// SD card write speed by write size, as Taildrop's writes would see it.
static void sd(void) {
    static const size_t sizes[] = {4 << 10, 16 << 10, 64 << 10};
    const size_t total = 16 << 20;
    for (int i = 0; i < 3; i++) {
        FILE *f = fopen("sdmc:/speedtest.tmp", "wb");
        if (!f) {
            printf("  cannot create sdmc:/speedtest.tmp\n");
            return;
        }
        setvbuf(f, NULL, _IONBF, 0);
        double t = now_s(), worst = 0;
        for (size_t done = 0; done < total; done += sizes[i]) {
            double w = now_s();
            if (fwrite(g_buf, 1, sizes[i], f) != sizes[i]) break;
            w = now_s() - w;
            if (w > worst) worst = w;
        }
        fclose(f);
        t = now_s() - t;
        printf("  SD writes of %3zu KB: %5.1f Mbit/s (%.2f ms per write, worst %.0f ms)\n", sizes[i] >> 10,
               total * 8 / t / 1e6, t * 1e3 / (total / sizes[i]), worst * 1e3);
        remove("sdmc:/speedtest.tmp");
    }
}

static const int RATES[] = {10, 15, 20, 25, 30, 35, 40, 50, 60, 80, 100};

static void throughput(const char *ip) {
    tcp_down(ip);
    tcp_up(ip);
    tcp_down(ip);
    tcp_up(ip);
    for (size_t r = 0; r < sizeof RATES / sizeof *RATES; r++)
        if (udp_down(ip, RATES[r]) > 20) break;
    for (size_t r = 0; r < sizeof RATES / sizeof *RATES; r++)
        if (udp_up(ip, RATES[r]) > 20) break;
}

int main(int argc, char **argv) {
    static const SocketInitConfig cfg = {
        .tcp_tx_buf_size = 0x20000,
        .tcp_rx_buf_size = 0x20000,
        .tcp_tx_buf_max_size = 0x100000,
        .tcp_rx_buf_max_size = 0x100000,
        .udp_tx_buf_size = 0x2400,
        .udp_rx_buf_size = 0x40000,
        .sb_efficiency = 4,
        .num_bsd_sessions = 3,
        .bsd_service_type = BsdServiceType_User,
    };
    if (R_FAILED(socketInitialize(&cfg))) {
        socketInitializeDefault();
        printf("(large socket buffers refused; using libnx defaults)\n");
    }
    nxlinkStdio();
    appletSetMediaPlaybackState(true);  // no auto-sleep mid-test
    // Tests: +b crypto, +s SD card, +c call costs, +t throughput (default all;
    // not -b: nxlink would take that as its own option).
    const char *tests = "bsct";
    for (int i = 1; i < argc; i++)
        if (argv[i][0] == '+') tests = argv[i] + 1;
    printf("tailscale-nx speedtest, %d s per test\n", SECS);
    if (strchr(tests, 'b')) {
        printf("\ncrypto (this core):\n");
        bench();
    }
    if (strchr(tests, 's')) {
        printf("\nSD card:\n");
        sd();
    }
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '+') continue;
        printf("\n%s:\n", argv[i]);
        if (strchr(tests, 'c')) calls(argv[i]);
        if (strchr(tests, 't')) throughput(argv[i]);
    }
    printf("done\n");
    socketExit();
    return 0;
}
