// Memory probe run under the interpose shim: mimics a Moonlight session (a
// TCP control connection plus a fast UDP stream, then a stall where the app
// stops reading) and prints the Rust heap after each phase, twice, to tell a
// one-off high-water mark from a leak.
//
// usage: heap-probe <peer-ip>   (peer runs HTTP on 8080 and the UDP blaster
// on 9000: "go <count> <pps>" streams <count> 1200-byte datagrams back)
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void (*heap_stats)(size_t *, size_t *);
static size_t (*heap_classes)(char *, size_t);

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void report(const char *phase) {
    size_t cur = 0, peak = 0;
    if (heap_stats) heap_stats(&cur, &peak);
    char classes[200] = "";
    if (heap_classes) heap_classes(classes, sizeof classes);
    printf("%-28s rust %4zu KB (peak %4zu KB)  %s\n", phase, cur / 1024, peak / 1024, classes);
    fflush(stdout);
}

static struct sockaddr_in addr(const char *ip, int port) {
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}

#define NUDP 4

// Reads datagrams on every socket for `secs`, sending a small upstream packet
// (input, acks) on each about every 2 ms; returns how many arrived.
static long drain(const int *fds, double secs) {
    char buf[2048];
    long n = 0;
    double end = now() + secs, next_up = 0;
    while (now() < end) {
        int idle = 1;
        for (int i = 0; i < NUDP; i++) {
            ssize_t r = recv(fds[i], buf, sizeof buf, MSG_DONTWAIT);
            if (r > 0) n++, idle = 0;
        }
        if (now() >= next_up) {
            for (int i = 0; i < NUDP; i++) send(fds[i], "ack-and-input-state-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 48, 0);
            next_up = now() + 0.002;
        }
        if (idle) usleep(200);
    }
    return n;
}

static void go(const int *fds, const char *cmd) {
    for (int i = 0; i < NUDP; i++) send(fds[i], cmd, strlen(cmd), 0);
}

static int session(const char *ip, int round) {
    char label[64];
    struct sockaddr_in web = addr(ip, 8080), blaster = addr(ip, 9000);

    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(tcp, (struct sockaddr *)&web, sizeof web) != 0) { perror("tcp connect"); return 1; }
    const char req[] = "GET / HTTP/1.1\r\nHost: peer\r\n\r\n";
    send(tcp, req, sizeof req - 1, 0);
    char buf[4096];
    recv(tcp, buf, sizeof buf, 0);

    // Moonlight retries its connects many times before the stream starts.
    struct sockaddr_in closed = addr(ip, 48010);
    for (int i = 0; i < 20; i++) {
        int c = socket(AF_INET, SOCK_STREAM, 0);
        fcntl(c, F_SETFL, O_NONBLOCK);
        connect(c, (struct sockaddr *)&closed, sizeof closed);
        usleep(20 * 1000);
        close(c);
    }
    snprintf(label, sizeof label, "r%d after connect storm", round);
    report(label);

    int udp[NUDP];
    for (int i = 0; i < NUDP; i++) {
        udp[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (connect(udp[i], (struct sockaddr *)&blaster, sizeof blaster) != 0) { perror("udp connect"); return 1; }
    }
    snprintf(label, sizeof label, "r%d connected", round);
    report(label);

    // Streaming while reading (4 x 1500 pkt/s, ~58 Mbit/s, for 3 s).
    go(udp, "go 4500 1500");
    long got = drain(udp, 3.5);
    snprintf(label, sizeof label, "r%d streamed (%ld pkts)", round, got);
    report(label);

    // Stall: the app stops reading (HOME menu) while the stream continues.
    go(udp, "go 3000 1500");
    usleep(2500 * 1000);
    snprintf(label, sizeof label, "r%d stalled", round);
    report(label);

    got = drain(udp, 2.0);
    snprintf(label, sizeof label, "r%d drained (%ld pkts)", round, got);
    report(label);

    for (int i = 0; i < NUDP; i++) close(udp[i]);
    close(tcp);
    usleep(3000 * 1000);
    snprintf(label, sizeof label, "r%d closed + 3s", round);
    report(label);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: heap-probe <peer-ip>\n"); return 2; }
    // The first socket() starts the engine (TSNX_WAIT_READY waits for peers).
    int warm = socket(AF_INET, SOCK_DGRAM, 0);
    close(warm);
    heap_stats = (void (*)(size_t *, size_t *))dlsym(RTLD_DEFAULT, "tsnx_heap_stats");
    heap_classes = (size_t (*)(char *, size_t))dlsym(RTLD_DEFAULT, "tsnx_heap_classes");
    if (!heap_stats) { fprintf(stderr, "tsnx_heap_stats not found (run under the shim)\n"); return 2; }
    usleep(3000 * 1000);
    report("idle baseline");
    for (int round = 1; round <= 2; round++)
        if (session(argv[1], round)) return 1;
    usleep(5000 * 1000);
    report("final idle");
    return 0;
}
