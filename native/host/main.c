// tsnx-c: host build of the C driver + FFI, for testing on the development
// machine exactly the code paths the Switch app uses.
//
//   tsnx-c --control URL [--authkey K] [--hostname H] [--state FILE]
//          [--extra-root CA.der] [--echo-test 100.x.y.z]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tsnx.h"
#include "tsnx_app.h"
#include "tsnx_driver.h"

void tsnx_platform_random(uint8_t *buf, size_t len) { arc4random_buf(buf, len); }

static const char *arg(int argc, char **argv, const char *name) {
    for (int i = 1; i + 1 < argc; i++)
        if (!strcmp(argv[i], name)) return argv[i + 1];
    return NULL;
}

static int g_peers;

static void on_event(void *ctx, const TsnxEvent *ev) {
    (void)ctx;
    static const char *names[] = {"log", "login-url", "authorized", "addresses", "peers",
                                  "home-derp", "error", "endpoints", "peer-path"};
    const char *name = ev->kind < sizeof names / sizeof *names ? names[ev->kind] : "?";
    if (ev->kind == TSNX_EVENT_PEERS) g_peers = (int)ev->value;
    printf("[event] %s value=%u %s\n", name, ev->value, ev->text);
    fflush(stdout);
}

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)n);
    *len = fread(buf, 1, (size_t)n, f);
    fclose(f);
    return buf;
}

int main(int argc, char **argv) {
    const char *control = arg(argc, argv, "--control");
    if (!control) {
        fprintf(stderr, "usage: %s --control URL [--authkey K] [--hostname H] [--state FILE] "
                        "[--extra-root CA.der] [--echo-test IP]\n", argv[0]);
        return 2;
    }
    uint8_t seed[32];
    tsnx_platform_random(seed, sizeof seed);
    tsnx_seed_rng(seed);

    uint8_t machine[32], node[32], disco[32];
    const char *state = arg(argc, argv, "--state");
    if (tsnx_state_load_or_create(state ? state : "tsnx-c.state", machine, node, disco) != 0) {
        fprintf(stderr, "cannot load/create state\n");
        return 1;
    }
    size_t root_len = 0;
    uint8_t *root = NULL;
    const char *root_path = arg(argc, argv, "--extra-root");
    if (root_path && !(root = read_file(root_path, &root_len))) {
        fprintf(stderr, "cannot read %s\n", root_path);
        return 1;
    }
    const char *hostname = arg(argc, argv, "--hostname");
    TsnxConfig cfg = {
        .control_url = control,
        .auth_key = arg(argc, argv, "--authkey"),
        .hostname = hostname ? hostname : "tsnx-c",
        .machine_key = machine,
        .node_key = node,
        .disco_key = disco,
        .extra_root_der = root,
        .extra_root_len = root_len,
    };
    bool corrected = false;
    uint64_t unix_time = tsnx_sane_unix_time((uint64_t)time(NULL), control, &corrected);
    if (corrected) fprintf(stderr, "warning: system clock implausible; using the server's Date\n");
    if (unix_time == 0) unix_time = (uint64_t)time(NULL);
    TsnxEngine *engine = tsnx_engine_new(&cfg, tsnx_driver_now_ns(), unix_time);
    if (!engine) {
        fprintf(stderr, "tsnx_engine_new failed\n");
        return 1;
    }
    TsnxDriver *driver = tsnx_driver_new(engine, on_event, NULL);
    tsnx_driver_set_connect_map(driver, getenv("TSNX_CONNECT_MAP"));
    const char *port = arg(argc, argv, "--port");
    if (tsnx_driver_open_udp(driver, port ? (uint16_t)atoi(port) : 0) != 0)
        fprintf(stderr, "warning: no UDP socket; DERP only\n");

    const char *echo_ip = arg(argc, argv, "--echo-test");
    TsnxEcho echo;
    if (echo_ip) {
        TsnxAddr target;
        if (tsnx_parse_ipv4(echo_ip, 7, &target) != 0) {
            fprintf(stderr, "bad --echo-test address\n");
            return 2;
        }
        tsnx_echo_init(&echo, &target);
    }
    for (;;) {
        if (tsnx_driver_run_once(driver, 50) != 0) {
            fprintf(stderr, "driver error\n");
            return 1;
        }
        if (echo_ip && g_peers > 0) {
            int r = tsnx_echo_step(&echo, engine, tsnx_driver_now_ns());
            if (r) {
                printf("echo test %s\n", r > 0 ? "PASSED" : "FAILED");
                return r > 0 ? 0 : 1;
            }
        }
    }
}
