// tsnx-app: homebrew front end for the tsnx engine.
//
// Joins the tailnet configured in sdmc:/config/tailscale-nx/config.ini and
// shows status. Buttons: Y = echo self-test against `echo_test` peer,
// X = crypto benchmark, + = exit. Run with `nxlink -s tsnx-app.nro` to stream
// the log back to the development machine.
//
// config.ini:
//   control_url=https://controlplane.tailscale.com
//   auth_key=tskey-auth-...        (optional; otherwise a login URL is shown)
//   hostname=switch
//   echo_test=100.64.0.1           (optional; a peer running TCP/UDP echo on port 7)
//   ca_cert=sdmc:/config/tailscale-nx/ca.der  (optional extra trusted root, DER)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <switch.h>

#include "tsnx.h"
#include "tsnx_app.h"
#include "tsnx_driver.h"

#define CONFIG_DIR "sdmc:/config/tailscale-nx"
#define CONFIG_PATH CONFIG_DIR "/config.ini"
#define STATE_PATH CONFIG_DIR "/state"

typedef struct {
    char control_url[256];
    char auth_key[256];
    char hostname[64];
    char echo_test[64];
    char ca_cert[256];
} Config;

void tsnx_platform_random(uint8_t *buf, size_t len) { randomGet(buf, len); }

_Noreturn void tsnx_platform_panic(const uint8_t *msg, size_t len) {
    printf("\nPANIC in tsnx core: %.*s\n", (int)len, (const char *)msg);
    consoleUpdate(NULL);
    fflush(stdout);
    svcSleepThread(5000000000ULL);
    abort();
}

static void trim(char *s) {
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ')) s[--n] = 0;
}

static int load_config(Config *c) {
    memset(c, 0, sizeof *c);
    strcpy(c->control_url, "https://controlplane.tailscale.com");
    strcpy(c->hostname, "nintendo-switch");
    FILE *f = fopen(CONFIG_PATH, "r");
    if (!f) return -1;
    char line[320];
    while (fgets(line, sizeof line, f)) {
        trim(line);
        char *eq = strchr(line, '=');
        if (!eq || line[0] == '#') continue;
        *eq = 0;
        const char *v = eq + 1;
        if (!strcmp(line, "control_url")) snprintf(c->control_url, sizeof c->control_url, "%s", v);
        if (!strcmp(line, "auth_key")) snprintf(c->auth_key, sizeof c->auth_key, "%s", v);
        if (!strcmp(line, "hostname")) snprintf(c->hostname, sizeof c->hostname, "%s", v);
        if (!strcmp(line, "echo_test")) snprintf(c->echo_test, sizeof c->echo_test, "%s", v);
        if (!strcmp(line, "ca_cert")) snprintf(c->ca_cert, sizeof c->ca_cert, "%s", v);
    }
    fclose(f);
    return 0;
}

static void write_example_config(void) {
    mkdir("sdmc:/config", 0777);
    mkdir(CONFIG_DIR, 0777);
    FILE *f = fopen(CONFIG_PATH, "w");
    if (!f) return;
    fputs("# tailscale-nx configuration\n"
          "control_url=https://controlplane.tailscale.com\n"
          "# auth_key=tskey-auth-...\n"
          "hostname=nintendo-switch\n"
          "# echo_test=100.64.0.1\n",
          f);
    fclose(f);
}

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = n > 0 ? malloc((size_t)n) : NULL;
    *len = buf ? fread(buf, 1, (size_t)n, f) : 0;
    fclose(f);
    return buf;
}

// For saving a replaced node key from on_event.
static TsnxEngine *g_engine;

static void on_event(void *ctx, const TsnxEvent *ev) {
    int *peers = ctx;
    switch (ev->kind) {
        case TSNX_EVENT_NODE_KEY: {
            uint8_t node[32];
            tsnx_engine_node_key(g_engine, node);
            if (tsnx_state_set_node(STATE_PATH, node) != 0) printf("\x1b[31mcannot save the new node key\x1b[0m\n");
            break;
        }
        case TSNX_EVENT_LOGIN_URL:
            printf("\x1b[33mLogin required:\x1b[0m open\n  %s\non another device.\n", ev->text);
            break;
        case TSNX_EVENT_AUTHORIZED:
            printf("\x1b[32mAuthorized.\x1b[0m\n");
            break;
        case TSNX_EVENT_ADDRESSES:
            printf("Tailnet address: \x1b[36m%s\x1b[0m\n", ev->text);
            break;
        case TSNX_EVENT_PEERS:
            *peers = (int)ev->value;
            printf("Peers: %u\n", ev->value);
            break;
        case TSNX_EVENT_HOME_DERP:
            printf("Home DERP region: %u\n", ev->value);
            break;
        case TSNX_EVENT_ENDPOINTS:
            printf("Endpoints: %s\n", ev->text);
            break;
        case TSNX_EVENT_PEER_PATH:
            printf("Path: %s\n", ev->text);
            break;
        case TSNX_EVENT_ERROR:
            printf("\x1b[31m%s\x1b[0m\n", ev->text);
            break;
        default:
            printf("%s\n", ev->text);
    }
}

// The network clock if it has been synced (QuickNTP / Nintendo NTP), else the
// user-set clock.
static uint64_t console_unix_time(void) {
    u64 t = 0;
    if (R_SUCCEEDED(timeGetCurrentTime(TimeType_NetworkSystemClock, &t)) && t > (u64)TSNX_BUILD_UNIX) return t;
    if (R_SUCCEEDED(timeGetCurrentTime(TimeType_UserSystemClock, &t))) return t;
    return (uint64_t)time(NULL);
}

static const char *fmt_date(uint64_t t) {
    static char buf[2][32];
    static int i;
    i ^= 1;
    time_t tt = (time_t)t;
    struct tm tm;
    gmtime_r(&tt, &tm);
    strftime(buf[i], sizeof buf[i], "%Y-%m-%d %H:%M UTC", &tm);
    return buf[i];
}

static void log_line(uint32_t level, const char *msg) {
    printf(level <= 2 ? "\x1b[33m%s\x1b[0m\n" : "%s\n", msg);
}

static void run_bench(void) {
    const size_t packet_len = 1400;
    const u32 packets = 4000;
    u64 start = armGetSystemTick();
    tsnx_bench_aead(packet_len, packets);
    double secs = (double)armTicksToNs(armGetSystemTick() - start) / 1e9;
    printf("chacha20poly1305: %.1f Mbit/s\n", (double)(packet_len * packets) * 8.0 / secs / 1e6);
    start = armGetSystemTick();
    tsnx_bench_x25519(200);
    secs = (double)armTicksToNs(armGetSystemTick() - start) / 1e9;
    printf("x25519: %.0f ops/s\n", 200 / secs);
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    consoleInit(NULL);
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);

    Result rc = socketInitializeDefault();
    if (R_SUCCEEDED(rc)) nxlinkStdio();
    printf("tailscale-nx %s\n", tsnx_version());
    // Core log lines at info level and above (netcheck, paths, recoveries).
    tsnx_set_log_callback(log_line, 3);

    u8 seed[32];
    randomGet(seed, sizeof seed);
    tsnx_seed_rng(seed);
    u32 st = tsnx_selftest();
    if (st != TSNX_SELFTEST_OK) printf("\x1b[31mcrypto selftest FAILED (%u)\x1b[0m\n", st);

    Config cfg;
    if (load_config(&cfg) != 0) {
        write_example_config();
        printf("No config found; wrote an example to %s.\n", CONFIG_PATH);
    }
    uint8_t machine[32], node[32], disco[32];
    TsnxEngine *engine = NULL;
    TsnxDriver *driver = NULL;
    int peers = 0;
    if (R_FAILED(rc)) {
        printf("socketInitializeDefault failed: 0x%x\n", rc);
    } else if (tsnx_state_load_or_create(STATE_PATH, machine, node, disco) != 0) {
        printf("cannot read/write %s\n", STATE_PATH);
    } else {
        size_t ca_len = 0;
        uint8_t *ca = cfg.ca_cert[0] ? read_file(cfg.ca_cert, &ca_len) : NULL;
        if (cfg.ca_cert[0] && !ca) printf("cannot read ca_cert %s\n", cfg.ca_cert);
        TsnxConfig ecfg = {
            .control_url = cfg.control_url,
            .auth_key = cfg.auth_key[0] ? cfg.auth_key : NULL,
            .hostname = cfg.hostname,
            .machine_key = machine,
            .node_key = node,
            .disco_key = disco,
            .extra_root_der = ca,
            .extra_root_len = ca_len,
        };
        printf("Control: %s, hostname %s\n", cfg.control_url, cfg.hostname);
        uint64_t now_unix = console_unix_time();
        bool corrected = false;
        uint64_t unix_time = tsnx_sane_unix_time(now_unix, cfg.control_url, &corrected);
        if (corrected) {
            printf("\x1b[33mConsole clock looks wrong (%s); using the server's time (%s).\n"
                   "Fix it with the QuickNTP overlay to avoid this.\x1b[0m\n",
                   fmt_date(now_unix), fmt_date(unix_time));
        } else if (unix_time == 0) {
            printf("\x1b[31mConsole clock looks wrong (%s) and the server's time is unavailable.\n"
                   "TLS will fail: set the clock (QuickNTP overlay or System Settings).\x1b[0m\n",
                   fmt_date(now_unix));
            unix_time = now_unix;
        }
        engine = g_engine = tsnx_engine_new(&ecfg, tsnx_driver_now_ns(), unix_time);
        if (engine) driver = tsnx_driver_new(engine, on_event, &peers);
        if (!driver) printf("engine init failed\n");
        // Tailscale's default port; a stable port keeps NAT mappings stable.
        if (driver && tsnx_driver_open_udp(driver, 41641) != 0 && tsnx_driver_open_udp(driver, 0) != 0)
            printf("no UDP socket: DERP relay only\n");
    }
    printf("\nY: echo test   X: benchmark   +: exit\n\n");

    TsnxEcho echo;
    bool echo_running = false;
    while (appletMainLoop()) {
        padUpdate(&pad);
        u64 down = padGetButtonsDown(&pad);
        if (down & HidNpadButton_Plus) break;
        if (down & HidNpadButton_X) run_bench();
        if ((down & HidNpadButton_Y) && driver) {
            TsnxAddr target;
            if (!cfg.echo_test[0] || tsnx_parse_ipv4(cfg.echo_test, 7, &target) != 0) {
                printf("set echo_test=<peer ip> in config.ini\n");
            } else if (peers == 0) {
                printf("not connected to the tailnet yet\n");
            } else {
                printf("echo test against %s:7 ...\n", cfg.echo_test);
                tsnx_echo_init(&echo, &target);
                echo_running = true;
            }
        }
        if (driver) {
            // Short waits keep the UI responsive; the engine is event-driven.
            if (tsnx_driver_run_once(driver, 16) != 0) printf("driver error\n");
            if (echo_running) {
                int r = tsnx_echo_step(&echo, engine, tsnx_driver_now_ns());
                if (r) {
                    printf(r > 0 ? "\x1b[32mecho test PASSED\x1b[0m\n" : "\x1b[31mecho test FAILED\x1b[0m\n");
                    echo_running = false;
                }
            }
        }
        consoleUpdate(NULL);
    }

    tsnx_driver_free(driver);
    tsnx_engine_free(engine);
    socketExit();
    consoleExit(NULL);
    return 0;
}
