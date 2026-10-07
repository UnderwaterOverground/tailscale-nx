// Shared application logic for tsnx front ends (host CLI, Switch app):
// key state persistence and the overlay echo self-test.
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "tsnx.h"

#ifdef __cplusplus
extern "C" {
#endif

// Fills buf with cryptographically secure random bytes (platform-provided).
void tsnx_platform_random(uint8_t *buf, size_t len);

#ifndef TSNX_NO_STDIO
// Loads the 32-byte machine, node and disco private keys from `path`,
// generating (and saving) any that are missing. Returns 0 on success.
int tsnx_state_load_or_create(const char *path, uint8_t machine[32], uint8_t node[32], uint8_t disco[32]);
// Replaces the node key in the state file (after TSNX_EVENT_NODE_KEY).
int tsnx_state_set_node(const char *path, const uint8_t node[32]);
#endif

// Wall clock sanity. Consoles often have wrong clocks (dead RTC battery, or
// Nintendo's NTP blocked by DNS filters), and TLS certificate checks need a
// roughly correct date.
//
// Returns `system_unix` if it is plausible: no earlier than the build date and
// no more than TSNX_CLOCK_MAX_AHEAD after it. Otherwise asks `control_url`'s
// host for its HTTP Date header (plain HTTP, port 80) and uses that if it is
// plausible, setting *corrected. Returns 0 if neither is usable.
#define TSNX_CLOCK_MAX_AHEAD (3ull * 365 * 86400)
uint64_t tsnx_sane_unix_time(uint64_t system_unix, const char *control_url, bool *corrected);

// Parses an RFC 7231 IMF-fixdate ("Fri, 02 Oct 2026 10:24:03 GMT"). 0 on error.
uint64_t tsnx_parse_http_date(const char *s);

// TCP + UDP echo against port 7 of a tailnet peer.
typedef struct {
    TsnxAddr target;
    uint64_t started_ns, last_udp_ns;
    int32_t tcp, udp;
    bool tcp_sent;
    char tcp_got[64];
    size_t tcp_got_len;
    bool udp_ok;
    int result;  // 0 running, 1 passed, -1 failed
} TsnxEcho;

// Parses "a.b.c.d" into an IPv4 TsnxAddr. Returns 0 on success.
int tsnx_parse_ipv4(const char *s, uint16_t port, TsnxAddr *out);
void tsnx_echo_init(TsnxEcho *t, const TsnxAddr *target);
// Advances the test; returns its result (0 while still running).
int tsnx_echo_step(TsnxEcho *t, TsnxEngine *e, uint64_t now_ns);

#ifdef __cplusplus
}
#endif
