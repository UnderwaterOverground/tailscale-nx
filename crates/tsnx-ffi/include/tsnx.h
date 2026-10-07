// C interface to the tsnx Rust core (crates/tsnx-ffi).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Selftest failure codes returned by tsnx_selftest().
enum tsnx_selftest_failure {
    TSNX_SELFTEST_OK = 0,
    TSNX_SELFTEST_X25519 = 1,
    TSNX_SELFTEST_AEAD_SEAL = 2,
    TSNX_SELFTEST_AEAD_OPEN = 3,
    TSNX_SELFTEST_AEAD_TAMPER = 4,
    TSNX_SELFTEST_BLAKE2S = 5,
};

const char *tsnx_version(void);
uint32_t tsnx_selftest(void);
uint64_t tsnx_bench_aead(size_t packet_len, uint32_t iterations);
uint64_t tsnx_bench_x25519(uint32_t iterations);

// Routes the core's log records to cb (level 1 error .. 5 trace; msg valid
// only during the call). max_level 0 disables logging.
typedef void (*tsnx_log_fn)(uint32_t level, const char *msg);
void tsnx_set_log_callback(tsnx_log_fn cb, uint32_t max_level);

// Rust heap usage (bytes): current and high-water mark.
void tsnx_heap_stats(size_t *current, size_t *peak);

// Live Rust heap by allocation size class as text ("<=64:12K/310 ..." =
// KB/allocations per class), NUL-terminated. Returns the length written.
size_t tsnx_heap_classes(char *buf, size_t len);

// Seeds the core's CSPRNG with 32 bytes of entropy. Call once at startup.
void tsnx_seed_rng(const uint8_t seed[32]);
// Wall-clock time (Unix seconds) used for certificate validity checks.
void tsnx_set_unix_time(uint64_t unix_secs);

// Standalone TLS 1.3 session; the caller moves bytes between it and a socket.
typedef struct TsnxTls TsnxTls;
#define TSNX_TLS_ESTABLISHED 1u
#define TSNX_TLS_PEER_CLOSED 2u
#define TSNX_TLS_FAILED 4u
TsnxTls *tsnx_tls_new(const char *server_name);
void tsnx_tls_free(TsnxTls *s);
int tsnx_tls_feed(TsnxTls *s, const uint8_t *data, size_t len);
int tsnx_tls_write(TsnxTls *s, const uint8_t *data, size_t len);
size_t tsnx_tls_take_outgoing(TsnxTls *s, uint8_t *buf, size_t cap);
size_t tsnx_tls_read(TsnxTls *s, uint8_t *buf, size_t cap);
uint32_t tsnx_tls_state(const TsnxTls *s);
const char *tsnx_tls_last_error(const TsnxTls *s);

// ---- Engine ----------------------------------------------------------------
// A complete Tailscale node. The caller owns sockets and the clock: perform the
// I/O it requests, report results back, and call tsnx_engine_timeout by
// tsnx_engine_next_deadline. Times are monotonic nanoseconds.

typedef struct TsnxEngine TsnxEngine;

typedef struct {
    const char *control_url;  // e.g. "https://controlplane.tailscale.com"
    const char *auth_key;     // may be NULL (interactive login)
    const char *hostname;
    const uint8_t *machine_key;  // 32-byte private keys, persisted by the caller
    const uint8_t *node_key;
    const uint8_t *disco_key;    // persist too (NULL = new per run; peers then reset sessions)
    const uint8_t *extra_root_der;  // optional trusted root (DER), for dev servers
    size_t extra_root_len;
} TsnxConfig;

#define TSNX_IO_CONNECT 1u  // resolve host (or parse IP literal), TCP connect to port
#define TSNX_IO_SEND 2u     // write data to connection id
#define TSNX_IO_CLOSE 3u    // close connection id
#define TSNX_IO_SEND_UDP 4u // send data as one datagram to addr from the engine's UDP socket

typedef struct {
    uint8_t family;  // 4 or 6
    uint8_t ip[16];  // IPv4 in the first 4 bytes
    uint16_t port;
} TsnxAddr;

typedef struct {
    uint32_t kind;
    uint32_t id;
    const char *host;
    uint16_t port;
    const uint8_t *data;  // valid until the next tsnx_engine_poll_io
    size_t len;
    TsnxAddr addr;        // SEND_UDP destination
} TsnxIo;

#define TSNX_EVENT_LOG 0u
#define TSNX_EVENT_LOGIN_URL 1u
#define TSNX_EVENT_AUTHORIZED 2u
#define TSNX_EVENT_ADDRESSES 3u
#define TSNX_EVENT_PEERS 4u
#define TSNX_EVENT_HOME_DERP 5u
#define TSNX_EVENT_ERROR 6u
#define TSNX_EVENT_ENDPOINTS 7u  // our advertised direct endpoints (text)
#define TSNX_EVENT_PEER_PATH 8u  // value 1 = direct, 0 = DERP; text describes it
// Our node key expired and was replaced: save tsnx_engine_node_key() as the
// state file's node= key (no text; the key is never put in an event).
#define TSNX_EVENT_NODE_KEY 9u

typedef struct {
    uint32_t kind;
    uint32_t value;    // peer count, DERP region, ...
    const char *text;  // valid until the next tsnx_engine_poll_event
} TsnxEvent;

TsnxEngine *tsnx_engine_new(const TsnxConfig *cfg, uint64_t now_ns, uint64_t unix_secs);
void tsnx_engine_free(TsnxEngine *e);
bool tsnx_engine_poll_io(TsnxEngine *e, TsnxIo *out);
bool tsnx_engine_poll_event(TsnxEngine *e, TsnxEvent *out);
void tsnx_engine_connected(TsnxEngine *e, uint32_t id, uint64_t now_ns);
void tsnx_engine_data(TsnxEngine *e, uint32_t id, const uint8_t *data, size_t len, uint64_t now_ns);
void tsnx_engine_closed(TsnxEngine *e, uint32_t id, uint64_t now_ns);
// A datagram arrived on the engine's UDP socket.
void tsnx_engine_udp(TsnxEngine *e, const TsnxAddr *src, const uint8_t *data, size_t len, uint64_t now_ns);
// Local UDP endpoints (interface address + bound port) to advertise to peers.
void tsnx_engine_set_local_endpoints(TsnxEngine *e, const TsnxAddr *eps, size_t n, uint64_t now_ns);
void tsnx_engine_timeout(TsnxEngine *e, uint64_t now_ns);
uint64_t tsnx_engine_next_deadline(TsnxEngine *e);

// ---- Overlay sockets (tailnet side) -------------------------------------------
// Non-blocking. Ids are > 0; errors are negative TSNX_E* codes.

#define TSNX_EAGAIN (-1)
#define TSNX_ENOTCONN (-2)
#define TSNX_EBADF (-3)
#define TSNX_EADDRINUSE (-4)
#define TSNX_ECONNREFUSED (-5)
#define TSNX_ECONNRESET (-6)
#define TSNX_EINVAL (-7)
#define TSNX_ENOBUFS (-8)

#define TSNX_READABLE 1u
#define TSNX_WRITABLE 2u
#define TSNX_HUP 4u

int32_t tsnx_net_tcp_connect(TsnxEngine *e, const TsnxAddr *dst);
int32_t tsnx_net_tcp_listen(TsnxEngine *e, uint16_t port, uint32_t backlog);
int32_t tsnx_net_tcp_accept(TsnxEngine *e, int32_t id, TsnxAddr *peer);
int32_t tsnx_net_send(TsnxEngine *e, int32_t id, const uint8_t *data, size_t len);
int32_t tsnx_net_recv(TsnxEngine *e, int32_t id, uint8_t *buf, size_t len);
int32_t tsnx_net_shutdown(TsnxEngine *e, int32_t id);
int32_t tsnx_net_udp_bind(TsnxEngine *e, uint16_t port);
int32_t tsnx_net_udp_sendto(TsnxEngine *e, int32_t id, const uint8_t *data, size_t len, const TsnxAddr *dst);
int32_t tsnx_net_udp_recvfrom(TsnxEngine *e, int32_t id, uint8_t *buf, size_t len, TsnxAddr *src);
uint32_t tsnx_net_readiness(TsnxEngine *e, int32_t id);
// Writes "a.b.c.d name\n" for this node and every peer (MagicDNS names, no
// trailing dot), NUL-terminated and truncated to cap. Returns the full length.
size_t tsnx_engine_hosts(TsnxEngine *e, char *buf, size_t cap);
// Our current private node key (32 bytes), for the state file.
void tsnx_engine_node_key(TsnxEngine *e, uint8_t out[32]);
// Bytes of overlay socket buffers in use (TCP buffers, queued datagrams).
size_t tsnx_net_buffer_usage(TsnxEngine *e);
// Most bytes of overlay socket buffers allowed at once (new TCP connections
// get smaller buffers as it fills; past it they fail with TSNX_ENOBUFS).
void tsnx_net_set_budget(TsnxEngine *e, size_t bytes);
void tsnx_net_close(TsnxEngine *e, int32_t id);
int32_t tsnx_net_local_addr(TsnxEngine *e, int32_t id, TsnxAddr *out);
int32_t tsnx_net_peer_addr(TsnxEngine *e, int32_t id, TsnxAddr *out);

// Must be provided by the embedding program on no_std targets. Called with a
// (non NUL-terminated) panic message; must not return.
#ifdef __cplusplus
[[noreturn]]
#else
_Noreturn
#endif
void tsnx_platform_panic(const uint8_t *msg, size_t len);

#ifdef __cplusplus
}
#endif
