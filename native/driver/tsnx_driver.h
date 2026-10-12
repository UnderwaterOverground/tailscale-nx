// Portable (POSIX sockets + poll) driver for the tsnx engine. Runs unchanged
// on macOS/Linux for testing and on Horizon via libnx's BSD socket layer.
#pragma once

#include <poll.h>
#include <stdint.h>

#include "tsnx.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TsnxDriver TsnxDriver;

// Called for every engine status event.
typedef void (*tsnx_event_fn)(void *ctx, const TsnxEvent *ev);

TsnxDriver *tsnx_driver_new(TsnxEngine *engine, tsnx_event_fn on_event, void *ctx);
void tsnx_driver_free(TsnxDriver *d);

// Opens the engine's UDP socket on `port` (0 = any) for direct peer paths,
// and advertises the local endpoint. Returns 0, or -1 on failure (the engine
// then works over DERP only).
int tsnx_driver_open_udp(TsnxDriver *d, uint16_t port);

// The last place the driver entered (a static string, NULL before any): if
// the thread driving it seems stuck, this names where it went last.
const char *tsnx_driver_step(void);

// Re-detects the local IP and re-advertises endpoints (call after network
// changes).
void tsnx_driver_refresh_endpoints(TsnxDriver *d);

// Closes every socket (the engine sees its connections drop and will
// reconnect), e.g. before the console sleeps. Resume reopens the UDP socket
// (on the same port if possible); the engine re-dials when next pumped.
void tsnx_driver_suspend(TsnxDriver *d);
int tsnx_driver_resume(TsnxDriver *d);

// Optional address rewrites for development, "host:port=ip:port,..." (e.g.
// reaching a container hostname through a published port). Copied.
void tsnx_driver_set_connect_map(TsnxDriver *d, const char *map);

// Where Taildrop puts received files. Called on whichever thread drives the
// engine, one file at a time. Failures return an HTTP status for the sender
// (e.g. 507 no space, 500 write error) with a message in why[why_cap].
typedef struct {
    void *ctx;
    // A peer offers `name` (validated: safe in any directory) of `size`
    // bytes (UINT64_MAX = unknown) from device `from`: 0 to take it (the
    // file is then open for writing), or a status to refuse.
    int (*open)(void *ctx, const char *name, uint64_t size, const char *from, char *why, size_t why_cap);
    // Appends data: 0, or a status (the transfer is then cancelled).
    int (*write)(void *ctx, const uint8_t *data, size_t len, char *why, size_t why_cap);
    // ok: everything arrived; save the file (0, or a status). !ok: discard
    // what was written (return value ignored).
    int (*close)(void *ctx, int ok, char *why, size_t why_cap);
} TsnxDropSink;

// Receives Taildrop files on `port` into `sink` (copied). Returns 0, or -1.
int tsnx_driver_set_taildrop(TsnxDriver *d, const TsnxDropSink *sink, uint16_t port);

// Most file descriptors the driver polls (connections + its UDP socket).
#define TSNX_DRIVER_MAX_FDS 33

// Split form of tsnx_driver_run_once, for callers that poll extra fds or
// must not hold a lock while blocked (see native/runtime):
//   n = tsnx_driver_prepare(d, fds, cap, max_wait, &wait);  // fills fds[0..n)
//   poll(fds, n + extra, wait);
//   tsnx_driver_dispatch(d, fds);                           // reads fds[0..n)
int tsnx_driver_prepare(TsnxDriver *d, struct pollfd *fds, int cap, int max_wait_ms, int *wait_ms);
void tsnx_driver_dispatch(TsnxDriver *d, const struct pollfd *fds);

// Performs engine I/O queued since the last call (e.g. after overlay socket
// operations) without waiting.
void tsnx_driver_pump(TsnxDriver *d);

// Performs pending engine I/O, waits up to max_wait_ms for sockets or the
// engine's next deadline, and dispatches results. Returns 0, or -1 on a
// fatal driver error.
int tsnx_driver_run_once(TsnxDriver *d, int max_wait_ms);

// Monotonic clock in nanoseconds, as fed to the engine.
uint64_t tsnx_driver_now_ns(void);

#ifdef __cplusplus
}
#endif
