// Checks GitHub for a newer tailscale-nx release: one HTTPS request for
// github.com/<repo>/releases/latest, whose redirect names the latest tag.
// Non-blocking after the start: call tsnx_update_step until it returns
// something other than TSNX_UPDATE_PENDING, then tsnx_update_free.
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Where releases are published.
#define TSNX_UPDATE_REPO "UnderwaterOverground/tailscale-nx"

typedef struct TsnxUpdate TsnxUpdate;

enum {
    TSNX_UPDATE_FAILED = -1,  // tsnx_update_error says why
    TSNX_UPDATE_PENDING = 0,
    TSNX_UPDATE_CURRENT = 1,  // no newer release
    TSNX_UPDATE_NEWER = 2,    // tsnx_update_latest has its version
};

// Resolves github.com (blocking, like the driver's connects) and starts
// connecting. `current` is our version ("1.0.1"). The check gives up
// `timeout_ms` after now_ns. NULL only if out of memory.
TsnxUpdate *tsnx_update_start(const char *repo, const char *current, uint64_t now_ns, uint32_t timeout_ms);
int tsnx_update_step(TsnxUpdate *u, uint64_t now_ns);
// The latest release's version without the "v" ("1.1.0"), or "" if unknown.
const char *tsnx_update_latest(const TsnxUpdate *u);
const char *tsnx_update_error(const TsnxUpdate *u);
// Closes the connection.
void tsnx_update_free(TsnxUpdate *u);

// Compares dotted versions numerically ("1.10.0" > "1.9.2"); anything after
// the numbers ("-beta") is ignored. Returns <0, 0 or >0.
int tsnx_version_compare(const char *a, const char *b);

#ifdef __cplusplus
}
#endif
