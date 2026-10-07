// Hostname resolution for the driver, with a pluggable implementation:
// getaddrinfo by default; a minimal DNS-over-UDP client for environments
// where the system resolver can't be used (Atmosphère sysmodules).
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Resolves `host` (or parses an IPv4 literal) to an IPv4 address in network
// byte order. Returns 0 on success.
typedef int (*tsnx_resolver_fn)(const char *host, uint32_t *ipv4_be);

void tsnx_set_resolver(tsnx_resolver_fn fn);
int tsnx_resolve_ipv4(const char *host, uint32_t *ipv4_be);

// One A-record query to `server_be` (UDP 53), waiting up to timeout_ms.
// Returns 0, or -1 with errno saying why (ETIMEDOUT, EPROTO, ENOENT, or the
// socket call's own error).
int tsnx_dns_query_a(uint32_t server_be, const char *host, uint32_t *ipv4_be, int timeout_ms);

#ifdef __cplusplus
}
#endif
