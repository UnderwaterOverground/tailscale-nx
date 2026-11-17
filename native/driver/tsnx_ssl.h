// TLS through the console's ssl service, for the driver's control and DERP
// connections and the update check: on the Switch the engine has no TLS of
// its own (rustls would add about 224 KB). The service reads and writes the
// socket itself, through a duplicate of ours, so callers poll their own fd
// and call in here when it's ready. Switch only.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TsnxSsl TsnxSsl;

// Opens the ssl service and our context, trusting the console's roots plus
// Let's Encrypt's. check_dates: also reject expired certificates (only
// when the console's clock is right). Returns 0, or the failing Result
// (after a root that failed to import, the service is still usable).
uint32_t tsnx_ssl_init(int check_dates);
// Trusts one more root (DER), e.g. ca_cert= for a self-signed dev server.
uint32_t tsnx_ssl_add_root(const uint8_t *der, size_t len);
void tsnx_ssl_exit(void);

// Starts TLS with server_name over fd, a connected non-blocking TCP socket
// that stays ours (close it after tsnx_ssl_free). NULL on failure, with
// the reason in *rc_out.
TsnxSsl *tsnx_ssl_start(int fd, const char *server_name, uint32_t *rc_out);
// Advances the handshake: 1 done, 0 waiting for the socket to be readable,
// -1 failed (see tsnx_ssl_describe).
int tsnx_ssl_handshake(TsnxSsl *s);
// As recv/send: > 0 bytes, 0 closed (read), or -1 with errno EAGAIN (wait
// for the socket) or EIO (failed). A read returns what the service already
// decrypted before it touches the socket: after readiness, read until
// EAGAIN.
ssize_t tsnx_ssl_read(TsnxSsl *s, void *buf, size_t len);
ssize_t tsnx_ssl_write(TsnxSsl *s, const void *buf, size_t len);
// Why the last call failed, for the log.
void tsnx_ssl_describe(const TsnxSsl *s, char *buf, size_t cap);
void tsnx_ssl_free(TsnxSsl *s);

#ifdef __cplusplus
}
#endif
