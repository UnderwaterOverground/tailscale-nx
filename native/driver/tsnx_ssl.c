// See tsnx_ssl.h.
#ifdef __SWITCH__
#include "tsnx_ssl.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <switch.h>
#include <sys/iosupport.h>

#ifdef TSNX_NO_STDIO
// Builds without newlib's printf (the sysmodule) supply this instead.
int tsnx_snprintf(char *dst, size_t size, const char *fmt, ...);
#define snprintf tsnx_snprintf
#else
#include <stdio.h>
#endif

// The console's list has ISRG Root X1 (10.1.0+), which Tailscale's chains
// end in today (through X2, cross-signed by X1), but not X2 or the newer
// Root YE and YR. GitHub's chain ends in USERTrust ECC, which it has too.
#include "tsnx_ssl_roots.inc"

struct TsnxSsl {
    SslConnection c;
    Result rc;      // the call that failed
    Result verify;  // why the certificate was refused, if it was
};

static SslContext g_ctx;
static bool g_ready;
static u32 g_verify;

// The service's "would block" (2123-0204).
static bool would_block(Result rc) { return R_MODULE(rc) == 123 && R_DESCRIPTION(rc) == 204; }

uint32_t tsnx_ssl_init(int check_dates) {
    if (g_ready) return 0;
    Result rc = sslInitialize(1);
    if (R_FAILED(rc)) return rc;
    // The service picks TLS 1.2 for Tailscale's and GitHub's servers anyway.
    const u32 versions = SslVersion_TlsV12 | (hosversionAtLeast(11, 0, 0) ? SslVersion_TlsV13 : 0);
    rc = sslCreateContext(&g_ctx, versions);
    if (R_FAILED(rc)) {
        sslExit();
        return rc;
    }
    g_ready = true;
    g_verify = SslVerifyOption_PeerCa | SslVerifyOption_HostName | (check_dates ? SslVerifyOption_DateCheck : 0);
    // A root that won't import (reported) leaves the others to try.
    Result first = 0;
    for (size_t i = 0; i < sizeof k_roots / sizeof k_roots[0]; i++) {
        rc = tsnx_ssl_add_root(k_roots[i].der, k_roots[i].len);
        if (R_FAILED(rc) && !first) first = rc;
    }
    return first;
}

uint32_t tsnx_ssl_add_root(const uint8_t *der, size_t len) {
    if (!g_ready) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    u64 id;
    return sslContextImportServerPki(&g_ctx, der, (u32)len, SslCertificateFormat_Der, &id);
}

void tsnx_ssl_exit(void) {
    if (!g_ready) return;
    sslContextClose(&g_ctx);
    sslExit();
    g_ready = false;
}

TsnxSsl *tsnx_ssl_start(int fd, const char *server_name, uint32_t *rc_out) {
    *rc_out = MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    if (!g_ready) return NULL;
    // The socket service's own descriptor for fd, as libnx's fd lookup does
    // (socketSslConnectionSetSocketDescriptor returns -1 for success too
    // once DoNotCloseSocket is set, so it can't tell us whether it worked).
    __handle *h = __get_handle(fd);
    *rc_out = MAKERESULT(Module_Libnx, LibnxError_BadInput);
    if (!h || !h->fileStruct) return NULL;
    const int bsd_fd = *(const int *)h->fileStruct;
    TsnxSsl *s = calloc(1, sizeof *s);
    *rc_out = MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
    if (!s) return NULL;
    Result rc = sslContextCreateConnection(&g_ctx, &s->c);
    if (R_FAILED(rc)) {
        free(s);
        *rc_out = rc;
        return NULL;
    }
    // The service works on a duplicate of the socket, and ours stays open:
    // we poll it, and close it.
    int dup_fd = -1;
    rc = sslConnectionSetOption(&s->c, SslOptionType_DoNotCloseSocket, true);
    if (R_SUCCEEDED(rc)) rc = sslConnectionSetSocketDescriptor(&s->c, bsd_fd, &dup_fd);
    if (R_SUCCEEDED(rc)) rc = sslConnectionSetHostName(&s->c, server_name, (u32)strlen(server_name) + 1);
    if (R_SUCCEEDED(rc)) rc = sslConnectionSetVerifyOption(&s->c, g_verify);
    if (R_SUCCEEDED(rc)) rc = sslConnectionSetIoMode(&s->c, SslIoMode_NonBlocking);
    if (R_FAILED(rc)) {
        tsnx_ssl_free(s);
        *rc_out = rc;
        return NULL;
    }
    *rc_out = 0;
    return s;
}

int tsnx_ssl_handshake(TsnxSsl *s) {
    const Result rc = sslConnectionDoHandshake(&s->c, NULL, NULL, NULL, 0);
    if (R_SUCCEEDED(rc)) return 1;
    if (would_block(rc)) return 0;
    s->rc = rc;
    s->verify = sslConnectionGetVerifyCertError(&s->c);
    return -1;
}

static ssize_t io_result(TsnxSsl *s, Result rc, u32 n) {
    if (R_SUCCEEDED(rc)) return (ssize_t)n;
    if (would_block(rc)) {
        errno = EAGAIN;
    } else {
        errno = EIO;
        s->rc = rc;
    }
    return -1;
}

ssize_t tsnx_ssl_read(TsnxSsl *s, void *buf, size_t len) {
    u32 n = 0;
    const Result rc = sslConnectionRead(&s->c, buf, (u32)len, &n);
    return io_result(s, rc, n);
}

ssize_t tsnx_ssl_write(TsnxSsl *s, const void *buf, size_t len) {
    u32 n = 0;
    const Result rc = sslConnectionWrite(&s->c, buf, (u32)len, &n);
    return io_result(s, rc, n);
}

void tsnx_ssl_describe(const TsnxSsl *s, char *buf, size_t cap) {
    if (R_FAILED(s->verify)) {
        snprintf(buf, cap, "%04u-%04u (certificate: %04u-%04u)", 2000 + R_MODULE(s->rc), R_DESCRIPTION(s->rc),
                 2000 + R_MODULE(s->verify), R_DESCRIPTION(s->verify));
    } else {
        snprintf(buf, cap, "%04u-%04u", 2000 + R_MODULE(s->rc), R_DESCRIPTION(s->rc));
    }
}

void tsnx_ssl_free(TsnxSsl *s) {
    if (!s) return;
    sslConnectionClose(&s->c);
    free(s);
}
#endif
