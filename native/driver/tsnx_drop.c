// See tsnx_drop.h.
#include "tsnx_drop.h"

#include <stdio.h>
#include <string.h>

#ifdef TSNX_NO_STDIO
int tsnx_snprintf(char *dst, size_t size, const char *fmt, ...);
#define snprintf tsnx_snprintf
#endif

// Size as "12.3 MB" etc. for messages.
static void human(char *out, size_t cap, uint64_t n) {
    if (n >= 1000000000ull) {
        snprintf(out, cap, "%u.%u GB", (unsigned)(n / 1000000000ull), (unsigned)(n / 100000000ull % 10));
    } else if (n >= 1000000ull) {
        snprintf(out, cap, "%u.%u MB", (unsigned)(n / 1000000ull), (unsigned)(n / 100000ull % 10));
    } else {
        snprintf(out, cap, "%u KB", (unsigned)((n + 999) / 1000));
    }
}

static void report(TsnxDropDir *s, int saved, const char *name, const char *why) {
    if (s->on_result) s->on_result(s->result_ctx, saved, name, s->written, s->from, why);
}

static int drop_open(void *ctx, const char *name, uint64_t size, const char *from, char *why, size_t why_cap) {
    TsnxDropDir *s = ctx;
    snprintf(s->name, sizeof s->name, "%s", name);
    snprintf(s->from, sizeof s->from, "%s", from ? from : "");
    s->written = 0;
    int k = s->fs->kind(s->dir);
    if (k == 0 && s->fs->mkdir(s->dir) != 0) k = s->fs->kind(s->dir);  // lost a race: fine if it's there now
    else if (k == 0) k = 1;
    if (k != 1) {
        snprintf(why, why_cap, "the Switch can't create its %s folder", s->dir);
        report(s, 0, name, why);
        return 500;
    }
    uint64_t free_bytes, total;
    if (s->fs->space(s->dir, &free_bytes, &total) != 0) {
        snprintf(why, why_cap, "the Switch can't read its SD card's free space");
        report(s, 0, name, why);
        return 500;
    }
    // Leave some of the card free: a full card breaks other software.
    uint64_t reserve = total / 200;
    s->allowance = free_bytes > reserve ? free_bytes - reserve : 0;
    if (size != UINT64_MAX && size > s->allowance) {
        char need[24], have[24];
        human(need, sizeof need, size);
        human(have, sizeof have, s->allowance);
        snprintf(why, why_cap, "not enough space on the Switch's SD card (%s needed, %s available)", need, have);
        report(s, 0, name, why);
        return 507;
    }
    if (snprintf(s->partial, sizeof s->partial, "%s/%s.partial", s->dir, name) >= (int)sizeof s->partial ||
        !(s->file = s->fs->create(s->partial, size))) {
        s->file = NULL;
        if (size != UINT64_MAX && size >= 0xFFFFFFFFull) {
            snprintf(why, why_cap, "the Switch can't create a file of 4 GB or more on its SD card");
        } else {
            snprintf(why, why_cap, "the Switch can't create the file");
        }
        report(s, 0, name, why);
        return 500;
    }
    return 0;
}

static void discard(TsnxDropDir *s) {
    if (s->file) {
        s->fs->close(s->file);
        s->file = NULL;
        s->fs->remove(s->partial);
    }
}

static int drop_write(void *ctx, const uint8_t *data, size_t len, char *why, size_t why_cap) {
    TsnxDropDir *s = ctx;
    if (!s->file) return 500;
    int rc = len > s->allowance - s->written ? 1 : s->fs->write(s->file, s->written, data, len);
    if (rc != 0) {
        snprintf(why, why_cap, rc == 1 ? "the Switch's SD card is full" : "the Switch couldn't write to its SD card");
        discard(s);
        report(s, 0, s->name, why);
        return rc == 1 ? 507 : 500;
    }
    s->written += len;
    return 0;
}

// "name.ext" -> "name (n).ext" (the extension is from the last dot, unless
// the name starts with it).
static int numbered(char *out, size_t cap, const char *dir, const char *name, int n) {
    const char *dot = strrchr(name, '.');
    if (!dot || dot == name) dot = name + strlen(name);
    return snprintf(out, cap, "%s/%.*s (%d)%s", dir, (int)(dot - name), name, n, dot) < (int)cap ? 0 : -1;
}

static int drop_close(void *ctx, int ok, char *why, size_t why_cap) {
    TsnxDropDir *s = ctx;
    if (!s->file) return 500;
    if (!ok) {
        discard(s);
        report(s, 0, s->name, "the transfer was interrupted");
        return 0;
    }
    if (s->fs->close(s->file) != 0) {
        s->file = NULL;
        s->fs->remove(s->partial);
        snprintf(why, why_cap, "the Switch couldn't finish writing to its SD card");
        report(s, 0, s->name, why);
        return 500;
    }
    s->file = NULL;
    // Never overwrite: "photo.jpg", then "photo (1).jpg", ...
    char final[TSNX_DROP_PATH_MAX];
    snprintf(final, sizeof final, "%s/%s", s->dir, s->name);
    for (int n = 1; s->fs->kind(final) != 0; n++) {
        if (n > 99 || numbered(final, sizeof final, s->dir, s->name, n) != 0) {
            s->fs->remove(s->partial);
            snprintf(why, why_cap, "the Switch already has too many files named %s", s->name);
            report(s, 0, s->name, why);
            return 409;
        }
    }
    if (s->fs->rename(s->partial, final) != 0) {
        s->fs->remove(s->partial);
        snprintf(why, why_cap, "the Switch couldn't save the file");
        report(s, 0, s->name, why);
        return 500;
    }
    report(s, 1, final + strlen(s->dir) + 1, "");
    return 0;
}

TsnxDropSink tsnx_drop_dir(TsnxDropDir *state, const TsnxFs *fs, const char *dir, tsnx_drop_result_fn on_result,
                           void *result_ctx) {
    memset(state, 0, sizeof *state);
    state->fs = fs;
    snprintf(state->dir, sizeof state->dir, "%s", dir);
    state->on_result = on_result;
    state->result_ctx = result_ctx;
    TsnxDropSink sink = {state, drop_open, drop_write, drop_close};
    return sink;
}

#if !defined(TSNX_NO_STDIO) && !defined(__SWITCH__)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

static int px_kind(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return errno == ENOENT ? 0 : -1;
    return S_ISDIR(st.st_mode) ? 1 : -1;
}

static int px_mkdir(const char *path) { return mkdir(path, 0755); }

static int px_space(const char *path, uint64_t *free_bytes, uint64_t *total) {
    struct statvfs v;
    if (statvfs(path, &v) != 0) return -1;
    *free_bytes = (uint64_t)v.f_bavail * v.f_frsize;
    *total = (uint64_t)v.f_blocks * v.f_frsize;
    return 0;
}

static void *px_create(const char *path, uint64_t size) {
    (void)size;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    return fd < 0 ? NULL : (void *)(intptr_t)(fd + 1);
}

static int px_write(void *f, uint64_t off, const uint8_t *data, size_t len) {
    int fd = (int)(intptr_t)f - 1;
    while (len > 0) {
        ssize_t n = pwrite(fd, data, len, (off_t)off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return errno == ENOSPC ? 1 : -1;
        data += n;
        len -= (size_t)n;
        off += (uint64_t)n;
    }
    return 0;
}

static int px_close(void *f) { return close((int)(intptr_t)f - 1); }

const TsnxFs tsnx_posix_fs = {px_kind, px_mkdir, px_space, px_create, px_write, px_close, rename, remove};
#endif
