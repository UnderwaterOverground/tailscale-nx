// Tests for tsnx_drop.c on a temporary folder (make drop-test).
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tsnx_drop.h"

static uint64_t fake_free = UINT64_MAX;
static int full_after = -1;  // fail writes with "disk full" after this many bytes
static int real_space(const char *p, uint64_t *f, uint64_t *t) {
    int rc = tsnx_posix_fs.space(p, f, t);
    if (fake_free != UINT64_MAX) *f = fake_free, *t = 100000000;
    return rc;
}
static int limited_write(void *f, uint64_t off, const uint8_t *d, size_t n) {
    if (full_after >= 0 && off + n > (uint64_t)full_after) return 1;
    return tsnx_posix_fs.write(f, off, d, n);
}

static char last[512];
static void on_result(void *ctx, int saved, const char *name, uint64_t bytes, const char *from, const char *why) {
    (void)ctx;
    snprintf(last, sizeof last, "%d|%s|%llu|%s|%s", saved, name, (unsigned long long)bytes, from, why);
}

static int exists(const char *dir, const char *name) {
    char p[600];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    struct stat st;
    return stat(p, &st) == 0;
}

static int send_file(TsnxDropSink *s, const char *name, const char *data, int declare) {
    char why[160] = "";
    size_t len = strlen(data);
    int st = s->open(s->ctx, name, declare ? len : UINT64_MAX, "laptop", why, sizeof why);
    if (st) return st;
    for (size_t i = 0; i < len; i += 3) {
        size_t n = len - i < 3 ? len - i : 3;
        if ((st = s->write(s->ctx, (const uint8_t *)data + i, n, why, sizeof why))) return st;
    }
    return s->close(s->ctx, 1, why, sizeof why);
}

int main(void) {
    char base[] = "/tmp/tsnx-drop-XXXXXX";
    assert(mkdtemp(base));
    char dir[256];
    snprintf(dir, sizeof dir, "%s/Taildrop", base);
    TsnxFs fs = tsnx_posix_fs;
    fs.space = real_space;
    fs.write = limited_write;
    TsnxDropDir state;
    TsnxDropSink s = tsnx_drop_dir(&state, &fs, dir, on_result, NULL);

    // Creates the folder, saves, never overwrites.
    assert(send_file(&s, "a.txt", "hello", 1) == 0 && exists(dir, "a.txt"));
    assert(strcmp(last, "1|a.txt|5|laptop|") == 0);
    assert(send_file(&s, "a.txt", "again", 0) == 0 && exists(dir, "a (1).txt"));
    assert(send_file(&s, "a.txt", "third", 1) == 0 && exists(dir, "a (2).txt"));
    assert(send_file(&s, ".bashrc", "x", 1) == 0 && send_file(&s, ".bashrc", "x", 1) == 0 && exists(dir, ".bashrc (1)"));
    assert(!exists(dir, "a.txt.partial"));

    // Too big for the space left (0.5% of 100 MB kept free): refused up front.
    fake_free = 600000;
    assert(send_file(&s, "big.bin", "0123456789", 1) == 0);
    char big[200001];
    memset(big, 'x', sizeof big - 1);
    big[sizeof big - 1] = 0;
    assert(send_file(&s, "huge.bin", big, 1) == 507 && !exists(dir, "huge.bin.partial"));
    assert(strstr(last, "not enough space") != NULL);
    // Unknown size: stopped once it reaches the allowance, partial removed.
    assert(send_file(&s, "stream.bin", big, 0) == 507 && !exists(dir, "stream.bin.partial") && !exists(dir, "stream.bin"));
    fake_free = UINT64_MAX;

    // Disk full mid-write.
    full_after = 4;
    assert(send_file(&s, "full.bin", "0123456789", 1) == 507 && !exists(dir, "full.bin.partial"));
    full_after = -1;

    // Interrupted: discarded.
    char why[64];
    assert(s.open(s.ctx, "cut.bin", 10, "laptop", why, sizeof why) == 0);
    assert(s.write(s.ctx, (const uint8_t *)"abc", 3, why, sizeof why) == 0);
    assert(exists(dir, "cut.bin.partial"));
    s.close(s.ctx, 0, why, sizeof why);
    assert(!exists(dir, "cut.bin.partial") && !exists(dir, "cut.bin"));

    // The folder name taken by a file: refused cleanly.
    char dir2[300];
    snprintf(dir2, sizeof dir2, "%s/NotADir", base);
    FILE *f = fopen(dir2, "w");
    fclose(f);
    TsnxDropDir state2;
    TsnxDropSink s2 = tsnx_drop_dir(&state2, &fs, dir2, on_result, NULL);
    assert(send_file(&s2, "a.txt", "x", 1) == 500 && strstr(last, "can't create its") != NULL);

    // An unwritable folder: refused cleanly.
    if (geteuid() != 0) {
        chmod(dir, 0555);
        assert(send_file(&s, "ro.txt", "x", 1) == 500);
        chmod(dir, 0755);
    }
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf %s", base);
    system(cmd);
    puts("drop-test: ok");
    return 0;
}
