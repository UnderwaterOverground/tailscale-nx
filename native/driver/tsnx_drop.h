// Saving Taildrop files into a folder: the policy shared by every platform
// (folder creation, the free-space check, writing to "<name>.partial" and
// renaming it once complete, never overwriting). The platform supplies the
// file operations; every failure becomes an answer for the sender, never an
// abort.
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "tsnx_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

// File operations on absolute paths. Return 0 on success unless noted.
typedef struct {
    // 1 = a directory, 0 = nothing there, -1 = something else (or error).
    int (*kind)(const char *path);
    int (*mkdir)(const char *path);
    // Free and total bytes of the file system holding `path`.
    int (*space)(const char *path, uint64_t *free_bytes, uint64_t *total_bytes);
    // Creates (or truncates) a file for writing; NULL on failure. `size` is
    // the expected size (UINT64_MAX = unknown), e.g. to pick a file kind that
    // can exceed FAT32's 4 GB limit.
    void *(*create)(const char *path, uint64_t size);
    // Writes at `offset`. 1 if the disk is full, -1 on other errors.
    int (*write)(void *file, uint64_t offset, const uint8_t *data, size_t len);
    // Flushes and closes.
    int (*close)(void *file);
    int (*rename)(const char *from, const char *to);
    int (*remove)(const char *path);
} TsnxFs;

// Told about every transfer's outcome: saved = 1 with the final file name
// (which may have " (1)" etc. added), or 0 with the reason.
typedef void (*tsnx_drop_result_fn)(void *ctx, int saved, const char *name, uint64_t bytes, const char *from,
                                    const char *why);

#define TSNX_DROP_PATH_MAX 640

typedef struct {
    const TsnxFs *fs;
    char dir[128];
    tsnx_drop_result_fn on_result;
    void *result_ctx;
    // The transfer in progress.
    void *file;
    char name[256], from[64];
    char partial[TSNX_DROP_PATH_MAX];
    uint64_t written, allowance;
} TsnxDropDir;

// Sets up `state` (which must outlive the sink) to save into `dir` (no
// trailing slash; created on first use) and returns the sink for
// tsnx_driver_set_taildrop. Keeps 0.5% of the file system free.
TsnxDropSink tsnx_drop_dir(TsnxDropDir *state, const TsnxFs *fs, const char *dir, tsnx_drop_result_fn on_result,
                           void *result_ctx);

#ifndef __SWITCH__
// File operations for POSIX systems (host builds and tests).
extern const TsnxFs tsnx_posix_fs;
#endif

#ifdef __cplusplus
}
#endif
