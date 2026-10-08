// See taildrop.hpp.
#include <stratosphere.hpp>

#include "log.hpp"
#include "status.hpp"
#include "taildrop.hpp"
#include "tsnx_drop.h"

namespace ams::taildrop {

    namespace {

        constexpr const char Dir[] = "sdmc:/Taildrop";
        // FAT32 can't hold a file of 4 GB or more: those become "big files"
        // (concatenation files: a folder of parts the file system presents
        // as one file, like installed games on FAT32 cards).
        constexpr u64 BigFileFrom = 0xFFFFFFFFull;

        // One transfer at a time (tsnx_drop.h), so one handle.
        constinit fs::FileHandle g_file = {};
        constinit bool g_open = false;

        int Kind(const char *path) {
            fs::DirectoryEntryType t;
            const Result rc = fs::GetEntryType(std::addressof(t), path);
            if (fs::ResultPathNotFound::Includes(rc)) return 0;
            if (R_FAILED(rc)) return -1;
            return t == fs::DirectoryEntryType_Directory ? 1 : -1;
        }

        int MakeDir(const char *path) { return R_SUCCEEDED(fs::CreateDirectory(path)) ? 0 : -1; }

        int Space(const char *path, uint64_t *free_bytes, uint64_t *total) {
            s64 f = 0, t = 0;
            if (R_FAILED(fs::GetFreeSpaceSize(std::addressof(f), path)) || R_FAILED(fs::GetTotalSpaceSize(std::addressof(t), path)) ||
                f < 0 || t <= 0) {
                return -1;
            }
            *free_bytes = static_cast<u64>(f);
            *total = static_cast<u64>(t);
            return 0;
        }

        void *Create(const char *path, uint64_t size) {
            if (g_open) return nullptr;
            static_cast<void>(fs::DeleteFile(path));
            const int option = size != UINT64_MAX && size >= BigFileFrom ? fs::CreateOption_BigFile : 0;
            if (R_FAILED(fs::CreateFile(path, 0, option))) return nullptr;
            if (R_FAILED(fs::OpenFile(std::addressof(g_file), path, fs::OpenMode_Write | fs::OpenMode_AllowAppend))) {
                static_cast<void>(fs::DeleteFile(path));
                return nullptr;
            }
            g_open = true;
            return std::addressof(g_file);
        }

        int Write(void *file, uint64_t offset, const uint8_t *data, size_t len) {
            const Result rc = fs::WriteFile(*static_cast<fs::FileHandle *>(file), static_cast<s64>(offset), data, len, fs::WriteOption::None);
            if (R_SUCCEEDED(rc)) return 0;
            Log("taildrop: write failed: 0x%x", rc.GetValue());
            return fs::ResultNotEnoughFreeSpace::Includes(rc) ? 1 : -1;
        }

        int Close(void *file) {
            auto *f = static_cast<fs::FileHandle *>(file);
            const Result rc = fs::FlushFile(*f);
            fs::CloseFile(*f);
            g_open = false;
            if (R_FAILED(rc)) Log("taildrop: flush failed: 0x%x", rc.GetValue());
            return R_SUCCEEDED(rc) ? 0 : -1;
        }

        int Rename(const char *from, const char *to) { return R_SUCCEEDED(fs::RenameFile(from, to)) ? 0 : -1; }

        int Remove(const char *path) { return R_SUCCEEDED(fs::DeleteFile(path)) ? 0 : -1; }

        constexpr TsnxFs SdFs = {Kind, MakeDir, Space, Create, Write, Close, Rename, Remove};

        constinit TsnxDropDir g_dir = {};

        void OnResult(void *, int saved, const char *name, uint64_t bytes, const char *from, const char *why) {
            if (saved) {
                Log("taildrop: saved %s (%llu bytes) from %s", name, static_cast<unsigned long long>(bytes), from);
            } else {
                Log("taildrop: %s from %s not saved: %s", name, from, why);
            }
            status::AnnounceFile(saved != 0, name, bytes, from, why);
        }

    }

    bool Start(TsnxDriver *driver) {
        const TsnxDropSink sink = tsnx_drop_dir(std::addressof(g_dir), std::addressof(SdFs), Dir, OnResult, nullptr);
        if (tsnx_driver_set_taildrop(driver, std::addressof(sink), Port) != 0) {
            Log("taildrop: cannot listen on port %u", Port);
            return false;
        }
        Log("taildrop: receiving files into %s", Dir);
        return true;
    }

}
