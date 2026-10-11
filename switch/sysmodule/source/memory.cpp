// See memory.hpp.
#include "memory.hpp"

#include "log.hpp"

namespace ams::memory {

    u64 Own() {
        u64 used = 0;
        return R_SUCCEEDED(svcGetInfo(&used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0)) ? used : 0;
    }

    bool SystemPool(u64 *free_bytes, u64 *total_bytes) {
        u64 handle = 0;
        if (R_FAILED(svcGetInfo(&handle, InfoType_ResourceLimit, INVALID_HANDLE, 0)) || handle == INVALID_HANDLE) return false;
        s64 limit = 0, current = 0;
        const bool ok = R_SUCCEEDED(svcGetResourceLimitLimitValue(&limit, static_cast<Handle>(handle), LimitableResource_Memory)) &&
                        R_SUCCEEDED(svcGetResourceLimitCurrentValue(&current, static_cast<Handle>(handle), LimitableResource_Memory)) &&
                        limit > 0 && current >= 0 && current <= limit;
        svcCloseHandle(static_cast<Handle>(handle));
        if (!ok) return false;
        *free_bytes = static_cast<u64>(limit - current);
        *total_bytes = static_cast<u64>(limit);
        return true;
    }

    void SampleBootLow(u64 now_ns, u64 after_ns) {
        static u64 first = 0, low = UINT64_MAX;
        static bool done = false;
        if (done) return;
        if (!first) first = now_ns;
        u64 free_bytes = 0, total = 0;
        if (SystemPool(&free_bytes, &total)) low = std::min(low, free_bytes);
        if (now_ns - first >= after_ns && low != UINT64_MAX) {
            done = true;
            Log("memory: least free system memory in the %lu s after we started: %lu KB", static_cast<unsigned long>(after_ns / 1'000'000'000ull),
                static_cast<unsigned long>(low / 1024));
        }
    }

}
