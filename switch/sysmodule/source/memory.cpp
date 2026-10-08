// See memory.hpp.
#include "memory.hpp"

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

}
