// Memory figures: ours (fixed at launch) and the system pool's, which every
// sysmodule, Nintendo's included, draws from.
#pragma once
#include <stratosphere.hpp>

namespace ams::memory {

    // What the kernel charges us: code, data, heap and main stack.
    u64 Own();

    // Free and total bytes of the memory pool we were launched in.
    bool SystemPool(u64 *free_bytes, u64 *total_bytes);

}
