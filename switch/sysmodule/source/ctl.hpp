// tsnx:ctl: status, login link, pause and stop for clients like the overlay
// (see native/ctl/tsnx_ctl.h). Runs on its own small server thread.
#pragma once

#include <stratosphere.hpp>

namespace ams::ctl {

    // Handles a Stop request: returns TSNX_CTL_STOP_* and sets *detail.
    using StopHandler = u32 (*)(u32 *detail);

    // Registers the service and starts its thread. Logs and returns false
    // on failure (the sysmodule works without it).
    bool Start(StopHandler stop);

}
