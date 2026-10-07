// tsnx:ctl: status, login link and pause for clients like the overlay (see
// native/ctl/tsnx_ctl.h). Runs on its own small server thread.
#pragma once

namespace ams::ctl {

    // Registers the service and starts its thread. Logs and returns false
    // on failure (the sysmodule works without it).
    bool Start();

}
