// What the sysmodule is doing, for tsnx:ctl clients (the overlay), plus the
// user-facing side effects of state changes: config/tailscale-nx/login.txt
// and an Ultrahand toast while a login is needed, and the pause switch.
#pragma once
#include <stratosphere.hpp>

extern "C" {
#include "tsnx.h"
}
#include "tsnx_ctl.h"

namespace tsnx {
    class Runtime;
}

namespace ams::status {

    // Once the runtime exists. Starts paused if the user left it paused.
    // `connect_notice`: a 5 s toast with our address on the first connection
    // after boot (unless the overlay turned it off).
    void Initialize(::tsnx::Runtime &rt, u32 flags, bool connect_notice);

    // Engine events (engine thread, runtime lock held).
    void OnEvent(const TsnxEvent &ev);

    TsnxCtlStatus Get();
    size_t GetLoginUrl(char *out, size_t cap);
    size_t GetLastError(char *out, size_t cap);

    // Pauses or resumes Tailscale (persisted). Not from the engine thread.
    void SetPaused(bool paused);
    bool IsPaused();

}
