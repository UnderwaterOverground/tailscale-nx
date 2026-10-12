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

    // A newer release (version without the "v") is out: a toast saying so.
    void AnnounceUpdate(const char *latest);

    // The engine loop ran a round (engine thread); GetStatus reports how
    // long ago, so a stuck engine shows as such in the overlay.
    void EngineRan(u64 now_ns);
    // What the engine loop is busy with outside the engine (nullptr when
    // done), named in the log if it gets stuck there.
    void EngineStep(const char *what);
    // Whether the console has an internet connection (engine thread).
    void SetOffline(bool offline);

    // Engine events (engine thread, runtime lock held).
    void OnEvent(const TsnxEvent &ev);

    TsnxCtlStatus Get();
    size_t GetLoginUrl(char *out, size_t cap);
    size_t GetLastError(char *out, size_t cap);

    // A Taildrop transfer ended: a short toast either way.
    void AnnounceFile(bool saved, const char *name, u64 bytes, const char *from, const char *why);

    // Pauses or resumes Tailscale (persisted). Not from the engine thread.
    void SetPaused(bool paused);
    bool IsPaused();
    // Joined the tailnet (not starting, logging in or paused).
    bool IsConnected();

    // Stopped from the overlay: TSNX_CTL_STOPPING from now on, and no login
    // prompt left behind for a process that is going away.
    void SetStopping();

}
