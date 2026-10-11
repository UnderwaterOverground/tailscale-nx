// bsd:u MITM: homebrew sockets that talk to tailnet addresses (100.64/10,
// fd7a:115c:a1e0::/48) are served by the tsnx engine's overlay sockets via the
// portable socket-virtualization layer (native/vsock); everything else is
// forwarded to the real bsd:u untouched.
#pragma once

#include <stratosphere.hpp>

namespace tsnx {
    class Runtime;
}

namespace ams::bsd_mitm {

    enum class Scope {
        Off,       // no MITM
        Homebrew,  // hbloader-launched programs (NROs) only
    };

    // Registers the MITM and starts its server threads (returns at once).
    // Returns false, after logging why, if it cannot run safely.
    //
    // `sys_ftpd`: also serve sys-ftpd (a sysmodule, so not covered by the
    // homebrew scope), making it reachable on the tailnet. It talks to bsd:s,
    // which every system service shares, so that MITM gets its own threads
    // and matches sys-ftpd alone; sys-ftpd is restarted so its sessions,
    // opened at boot before us, come through the MITM.
    //
    // `titles`: config.ini's mitm_titles, program IDs (16 hex digits, 0x
    // optional, comma or space separated) served like homebrew. Home-screen
    // forwarders run as their own title rather than through hbloader; the
    // running application is served anyway when its ID is outside
    // Nintendo's 01... range, so this is for forwarders inside it. Only
    // with the homebrew scope (mitm=off means no MITM at all); malformed
    // entries are logged and skipped.
    bool Start(::tsnx::Runtime &rt, Scope scope, bool sys_ftpd, const char *titles);

    // Removes the MITM registration from sm. Must run before this process
    // exits: sm asks the MITM owner about every new bsd:u session and aborts
    // (freezing the console) if the owner is gone. For the same reason the
    // overlay must not kill us (toolbox.json: requires_reboot). Covers bsd:s
    // too when sys-ftpd is served. Best effort, for the crash handler.
    void UninstallForExit();

    // ---- a deliberate stop (tsnx:ctl Stop) ----------------------------------

    enum class StopCheck {
        Ok,        // no client sessions; new ones bypass us until CancelStop
        Homebrew,  // homebrew sessions are open (closing them would break the app)
        Busy,      // a session sm handed us isn't acknowledged yet
    };

    // Refuses if homebrew has sessions through us. Otherwise answers "don't
    // MITM" to every new session from now on and waits (bounded) until every
    // session sm already sent us has been acknowledged: uninstalling with
    // one pending would leave sm deferring that service's requests, and our
    // acknowledgement would then abort. sys-ftpd's sessions don't count:
    // UninstallForStop restarts it. Undo with CancelStop.
    StopCheck PrepareStop(u32 *out_homebrew_sessions);
    void CancelStop();

    // After PrepareStop: uninstalls (checking every result), restarts
    // sys-ftpd if we served it, and waits (bounded) for every session
    // through us to close. True only if the process may now exit. On false
    // it must keep running (new sessions keep bypassing us).
    bool UninstallForStop();

}
