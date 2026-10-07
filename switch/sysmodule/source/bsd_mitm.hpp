// bsd:u MITM: homebrew sockets that talk to tailnet addresses (100.64/10,
// fd7a:115c:a1e0::/48) are served by the tsnx engine's overlay sockets via the
// portable socket-virtualization layer (native/vsock); everything else is
// forwarded to the real bsd:u untouched.
#pragma once

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
    bool Start(::tsnx::Runtime &rt, Scope scope, bool sys_ftpd);

    // Removes the MITM registration from sm. Must run before this process
    // exits: sm asks the MITM owner about every new bsd:u session and aborts
    // (freezing the console) if the owner is gone. For the same reason the
    // overlay must not kill us (toolbox.json: requires_reboot). Covers bsd:s
    // too when sys-ftpd is served.
    void UninstallForExit();

}
