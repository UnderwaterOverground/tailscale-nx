// tsnx:ctl, the tailscale-nx sysmodule's control service (status, login
// link, pause, stop). Shared by the sysmodule and its clients (the overlay).
//
//   cmd 0  GetStatus()                -> TsnxCtlStatus (raw)
//   cmd 1  GetLoginUrl(out buffer)    -> u32 length (0: none)
//   cmd 2  SetPaused(u8 paused)
//   cmd 3  GetLastError(out buffer)   -> u32 length (0: none)
//   cmd 4  Stop()                     -> u32 TSNX_CTL_STOP_*, u32 detail
//          (version 2+). Ends the process unless that could disturb the
//          console or an app; the reply says why not. On TSNX_CTL_STOP_OK
//          the process exits shortly after replying: close the session
//          and wait for it to be gone before starting it again.
//   cmd 5  GetActivePeers(out buffer)  -> u32 count (version 3+). Fills the
//          buffer with up to TSNX_CTL_MAX_PEERS TsnxCtlPeer (fewer if it's
//          smaller): the peers sent to in the last 45 s, most recent first,
//          and how each is reached. The count is how many are active, which
//          can be more than were written.
#pragma once
#include <stdint.h>

#define TSNX_CTL_SERVICE "tsnx:ctl"
#define TSNX_CTL_VERSION 3
#define TSNX_CTL_MAX_PEERS 32

enum {
    TSNX_CTL_STARTING = 0,     // waiting for the network / starting up
    TSNX_CTL_NEEDS_LOGIN = 1,  // a login link is waiting (GetLoginUrl)
    TSNX_CTL_CONNECTING = 2,   // authorized, joining the tailnet; with an address:
                               // lost the control server for a while, reconnecting
    TSNX_CTL_CONNECTED = 3,
    TSNX_CTL_PAUSED = 4,       // switched off by the user (survives reboots)
    TSNX_CTL_STOPPING = 5,     // stopped from the overlay; exiting (or idle until restart)
};

enum {
    TSNX_CTL_STOP_OK = 0,        // exiting now
    TSNX_CTL_STOP_HOMEBREW = 1,  // refused: homebrew has sockets through us (detail: sessions)
    TSNX_CTL_STOP_BUSY = 2,      // refused: a sleep or wake, or setup, is under way; try again
    TSNX_CTL_STOP_FAILED = 3,    // couldn't finish safely: stays idle until the console restarts
};

enum {
    TSNX_CTL_FLAG_MITM = 1,      // homebrew sockets reach the tailnet
    TSNX_CTL_FLAG_MAGICDNS = 2,  // tailnet names in Atmosphere's hosts file
    TSNX_CTL_FLAG_DIRECT = 4,    // an active peer is reached directly (before version 3: any peer, ever)
    TSNX_CTL_FLAG_OFFLINE = 8,   // the console has no internet connection
};

typedef struct {
    uint32_t version;    // TSNX_CTL_VERSION
    uint32_t state;      // TSNX_CTL_*
    uint8_t ipv4[4];     // our tailnet address, 0.0.0.0 if none yet
    uint32_t peers;
    uint32_t home_derp;  // relay region id, 0 if none
    uint32_t flags;      // TSNX_CTL_FLAG_*
    uint32_t memory_kb;       // what tailscale-nx takes (fixed), 0 if unknown
    uint32_t system_free_kb;  // free system memory, which sysmodules share
    // Seconds since the engine loop last ran a round (it runs at least once
    // a second), 0 below 3 s or while paused: anything more means it's stuck.
    // Always 0 from sysmodules before 1.1.
    uint32_t engine_stalled_s;
    uint32_t reserved[7];
} TsnxCtlStatus;

typedef struct {
    char name[32];          // first label of its name, NUL-terminated
    uint8_t direct;         // 1: a confirmed direct path; 0: relayed (DERP)
    uint8_t reserved;
    uint16_t latency_ms;    // when direct: its round trip (0: unknown)
    uint32_t relay_region;  // when relayed: the DERP region id (0: unknown)
} TsnxCtlPeer;

#ifdef __cplusplus
static_assert(sizeof(TsnxCtlStatus) == 64, "TsnxCtlStatus layout");
static_assert(sizeof(TsnxCtlPeer) == 40, "TsnxCtlPeer layout");
#endif
