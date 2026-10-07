// tsnx:ctl, the tailscale-nx sysmodule's control service (status, login
// link, pause). Shared by the sysmodule and its clients (the overlay).
//
//   cmd 0  GetStatus()                -> TsnxCtlStatus (raw)
//   cmd 1  GetLoginUrl(out buffer)    -> u32 length (0: none)
//   cmd 2  SetPaused(u8 paused)
//   cmd 3  GetLastError(out buffer)   -> u32 length (0: none)
#pragma once
#include <stdint.h>

#define TSNX_CTL_SERVICE "tsnx:ctl"
#define TSNX_CTL_VERSION 1

enum {
    TSNX_CTL_STARTING = 0,     // waiting for the network / starting up
    TSNX_CTL_NEEDS_LOGIN = 1,  // a login link is waiting (GetLoginUrl)
    TSNX_CTL_CONNECTING = 2,   // authorized, joining the tailnet
    TSNX_CTL_CONNECTED = 3,
    TSNX_CTL_PAUSED = 4,       // switched off by the user (survives reboots)
};

enum {
    TSNX_CTL_FLAG_MITM = 1,      // homebrew sockets reach the tailnet
    TSNX_CTL_FLAG_MAGICDNS = 2,  // tailnet names in Atmosphere's hosts file
    TSNX_CTL_FLAG_DIRECT = 4,    // at least one peer reached directly (not relayed)
};

typedef struct {
    uint32_t version;    // TSNX_CTL_VERSION
    uint32_t state;      // TSNX_CTL_*
    uint8_t ipv4[4];     // our tailnet address, 0.0.0.0 if none yet
    uint32_t peers;
    uint32_t home_derp;  // relay region id, 0 if none
    uint32_t flags;      // TSNX_CTL_FLAG_*
    uint32_t reserved[10];
} TsnxCtlStatus;

#ifdef __cplusplus
static_assert(sizeof(TsnxCtlStatus) == 64, "TsnxCtlStatus layout");
#endif
