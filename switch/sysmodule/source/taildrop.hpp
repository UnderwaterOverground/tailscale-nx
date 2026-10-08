// Taildrop receive on the Switch: files sent with `tailscale file cp` or the
// Tailscale apps' "Send file" land in sdmc:/Taildrop (see tsnx_drop.h for the
// policy), with a toast for each.
#pragma once
#include <stratosphere.hpp>

#include "tsnx_driver.h"

namespace ams::taildrop {

    // The peer API port we advertise.
    constexpr u16 Port = 41643;

    // Before the engine loop starts (no lock needed yet). Returns success.
    bool Start(TsnxDriver *driver);

}
