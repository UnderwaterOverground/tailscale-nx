// Sysmodule log: sdmc:/config/tailscale-nx/sysmodule.log plus the optional
// UDP log target (log_udp in config.ini). Never fails, safe from any thread.
#pragma once

namespace ams {

    void Log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

}
