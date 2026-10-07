// tailscale-nx sysmodule: runs the Tailscale engine from boot (boot2), so the
// console is on the tailnet without any app open.
//
// It also MITMs bsd:u for homebrew (bsd_mitm.cpp), so their sockets reach
// tailnet addresses through the engine (mitm=off in config.ini disables that).
//
// Files (SD card):
//   config/tailscale-nx/config.ini   shared with the app (control_url, auth_key,
//                                    hostname, ca_cert, log_udp=<ip>:<port>,
//                                    mitm=homebrew|homebrew,sys-ftpd|off,
//                                    magicdns=on|off,
//                                    overlay_budget_kb=<128..512>,
//                                    connect_notice=on|off)
//   config/tailscale-nx/state        node keys, shared with the app
//   config/tailscale-nx/disabled     kill switch: if present, exit at boot
//   config/tailscale-nx/crashed      written after 3 boots in a row that ended
//                                    within 3 minutes, or 2 sleeps that never woke;
//                                    keeps it off (delete to retry)
//   config/tailscale-nx/sysmodule.log (+ .1 from the previous boot)
#include <stratosphere.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>

extern "C" {
#include <switch/services/bsd.h>
#include "tsnx.h"
#include "tsnx_app.h"
#include "tsnx_dns.h"
#include "tsnx_driver.h"
}

#include <memory>
#include <string>

#include "bsd_mitm.hpp"
#include "ctl.hpp"
#include "hosts.hpp"
#include "log.hpp"
#include "runtime.hpp"
#include "stack_watch.hpp"
#include "status.hpp"

namespace ams {

    namespace {

        constexpr const char ConfigDir[] = "sdmc:/config/tailscale-nx";
        constexpr const char ConfigPath[] = "sdmc:/config/tailscale-nx/config.ini";
        constexpr const char StatePath[] = "sdmc:/config/tailscale-nx/state";
        constexpr const char DisabledPath[] = "sdmc:/config/tailscale-nx/disabled";
        constexpr const char CrashedPath[] = "sdmc:/config/tailscale-nx/crashed";
        constexpr const char StartingPath[] = "sdmc:/config/tailscale-nx/starting";
        constexpr const char SleepingPath[] = "sdmc:/config/tailscale-nx/sleeping";
        constexpr const char SleepFailuresPath[] = "sdmc:/config/tailscale-nx/sleep_failures";
        // A boot that doesn't last HealthyAfterNs counts against us (the
        // console itself can go down: a failed sleep made omm abort and
        // reboot it every ~2.5 minutes). Only boot-time starts count; a
        // sysmodule that dies isn't restarted, so loops span reboots.
        constexpr int MaxUnhealthyStarts = 3;
        constexpr u64 HealthyAfterNs = 180'000'000'000ull;
        constexpr u64 BootStartWithinNs = 120'000'000'000ull;
        constexpr int MaxSleepFailures = 2;
        constexpr const char LogPath[] = "sdmc:/config/tailscale-nx/sysmodule.log";
        constexpr const char OldLogPath[] = "sdmc:/config/tailscale-nx/sysmodule.log.1";
        constexpr s64 LogMaxSize = 512_KB;

        // Heap for the engine (Rust core + driver) and our own allocations.
        // Measured on the console: the engine peaked at 332 KB with 28 peers
        // (before the lean netmap decoder). Homebrew sockets on the tailnet
        // add overlay buffers, capped at 448 KB by the netstack's budget.
        constexpr size_t MallocBufferSize = 1_MB;
        alignas(os::MemoryPageSize) constinit u8 g_malloc_buffer[MallocBufferSize];

        // The engine's own sockets: control + DERP (TCP), WireGuard + DNS + log
        // (UDP). The transfer memory is the buffer pool for all of them, and
        // a UDP socket takes udp_tx + udp_rx of it, so it is sized for
        // sb_efficiency sockets' worth.
        consteval size_t BsdTransferMemorySize(const ::SocketInitConfig &c) {
            const u32 sum = c.tcp_tx_buf_max_size + c.tcp_rx_buf_max_size + c.udp_tx_buf_size + c.udp_rx_buf_size;
            return static_cast<size_t>(c.sb_efficiency) * util::AlignUp(sum, os::MemoryPageSize);
        }

        constexpr const ::SocketInitConfig SocketConfig = {
            .tcp_tx_buf_size = 0x4000,
            .tcp_rx_buf_size = 0x4000,
            .tcp_tx_buf_max_size = 0x8000,
            .tcp_rx_buf_max_size = 0x8000,
            .udp_tx_buf_size = 0x2000,
            .udp_rx_buf_size = 0xC000,
            .sb_efficiency = 3,
            .num_bsd_sessions = 3,
            .bsd_service_type = BsdServiceType_System,
        };

        alignas(os::MemoryPageSize) constinit u8 g_bsd_tmem[BsdTransferMemorySize(SocketConfig)];

        constexpr const ::BsdInitConfig BsdConfig = {
            .version = 1,
            .tmem_buffer = g_bsd_tmem,
            .tmem_buffer_size = sizeof(g_bsd_tmem),
            .tcp_tx_buf_size = SocketConfig.tcp_tx_buf_size,
            .tcp_rx_buf_size = SocketConfig.tcp_rx_buf_size,
            .tcp_tx_buf_max_size = SocketConfig.tcp_tx_buf_max_size,
            .tcp_rx_buf_max_size = SocketConfig.tcp_rx_buf_max_size,
            .udp_tx_buf_size = SocketConfig.udp_tx_buf_size,
            .udp_rx_buf_size = SocketConfig.udp_rx_buf_size,
            .sb_efficiency = SocketConfig.sb_efficiency,
        };

        // ---- files -------------------------------------------------------

        bool FileExists(const char *path) {
            fs::DirectoryEntryType type;
            return R_SUCCEEDED(fs::GetEntryType(std::addressof(type), path)) && type == fs::DirectoryEntryType_File;
        }

        // Reads a whole (small) file into buf, NUL-terminated. Returns length or -1.
        s64 ReadWholeFile(const char *path, char *buf, size_t cap) {
            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Read))) return -1;
            ON_SCOPE_EXIT { fs::CloseFile(f); };
            s64 size = 0;
            if (R_FAILED(fs::GetFileSize(std::addressof(size), f)) || size < 0 || static_cast<size_t>(size) >= cap) return -1;
            size_t got = 0;
            if (R_FAILED(fs::ReadFile(std::addressof(got), f, 0, buf, static_cast<size_t>(size)))) return -1;
            buf[got] = 0;
            return static_cast<s64>(got);
        }

        bool WriteWholeFile(const char *path, const void *data, size_t len) {
            static_cast<void>(fs::DeleteFile(path));
            if (R_FAILED(fs::CreateFile(path, static_cast<s64>(len)))) return false;
            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Write))) return false;
            ON_SCOPE_EXIT { fs::CloseFile(f); };
            return R_SUCCEEDED(fs::WriteFile(f, 0, data, len, fs::WriteOption::Flush));
        }

        // ---- logging -----------------------------------------------------

        constinit os::SdkMutex g_log_mutex;
        constinit fs::FileHandle g_log_file;
        constinit bool g_log_open = false;
        constinit s64 g_log_offset = 0;
        constinit int g_log_udp_fd = -1;
        // While the console sleeps, logging must not touch the socket service
        // (it may be asleep and block the caller): file only.
        constinit std::atomic<bool> g_log_udp_paused = false;
        // log_udp pointing at a tailnet address: lines queue here and the
        // engine loop sends them through the tunnel (works away from the LAN).
        constinit bool g_log_tailnet = false;
        constinit char g_tailnet_log[4_KB] = {};
        constinit size_t g_tailnet_log_len = 0;
        // After a wake the tunnel needs a moment to re-handshake; lines sent
        // before then are lost, so hold them until this tick.
        constinit u64 g_tailnet_log_hold_until_ns = 0;

        // Appends a line, dropping the oldest whole lines to make room.
        void QueueTailnetLog(const char *line, size_t n) {
            if (n > sizeof g_tailnet_log) return;
            while (g_tailnet_log_len + n > sizeof g_tailnet_log) {
                const char *nl = static_cast<const char *>(std::memchr(g_tailnet_log, '\n', g_tailnet_log_len));
                const size_t drop = nl ? static_cast<size_t>(nl - g_tailnet_log) + 1 : g_tailnet_log_len;
                std::memmove(g_tailnet_log, g_tailnet_log + drop, g_tailnet_log_len - drop);
                g_tailnet_log_len -= drop;
            }
            std::memcpy(g_tailnet_log + g_tailnet_log_len, line, n);
            g_tailnet_log_len += n;
        }
        constinit sockaddr_in g_log_udp_addr = {};
        // Lines logged before the UDP log socket exists, replayed once it does.
        constinit char g_early_log[4_KB] = {};
        constinit size_t g_early_log_len = 0;
        constinit bool g_early_log_done = false;

    }  // namespace

    void Log(const char *fmt, ...) {
            char line[600];
            const u64 ms = armTicksToNs(armGetSystemTick()) / 1'000'000;
            int n = util::SNPrintf(line, sizeof line, "[%5llu.%03llu] ", static_cast<unsigned long long>(ms / 1000),
                                  static_cast<unsigned long long>(ms % 1000));
            va_list ap;
            va_start(ap, fmt);
            n += util::VSNPrintf(line + n, sizeof line - n - 1, fmt, ap);
            va_end(ap);
            if (n > static_cast<int>(sizeof line) - 2) n = sizeof line - 2;
            line[n++] = '\n';
            line[n] = 0;

            std::scoped_lock lk(g_log_mutex);
            if (g_log_open && g_log_offset + n <= LogMaxSize) {
                // Logging must never take the sysmodule down: ignore failures.
                if (R_SUCCEEDED(fs::WriteFile(g_log_file, g_log_offset, line, n, fs::WriteOption::Flush))) g_log_offset += n;
            }
            if (g_log_tailnet) {
                QueueTailnetLog(line, n);
            } else if (g_log_udp_fd >= 0 && g_early_log_done && !g_log_udp_paused) {
                ::sendto(g_log_udp_fd, line, n, 0, reinterpret_cast<sockaddr *>(std::addressof(g_log_udp_addr)),
                         sizeof g_log_udp_addr);
            } else if (!g_early_log_done && g_early_log_len + n <= sizeof g_early_log) {
                std::memcpy(g_early_log + g_early_log_len, line, n);
                g_early_log_len += n;
            }
    }

    namespace {

        void OpenLog() {
            static_cast<void>(fs::DeleteFile(OldLogPath));
            static_cast<void>(fs::RenameFile(LogPath, OldLogPath));
            if (R_FAILED(fs::CreateFile(LogPath, 0))) return;
            g_log_open = R_SUCCEEDED(fs::OpenFile(std::addressof(g_log_file), LogPath, fs::OpenMode_Write | fs::OpenMode_AllowAppend));
        }

        // ---- config ------------------------------------------------------

        struct Config {
            char control_url[256] = "https://controlplane.tailscale.com";
            char auth_key[256] = {};
            char hostname[64] = "nintendo-switch";
            char ca_cert[256] = {};
            char log_udp[64] = {};
            char mitm[32] = "homebrew";  // "homebrew,sys-ftpd" or "off"
            char magicdns[8] = "on";      // tailnet names in Atmosphere's hosts file, or "off"
            char overlay_budget_kb[8] = {};  // tailnet socket buffers; default 320
            char connect_notice[8] = "on";   // toast with our address when first connected
        };

        void LoadConfig(Config &c) {
            static char buf[2_KB];  // config.ini is a few hundred bytes
            if (ReadWholeFile(ConfigPath, buf, sizeof buf) < 0) return;
            char *save = nullptr;
            for (char *line = strtok_r(buf, "\r\n", &save); line; line = strtok_r(nullptr, "\r\n", &save)) {
                if (line[0] == '#') continue;
                char *eq = std::strchr(line, '=');
                if (!eq) continue;
                *eq = 0;
                const char *v = eq + 1;
                auto set = [&](const char *key, char *dst, size_t cap) {
                    if (!std::strcmp(line, key)) util::SNPrintf(dst, cap, "%s", v);
                };
                set("control_url", c.control_url, sizeof c.control_url);
                set("auth_key", c.auth_key, sizeof c.auth_key);
                set("hostname", c.hostname, sizeof c.hostname);
                set("ca_cert", c.ca_cert, sizeof c.ca_cert);
                set("log_udp", c.log_udp, sizeof c.log_udp);
                set("mitm", c.mitm, sizeof c.mitm);
                set("magicdns", c.magicdns, sizeof c.magicdns);
                set("overlay_budget_kb", c.overlay_budget_kb, sizeof c.overlay_budget_kb);
                set("connect_notice", c.connect_notice, sizeof c.connect_notice);
            }
        }

        // ---- node keys (same format as the app: machine=/node=/disco= hex) --

        int HexNibble(char ch) {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            return -1;
        }

        bool ParseKey(const char *text, const char *name, u8 out[32]) {
            char needle[16];
            util::SNPrintf(needle, sizeof needle, "%s=", name);
            const char *p = std::strstr(text, needle);
            if (!p || (p != text && p[-1] != '\n')) return false;
            p += std::strlen(needle);
            for (int i = 0; i < 32; i++) {
                const int hi = HexNibble(p[2 * i]), lo = HexNibble(p[2 * i + 1]);
                if (hi < 0 || lo < 0) return false;
                out[i] = static_cast<u8>(hi * 16 + lo);
            }
            return true;
        }

        bool WriteKeys(const u8 machine[32], const u8 node[32], const u8 disco[32]) {
            char out[256];
            int n = 0;
            auto put = [&](const char *name, const u8 *k) {
                n += util::SNPrintf(out + n, sizeof out - n, "%s=", name);
                for (int i = 0; i < 32; i++) n += util::SNPrintf(out + n, sizeof out - n, "%02x", k[i]);
                n += util::SNPrintf(out + n, sizeof out - n, "\n");
            };
            put("machine", machine);
            put("node", node);
            put("disco", disco);
            return WriteWholeFile(StatePath, out, n);
        }

        bool LoadOrCreateKeys(u8 machine[32], u8 node[32], u8 disco[32]) {
            static char buf[1_KB];
            bool have_m = false, have_n = false, have_d = false;
            if (ReadWholeFile(StatePath, buf, sizeof buf) >= 0) {
                have_m = ParseKey(buf, "machine", machine);
                have_n = ParseKey(buf, "node", node);
                have_d = ParseKey(buf, "disco", disco);
                if (have_m && have_n && have_d) return true;
            }
            if (!have_m) os::GenerateRandomBytes(machine, 32);
            if (!have_n) os::GenerateRandomBytes(node, 32);
            if (!have_d) os::GenerateRandomBytes(disco, 32);
            return WriteKeys(machine, node, disco);
        }

        // The engine replaced our expired node key (TSNX_EVENT_NODE_KEY): store
        // it, or the next boot would come back with the expired one.
        void SaveNodeKey(TsnxEngine *engine) {
            u8 machine[32], node[32], disco[32];
            if (!LoadOrCreateKeys(machine, node, disco)) return;
            tsnx_engine_node_key(engine, node);
            if (!WriteKeys(machine, node, disco)) Log("cannot save the new node key to %s", StatePath);
        }

        // ---- network -----------------------------------------------------

        // DNS through the servers nifm reports (the system resolver can't be
        // used from a sysmodule), falling back to public resolvers.
        int ResolveViaDns(const char *host, u32 *out) {
            u32 ip = 0, mask = 0, gw = 0, dns1 = 0, dns2 = 0;
            u32 servers[4] = {};
            int n = 0;
            if (R_SUCCEEDED(nifmGetCurrentIpConfigInfo(&ip, &mask, &gw, &dns1, &dns2))) {
                if (dns1) servers[n++] = dns1;
                if (dns2) servers[n++] = dns2;
            }
            servers[n++] = inet_addr("1.1.1.1");
            servers[n++] = inet_addr("8.8.8.8");
            for (int i = 0; i < n; i++) {
                if (tsnx_dns_query_a(servers[i], host, out, 2000) == 0) return 0;
                Log("dns: %s via %s failed: errno %d", host, inet_ntoa(in_addr{servers[i]}), errno);
            }
            return -1;
        }

        bool NetworkUp() {
            NifmInternetConnectionStatus status;
            return R_SUCCEEDED(nifmGetInternetConnectionStatus(nullptr, nullptr, &status)) &&
                   status == NifmInternetConnectionStatus_Connected;
        }

        u32 CurrentIp() {
            u32 ip = 0;
            return R_SUCCEEDED(nifmGetCurrentIpAddress(&ip)) ? ip : 0;
        }

        // The network clock if synced, else the user clock.
        u64 ConsoleUnixTime() {
            u64 t = 0;
            if (R_SUCCEEDED(timeGetCurrentTime(TimeType_NetworkSystemClock, &t)) && t > static_cast<u64>(TSNX_BUILD_UNIX)) return t;
            if (R_SUCCEEDED(timeGetCurrentTime(TimeType_UserSystemClock, &t))) return t;
            return 0;
        }

        const char *EventName(u32 kind) {
            switch (kind) {
                case TSNX_EVENT_LOGIN_URL: return "login-url";
                case TSNX_EVENT_AUTHORIZED: return "authorized";
                case TSNX_EVENT_ADDRESSES: return "addresses";
                case TSNX_EVENT_PEERS: return "peers";
                case TSNX_EVENT_HOME_DERP: return "home-derp";
                case TSNX_EVENT_ERROR: return "error";
                case TSNX_EVENT_ENDPOINTS: return "endpoints";
                case TSNX_EVENT_PEER_PATH: return "path";
                case TSNX_EVENT_NODE_KEY: return "node-key";
                default: return "log";
            }
        }

        void OpenUdpLogSocket();

        void SetUpUdpLog(const char *target) {
            char host[48];
            const char *colon = std::strchr(target, ':');
            const int port = colon ? std::atoi(colon + 1) : 0;
            if (!colon || port <= 0 || port > 65535 || static_cast<size_t>(colon - target) >= sizeof host) return;
            std::memcpy(host, target, colon - target);
            host[colon - target] = 0;
            g_log_udp_addr.sin_family = AF_INET;
            g_log_udp_addr.sin_port = htons(static_cast<u16>(port));
            g_log_udp_addr.sin_addr.s_addr = inet_addr(host);
            if ((ntohl(g_log_udp_addr.sin_addr.s_addr) & 0xffc00000u) == 0x64400000u) {
                // A tailnet address (100.64.0.0/10): send through the engine.
                std::scoped_lock lk(g_log_mutex);
                g_log_tailnet = true;
                QueueTailnetLog(g_early_log, g_early_log_len);
                g_early_log_done = true;
                return;
            }
            OpenUdpLogSocket();
        }

        // Sends queued log lines through the tunnel (engine loop, runtime lock
        // held). Waits while we're not on the tailnet; lines from boot are
        // kept (the oldest dropped if the queue fills).
        void FlushTailnetLog(TsnxEngine *engine) {
            static int32_t udp = 0;
            static char out[sizeof g_tailnet_log];
            if (!g_log_tailnet) return;
            const TsnxCtlStatus st = status::Get();
            if (st.state == TSNX_CTL_PAUSED || st.ipv4[0] == 0) return;
            if (armTicksToNs(armGetSystemTick()) < g_tailnet_log_hold_until_ns) return;
            size_t len;
            {
                std::scoped_lock lk(g_log_mutex);
                if (g_tailnet_log_len == 0) return;
                len = g_tailnet_log_len;
                std::memcpy(out, g_tailnet_log, len);
                g_tailnet_log_len = 0;
            }
            if (udp <= 0) udp = tsnx_net_udp_bind(engine, 0);
            if (udp <= 0) return;
            TsnxAddr dst = {};
            dst.family = 4;
            std::memcpy(dst.ip, &g_log_udp_addr.sin_addr.s_addr, 4);
            dst.port = ntohs(g_log_udp_addr.sin_port);
            for (size_t off = 0; off < len;) {
                const char *nl = static_cast<const char *>(std::memchr(out + off, '\n', len - off));
                const size_t n = (nl ? static_cast<size_t>(nl - (out + off)) : len - off) + (nl ? 1 : 0);
                tsnx_net_udp_sendto(engine, udp, reinterpret_cast<const u8 *>(out + off), n, &dst);
                off += n;
            }
        }

        void CloseUdpLogSocket() {
            std::scoped_lock lk(g_log_mutex);
            if (g_log_udp_fd >= 0) ::close(g_log_udp_fd);
            g_log_udp_fd = -1;
        }

        void OpenUdpLogSocket() {
            if (g_log_udp_addr.sin_family != AF_INET || g_log_tailnet) return;
            const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) return;
            // Send-only: keep its share of the socket buffer pool small.
            const int rcv = 0x1000, snd = 0x2000;
            ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv);
            ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof snd);
            std::scoped_lock lk(g_log_mutex);
            g_log_udp_fd = fd;
        }

        // Sends the lines logged so far over UDP, once the network is up (at
        // boot the log socket exists before Wi-Fi does); later lines go out
        // directly.
        void FlushEarlyLog() {
            std::scoped_lock lk(g_log_mutex);
            if (g_early_log_done) return;  // includes the tailnet case (queued instead)
            if (g_log_udp_fd < 0) {
                g_early_log_done = true;
                return;
            }
            for (size_t off = 0; off < g_early_log_len;) {
                const char *nl = static_cast<const char *>(std::memchr(g_early_log + off, '\n', g_early_log_len - off));
                const size_t len = (nl ? static_cast<size_t>(nl - (g_early_log + off)) : g_early_log_len - off) + 1;
                ::sendto(g_log_udp_fd, g_early_log + off, len, 0, reinterpret_cast<sockaddr *>(std::addressof(g_log_udp_addr)),
                         sizeof g_log_udp_addr);
                off += len;
            }
            g_early_log_done = true;
        }

    }

    namespace {

        // ---- sleep / wake ----------------------------------------------------

        // With our sockets open and in use across sleep, the transition
        // failed and omm aborted (2165-0001). So we take part in power-state
        // changes (psc) and close every socket we own on the way down.
        constexpr auto TsnxPmModuleId = static_cast<psc::PmModuleId>(0x7453);
        constexpr psc::PmModuleId PmDependencies[] = {psc::PmModuleId_Nifm, psc::PmModuleId_Fs};

        psc::PmModule g_pm_module;
        constinit ::tsnx::Runtime *g_power_runtime = nullptr;
        alignas(os::ThreadStackAlignment) constinit u8 g_power_thread_stack[0x2000];  // measured: ~1 KB
        constinit os::ThreadType g_power_thread;

        // Every step is acknowledged without waiting on the network: by the
        // time "sleep ready" arrives the socket service may already be asleep,
        // and a blocked call there would hang the whole transition. So the
        // sockets close on the first step down (FullAwake -> MinimumAwake),
        // while everything is still awake, and reopen after FullAwake is
        // acknowledged, on the engine thread.
        void PowerThread(void *) {
            psc::PmState last = psc::PmState_FullAwake;
            bool suspended = false;
            // Time between being asked and acknowledging, over a wake's steps
            // (the system waits on every module, so this is our share).
            u64 wake_held_ns = 0;
            bool waking = false;
            for (;;) {
                g_pm_module.GetEventPointer()->Wait();
                const u64 asked = armTicksToNs(armGetSystemTick());
                psc::PmState state;
                psc::PmFlagSet flags;
                if (R_FAILED(g_pm_module.GetRequest(std::addressof(state), std::addressof(flags)))) continue;
                if (!suspended && last == psc::PmState_FullAwake && state != psc::PmState_FullAwake) {
                    // Every socket must be closed before we acknowledge: with
                    // ours open, the transition fails and omm aborts (2165-0001;
                    // also seen when this ran asynchronously). The engine thread
                    // does the closing; this thread never touches the socket
                    // service (it may already be asleep if the system went
                    // straight to "sleep ready") and waits a bounded time.
                    g_log_udp_paused = true;
                    Log("power: leaving full awake (state %d); closing sockets", static_cast<int>(state));
                    // A reboot or power-off (ShutdownReady) never wakes, so it
                    // must not count as a failed sleep.
                    if (state != psc::PmState_ShutdownReady) WriteWholeFile(SleepingPath, "1", 1);  // removed on wake; see PassesCrashGuard
                    g_power_runtime->RequestSuspend(::tsnx::Runtime::kSleep);
                    const u64 deadline = armTicksToNs(armGetSystemTick()) + 2'500'000'000ull;
                    while (!g_power_runtime->IsSuspended() && armTicksToNs(armGetSystemTick()) < deadline) {
                        os::SleepThread(TimeSpan::FromMilliSeconds(10));
                    }
                    if (!g_power_runtime->IsSuspended()) Log("power: sockets not closed in time; continuing");
                    suspended = true;
                }
                if (suspended && state == psc::PmState_ShutdownReady) static_cast<void>(fs::DeleteFile(SleepingPath));
                if (const Result rc = g_pm_module.Acknowledge(state, ResultSuccess()); R_FAILED(rc)) Log("power: acknowledge failed: 0x%x", rc.GetValue());
                // Wake steps: from "essential services awake" up to full awake
                // (a light sleep goes straight back to full awake).
                if (state == psc::PmState_EssentialServicesAwake) waking = true;
                if (suspended && (waking || state == psc::PmState_FullAwake)) wake_held_ns += armTicksToNs(armGetSystemTick()) - asked;
                if (suspended && state == psc::PmState_FullAwake) {
                    g_log_udp_paused = false;
                    g_power_runtime->Resume(::tsnx::Runtime::kSleep);
                    suspended = false;
                    static_cast<void>(fs::DeleteFile(SleepingPath));
                    static_cast<void>(fs::DeleteFile(SleepFailuresPath));
                    Log("power: awake; reconnecting (we held the wake for %llu us)", static_cast<unsigned long long>(wake_held_ns / 1000));
                    wake_held_ns = 0;
                    waking = false;
                }
                last = state;
            }
        }

        void StartPowerHandling(::tsnx::Runtime &rt) {
            g_power_runtime = std::addressof(rt);
            if (R_FAILED(::pscmInitialize())) {
                Log("power: psc unavailable; sleep may fail while running");
                return;
            }
            if (const Result rc = g_pm_module.Initialize(TsnxPmModuleId, PmDependencies, util::size(PmDependencies), os::EventClearMode_AutoClear); R_FAILED(rc)) {
                Log("power: psc module registration failed: 0x%x", rc.GetValue());
                return;
            }
            stack_watch::Paint(g_power_thread_stack, sizeof g_power_thread_stack);
            if (R_FAILED(os::CreateThread(std::addressof(g_power_thread), PowerThread, nullptr, g_power_thread_stack, sizeof g_power_thread_stack,
                                          os::GetThreadCurrentPriority(os::GetCurrentThread())))) {
                Log("power: cannot create thread");
                return;
            }
            os::SetThreadNamePointer(std::addressof(g_power_thread), "tsnx.Power");
            stack_watch::Add("power", std::addressof(g_power_thread));
            os::StartThread(std::addressof(g_power_thread));
        }

    }

    namespace init {

        // Only what logging needs; everything else is initialized in Main()
        // where failures are logged and end the process cleanly, never in a
        // fatal error screen.
        void InitializeSystemModule() {
            R_ABORT_UNLESS(sm::Initialize());
            fs::InitializeForSystem();
            fs::SetEnabledAutoAbort(false);
        }

        void FinalizeSystemModule() {}

        void Startup() {
            init::InitializeAllocator(g_malloc_buffer, sizeof(g_malloc_buffer));
        }

    }

    void NORETURN Exit(int rc) {
        AMS_UNUSED(rc);
        ::svcExitProcess();
        __builtin_unreachable();
    }

    // Crash-loop guard: stays off (and writes `crashed`) after repeated
    // boots that died early, or repeated sleeps that never woke up.
    bool PassesCrashGuard() {
        auto give_up = [](const char *why) {
            Log("%s: disabling (see %s)", why, CrashedPath);
            char msg[256];
            const int n = util::SNPrintf(msg, sizeof msg,
                                        "tailscale-nx stopped itself: %s.\n"
                                        "See sysmodule.log / sysmodule.log.1. Delete this file to try again.\n", why);
            WriteWholeFile(CrashedPath, msg, n);
            static_cast<void>(fs::DeleteFile(StartingPath));
            static_cast<void>(fs::DeleteFile(SleepFailuresPath));
            return false;
        };
        if (FileExists(CrashedPath)) {
            Log("%s exists (earlier runs failed): staying off; delete it to retry", CrashedPath);
            return false;
        }

        char buf[16] = {};
        if (FileExists(SleepingPath)) {
            // The console went to sleep with us running and never woke us.
            static_cast<void>(fs::DeleteFile(SleepingPath));
            const int failures = (ReadWholeFile(SleepFailuresPath, buf, sizeof buf) > 0 ? std::atoi(buf) : 0) + 1;
            if (failures >= MaxSleepFailures) return give_up("the console failed to wake from sleep twice in a row with it running");
            Log("warning: the last sleep never woke up (%d of %d before disabling)", failures, MaxSleepFailures);
            WriteWholeFile(SleepFailuresPath, buf, util::SNPrintf(buf, sizeof buf, "%d", failures));
        }

        if (armTicksToNs(armGetSystemTick()) > BootStartWithinNs) return true;  // started by hand
        const int count = ReadWholeFile(StartingPath, buf, sizeof buf) > 0 ? std::atoi(buf) : 0;
        if (count >= MaxUnhealthyStarts) return give_up("several boots in a row ended within 3 minutes of starting");
        WriteWholeFile(StartingPath, buf, util::SNPrintf(buf, sizeof buf, "%d", count + 1));
        return true;
    }

    void Main() {
        stack_watch::AddCurrent("main");
        // Without the SD card there is nothing to log to or configure from.
        if (R_FAILED(fs::MountSdCard("sdmc"))) return;
        static_cast<void>(fs::CreateDirectory("sdmc:/config"));
        static_cast<void>(fs::CreateDirectory(ConfigDir));
        OpenLog();
        Log("tailscale-nx sysmodule %s starting", tsnx_version());
        if (FileExists(DisabledPath)) {
            Log("%s exists: staying disabled", DisabledPath);
            return;
        }
        if (!PassesCrashGuard()) return;

        // Services, initialized here so a failure is a logged, clean exit.
        if (Result rc = nifmInitialize(NifmServiceType_Admin); R_FAILED(rc)) {
            Log("nifmInitialize failed: 0x%x", rc.GetValue());
            return;
        }
        if (Result rc = timeInitialize(); R_FAILED(rc)) Log("timeInitialize failed: 0x%x (clock from server)", rc.GetValue());
        if (Result rc = bsdInitialize(&BsdConfig, SocketConfig.num_bsd_sessions, SocketConfig.bsd_service_type); R_FAILED(rc)) {
            Log("bsdInitialize failed: 0x%x", rc.GetValue());
            return;
        }
        if (Result rc = socketInitialize(&SocketConfig); R_FAILED(rc)) {
            Log("socketInitialize failed: 0x%x", rc.GetValue());
            return;
        }

        Config cfg;
        LoadConfig(cfg);
        if (cfg.log_udp[0]) SetUpUdpLog(cfg.log_udp);
        tsnx_set_log_callback([](u32 level, const char *msg) { Log("%s%s", level <= 2 ? "WARN " : "", msg); }, 3);
        tsnx_set_resolver(ResolveViaDns);

        u8 seed[32];
        os::GenerateRandomBytes(seed, sizeof seed);
        tsnx_seed_rng(seed);
        if (const u32 st = tsnx_selftest(); st != TSNX_SELFTEST_OK) {
            Log("crypto selftest FAILED (%u); not starting", st);
            return;
        }

        u8 machine[32], node[32], disco[32];
        if (!LoadOrCreateKeys(machine, node, disco)) {
            Log("cannot read/write %s", StatePath);
            return;
        }

        // Boot2 runs before Wi-Fi is up.
        while (!NetworkUp()) os::SleepThread(TimeSpan::FromSeconds(1));
        u32 ip = CurrentIp();
        Log("network up, local address %s", inet_ntoa(in_addr{ip}));
        FlushEarlyLog();

        // Only a dev setup (self-signed control/DERP) has one; the engine
        // copies it, so it lives on the heap just until then.
        std::unique_ptr<u8[]> ca;
        s64 ca_len = -1;
        if (cfg.ca_cert[0]) {
            ca = std::make_unique<u8[]>(16_KB);
            ca_len = ReadWholeFile(cfg.ca_cert, reinterpret_cast<char *>(ca.get()), 16_KB);
            if (ca_len <= 0) Log("cannot read ca_cert %s", cfg.ca_cert);
        }

        bool corrected = false;
        const u64 console_time = ConsoleUnixTime();
        u64 unix_time = tsnx_sane_unix_time(console_time, cfg.control_url, &corrected);
        if (corrected) Log("console clock implausible (%llu); using the control server's time (%llu)",
                           static_cast<unsigned long long>(console_time), static_cast<unsigned long long>(unix_time));
        if (unix_time == 0) unix_time = console_time;

        TsnxConfig ecfg = {};
        ecfg.control_url = cfg.control_url;
        ecfg.auth_key = cfg.auth_key[0] ? cfg.auth_key : nullptr;
        ecfg.hostname = cfg.hostname;
        ecfg.machine_key = machine;
        ecfg.node_key = node;
        ecfg.disco_key = disco;
        ecfg.extra_root_der = ca_len > 0 ? ca.get() : nullptr;
        ecfg.extra_root_len = ca_len > 0 ? static_cast<size_t>(ca_len) : 0;
        TsnxEngine *engine = tsnx_engine_new(&ecfg, tsnx_driver_now_ns(), unix_time);
        ca.reset();
        if (!engine) {
            Log("engine init failed (control_url %s)", cfg.control_url);
            return;
        }
        // Peer names or addresses changed: refresh the hosts file (debounced
        // in the loop below). Events arrive with the runtime lock held.
        static u64 hosts_dirty_since = 0;
        TsnxDriver *driver = tsnx_driver_new(engine, [](void *ctx, const TsnxEvent *ev) {
            Log("%s: %s (%u)", EventName(ev->kind), ev->text, ev->value);
            if (ev->kind == TSNX_EVENT_NODE_KEY) SaveNodeKey(static_cast<TsnxEngine *>(ctx));
            status::OnEvent(*ev);
            if ((ev->kind == TSNX_EVENT_PEERS || ev->kind == TSNX_EVENT_ADDRESSES) && hosts_dirty_since == 0) {
                hosts_dirty_since = armTicksToNs(armGetSystemTick());
            }
        }, engine);
        const bool magicdns = std::strcmp(cfg.magicdns, "off") != 0;
        if (cfg.overlay_budget_kb[0]) {
            // Bounded by the sysmodule's 1 MB heap: the engine and the
            // MITM need about 300 KB of it besides the overlay buffers.
            const unsigned long kb = std::clamp(std::strtoul(cfg.overlay_budget_kb, nullptr, 10), 128ul, 512ul);
            tsnx_net_set_budget(engine, kb * 1024);
            Log("overlay buffer budget: %lu KB", kb);
        }
        if (tsnx_driver_open_udp(driver, 41641) != 0 && tsnx_driver_open_udp(driver, 0) != 0) Log("no UDP socket: DERP only");
        std::string error;
        auto rt = ::tsnx::Runtime::Adopt(engine, driver, &error);
        if (!rt) {
            Log("runtime: %s (errno %d)", error.c_str(), errno);
            return;
        }
        Log("engine started: control %s, hostname %s", cfg.control_url, cfg.hostname);

        // Homebrew sockets to tailnet addresses go through the engine.
        // The log socket goes down and up with the engine's own (sleep).
        rt->SetSuspendHooks([] { CloseUdpLogSocket(); }, [] {
            g_tailnet_log_hold_until_ns = armTicksToNs(armGetSystemTick()) + 10'000'000'000ull;
            OpenUdpLogSocket();
        });
        StartPowerHandling(*rt);
        // mitm=homebrew (default), off, or homebrew,sys-ftpd.
        const bool mitm = bsd_mitm::Start(*rt, std::strcmp(cfg.mitm, "off") == 0 ? bsd_mitm::Scope::Off : bsd_mitm::Scope::Homebrew,
                                          std::strstr(cfg.mitm, "sys-ftpd") != nullptr);

        // Status for the overlay (and the user's pause switch, applied before
        // the engine loop's first round), then its control service.
        status::Initialize(*rt, (mitm ? TSNX_CTL_FLAG_MITM : 0) | (magicdns ? TSNX_CTL_FLAG_MAGICDNS : 0),
                           std::strcmp(cfg.connect_notice, "off") != 0);
        ctl::Start();

        // Engine loop on this thread; housekeeping between rounds. Re-detect
        // our address after Wi-Fi changes (roaming, sleep/wake).
        u64 last_check = armTicksToNs(armGetSystemTick());
        u64 last_heap_log = 0;
        const u64 started = armTicksToNs(armGetSystemTick());
        bool healthy = false;
        size_t heap_all_peak = 0;
        rt->Run([&](TsnxDriver *d) {
            const u64 now = armTicksToNs(armGetSystemTick());
            // Whole-heap use (Rust, C++, C), sampled every round; the Rust
            // peak below is exact.
            const size_t heap_free = init::GetAllocator()->GetTotalFreeSize();
            heap_all_peak = std::max(heap_all_peak, MallocBufferSize - std::min(heap_free, MallocBufferSize));
            if (!healthy && now - started > HealthyAfterNs) {
                healthy = true;
                static_cast<void>(fs::DeleteFile(StartingPath));
                Log("running stably; crash guard reset");
            }
            if (now - last_heap_log > 60'000'000'000ull) {
                last_heap_log = now;
                size_t cur = 0, peak = 0;
                tsnx_heap_stats(&cur, &peak);
                Log("heap: rust %zu KB (peak %zu), all %zu KB (peak %zu, largest free %zu) of %zu KB; overlay buffers %zu KB", cur / 1024,
                    peak / 1024, (MallocBufferSize - std::min(heap_free, MallocBufferSize)) / 1024, heap_all_peak / 1024,
                    init::GetAllocator()->GetAllocatableSize() / 1024, MallocBufferSize / 1024, tsnx_net_buffer_usage(engine) / 1024);
                char classes[200];
                tsnx_heap_classes(classes, sizeof classes);
                Log("heap by size (KB/allocs): %s", classes);
                stack_watch::Log();
            }
            FlushTailnetLog(engine);
            if (magicdns && hosts_dirty_since != 0 && now - hosts_dirty_since > 3'000'000'000ull) {
                hosts_dirty_since = 0;
                hosts::Update(engine);
            }
            if (now - last_check > 5'000'000'000ull) {
                last_check = now;
                const u32 cur = NetworkUp() ? CurrentIp() : 0;
                if (cur != ip) {
                    Log("local address changed: %s", cur ? inet_ntoa(in_addr{cur}) : "(offline)");
                    ip = cur;
                    if (cur) tsnx_driver_refresh_endpoints(d);
                }
            }
        });
    }

}

namespace ams {

    // A crash in this process (libstratosphere's CrashHandler builds `ctx`
    // and calls this; the default reboots into the fatal screen). Log where
    // it happened, as offsets into our binary for addr2line, then end only
    // this process: tailscale-nx stops but the console keeps running.
    // Runs on the one-page exception stack, maybe with the log mutex held,
    // so it formats into a static buffer and writes without locking.
    void ExceptionHandler(FatalErrorContext *ctx) {
        static char line[640];
        const u64 base = ctx->module_base;
        auto off = [base](u64 a) { return a >= base ? a - base : a; };
        int n = util::SNPrintf(line, sizeof line, "CRASH desc 0x%x: pc +0x%lx lr +0x%lx far 0x%lx sp 0x%lx base 0x%lx; trace",
                               ctx->error_desc, off(ctx->pc), off(ctx->lr), ctx->far, ctx->sp, base);
        for (u64 i = 0; i < ctx->stack_trace_size && i < 12 && n < static_cast<int>(sizeof line) - 24; i++) {
            n += util::SNPrintf(line + n, sizeof line - n, " +0x%lx", off(ctx->stack_trace[i]));
        }
        if (n > static_cast<int>(sizeof line) - 2) n = sizeof line - 2;
        line[n++] = '\n';
        if (g_log_open) {
            static_cast<void>(fs::WriteFile(g_log_file, g_log_offset, line, n, fs::WriteOption::Flush));
            g_log_offset += n;
        }
        if (g_log_udp_fd >= 0) {
            ::sendto(g_log_udp_fd, line, n, 0, reinterpret_cast<sockaddr *>(std::addressof(g_log_udp_addr)), sizeof g_log_udp_addr);
        }
        bsd_mitm::UninstallForExit();
        svcExitProcess();
        __builtin_unreachable();
    }

}

extern "C" [[noreturn]] void tsnx_platform_panic(const uint8_t *msg, size_t len) {
    ams::Log("PANIC in tsnx core: %.*s", static_cast<int>(len), reinterpret_cast<const char *>(msg));
    AMS_ABORT("tsnx core panic");
}

// libstratosphere routes operator new/delete through its allocator only when
// asked; send them to malloc (backed by g_malloc_buffer).
void *operator new(size_t size) { return std::malloc(size); }
void *operator new(size_t size, const std::nothrow_t &) { return std::malloc(size); }
void operator delete(void *p) { std::free(p); }
void operator delete(void *p, size_t) { std::free(p); }
void *operator new[](size_t size) { return std::malloc(size); }
void *operator new[](size_t size, const std::nothrow_t &) { return std::malloc(size); }
void operator delete[](void *p) { std::free(p); }
void operator delete[](void *p, size_t) { std::free(p); }

// The shared C helpers' snprintf, routed to libstratosphere's formatter
// (the sysmodule build defines snprintf=tsnx_snprintf): newlib's would add
// its float formatting and stdio to the binary.
extern "C" int tsnx_snprintf(char *dst, size_t size, const char *fmt, ...) {
    std::va_list vl;
    va_start(vl, fmt);
    const int n = ams::util::VSNPrintf(dst, size, fmt, vl);
    va_end(vl);
    return n;
}

// Used by the shared app helpers (tsnx_app.c).
extern "C" void tsnx_platform_random(uint8_t *buf, size_t len) { ams::os::GenerateRandomBytes(buf, len); }
