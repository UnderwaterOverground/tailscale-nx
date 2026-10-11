// See status.hpp.
#include <stratosphere.hpp>

#include <atomic>
#include <cstring>

#include "log.hpp"
#include "runtime.hpp"
#include "status.hpp"

namespace ams::status {

    namespace {

        constexpr const char PausedPath[] = "sdmc:/config/tailscale-nx/paused";
        constexpr const char LoginPath[] = "sdmc:/config/tailscale-nx/login.txt";
        // Ultrahand shows a toast for each .notify file here (and only if it
        // is installed: we never create the directory).
        constexpr const char NotifyDir[] = "sdmc:/config/ultrahand/notifications";
        constexpr const char NotifyPath[] = "sdmc:/config/ultrahand/notifications/tailscale-nx-login.notify";
        constexpr const char ConnectedNotifyPath[] = "sdmc:/config/ultrahand/notifications/tailscale-nx-connected.notify";
        constexpr const char UpdateNotifyPath[] = "sdmc:/config/ultrahand/notifications/tailscale-nx-update.notify";
        // The overlay's "Notice when connected" switch: present = off.
        constexpr const char NoNoticePath[] = "sdmc:/config/tailscale-nx/no-connect-notice";
        constexpr const char UltrahandConfig[] = "sdmc:/config/ultrahand/config.ini";

        constinit os::SdkMutex g_mutex;
        constinit ::tsnx::Runtime *g_runtime = nullptr;
        constinit TsnxCtlStatus g_status = {};
        constinit bool g_authorized = false;
        constinit char g_login_url[256] = {};
        constinit char g_last_error[192] = {};
        constinit std::atomic<bool> g_paused = false;
        constinit bool g_connect_notice = true;   // config.ini connect_notice
        constinit bool g_announced_connected = false;  // once per boot
        // When the control server's map stream went away, 0 while it's up:
        // "Connected" turns into "Reconnecting" after ReconnectingAfterNs.
        constinit u64 g_control_lost_ns = 0;
        constexpr u64 ReconnectingAfterNs = 10'000'000'000ull;
        constinit std::atomic<u64> g_engine_ran_ns = 0;

        u64 NowNs() { return armTicksToNs(armGetSystemTick()); }

        bool Exists(const char *path, fs::DirectoryEntryType want) {
            fs::DirectoryEntryType t;
            return R_SUCCEEDED(fs::GetEntryType(std::addressof(t), path)) && t == want;
        }

        void WriteFile(const char *path, const char *data, size_t len) {
            static_cast<void>(fs::DeleteFile(path));
            if (R_FAILED(fs::CreateFile(path, static_cast<s64>(len)))) return;
            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Write))) return;
            static_cast<void>(fs::WriteFile(f, 0, data, len, fs::WriteOption::Flush));
            fs::CloseFile(f);
        }

        // Ultrahand's overlay-menu combo ("L+DDOWN+RS") in words.
        void MenuCombo(char *out, size_t cap) {
            util::SNPrintf(out, cap, "L+Down+R3");
            char buf[2_KB] = {};
            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(std::addressof(f), UltrahandConfig, fs::OpenMode_Read))) return;
            size_t got = 0;
            static_cast<void>(fs::ReadFile(std::addressof(got), f, 0, buf, sizeof buf - 1));
            fs::CloseFile(f);
            const char *p = std::strstr(buf, "\nkey_combo=");
            if (!p) return;
            p += 11;
            size_t n = 0;
            for (const char *tok = p; *tok && *tok != '\r' && *tok != '\n';) {
                const char *end = tok;
                while (*end && *end != '+' && *end != '\r' && *end != '\n') end++;
                const size_t len = static_cast<size_t>(end - tok);
                struct { const char *key, *word; } names[] = {
                    {"DDOWN", "Down"}, {"DUP", "Up"}, {"DLEFT", "Left"}, {"DRIGHT", "Right"}, {"RS", "R3"}, {"LS", "L3"},
                };
                const char *word = nullptr;
                for (const auto &nm : names) {
                    if (std::strlen(nm.key) == len && std::strncmp(tok, nm.key, len) == 0) word = nm.word;
                }
                n += util::SNPrintf(out + n, cap - n, "%s%.*s", n ? "+" : "", static_cast<int>(word ? std::strlen(word) : len), word ? word : tok);
                if (n >= cap || *end != '+') break;
                tok = end + 1;
            }
        }

        // A login link appeared: tell the user without them opening anything.
        void AnnounceLogin(const char *url) {
            char line[300];
            const int n = util::SNPrintf(line, sizeof line, "%s\n", url);
            WriteFile(LoginPath, line, static_cast<size_t>(n));
            if (!Exists(NotifyDir, fs::DirectoryEntryType_Directory)) return;
            char combo[64];
            MenuCombo(combo, sizeof combo);
            // Ultrahand cuts a toast at ~140 characters (font 18): keep it to
            // the link and the overlay combo; the scheme can be typed.
            const char *shown = std::strncmp(url, "https://", 8) == 0 ? url + 8 : url;
            static char json[512];
            const int m = util::SNPrintf(json, sizeof json,
                                         "{\n"
                                         "    \"title\": \"Tailscale: log in needed\",\n"
                                         "    \"text\": \"Open %s or %s > Tailscale for a QR code. Unwanted? Turn off tailscale-nx in Sysmodules.\",\n"
                                         "    \"font_size\": 18,\n"
                                         "    \"duration\": 0,\n"  // 0: stays until dismissed
                                         "    \"priority\": 20\n"
                                         "}\n",
                                         shown, combo);
            WriteFile(NotifyPath, json, static_cast<size_t>(m));
        }

        // First connection since boot: a short toast with our address. Not on
        // later reconnects (every wake would show it).
        void AnnounceConnected() {
            if (g_announced_connected || g_status.state != TSNX_CTL_CONNECTED) return;
            g_announced_connected = true;
            if (!g_connect_notice || Exists(NoNoticePath, fs::DirectoryEntryType_File)) return;
            if (!Exists(NotifyDir, fs::DirectoryEntryType_Directory)) return;
            static char json[256];
            const int n = util::SNPrintf(json, sizeof json,
                                         "{\n"
                                         "    \"title\": \"Tailscale\",\n"
                                         "    \"text\": \"Connected. IP: %u.%u.%u.%u\",\n"
                                         "    \"font_size\": 18,\n"
                                         "    \"duration\": 5000,\n"
                                         "    \"priority\": 10\n"
                                         "}\n",
                                         g_status.ipv4[0], g_status.ipv4[1], g_status.ipv4[2], g_status.ipv4[3]);
            WriteFile(ConnectedNotifyPath, json, static_cast<size_t>(n));
        }

        // `src` as JSON string content, at most `max` bytes of it (cut at a
        // character boundary, with "..."): quotes and backslashes escaped,
        // control characters dropped, UTF-8 kept.
        void JsonText(char *dst, size_t cap, const char *src, size_t max) {
            size_t n = 0, taken = 0;
            for (const char *p = src; *p && n + 8 < cap; p++) {
                const unsigned char c = static_cast<unsigned char>(*p);
                // Cut only before the first byte of a character.
                if (taken >= max && (c & 0xC0) != 0x80) {
                    dst[n++] = '.', dst[n++] = '.', dst[n++] = '.';
                    break;
                }
                taken++;
                if (c < 0x20 || c == 0x7f) continue;
                if (c == '"' || c == '\\') dst[n++] = '\\';
                dst[n++] = static_cast<char>(c);
            }
            dst[n] = 0;
        }

        void ClearLogin() {
            static_cast<void>(fs::DeleteFile(LoginPath));
            static_cast<void>(fs::DeleteFile(NotifyPath));
        }

        // Login URLs and errors go into JSON and the overlay: keep them to
        // plain printable ASCII without quotes or backslashes.
        void CopySafe(char *dst, size_t cap, const char *src) {
            size_t n = 0;
            for (; *src && n + 1 < cap; src++) {
                const char c = *src;
                if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') dst[n++] = c;
            }
            dst[n] = 0;
        }

    }

    void Initialize(::tsnx::Runtime &rt, u32 flags, bool connect_notice) {
        std::scoped_lock lk(g_mutex);
        g_runtime = std::addressof(rt);
        g_connect_notice = connect_notice;
        g_status.version = TSNX_CTL_VERSION;
        g_status.flags = flags;
        // A stale prompt from an earlier run: the engine reissues it if needed.
        ClearLogin();
        if (Exists(PausedPath, fs::DirectoryEntryType_File)) {
            g_paused = true;
            g_status.state = TSNX_CTL_PAUSED;
            rt.StartSuspended(::tsnx::Runtime::kPaused);
            Log("status: paused (delete %s or use the overlay to resume)", PausedPath);
        }
    }

    void OnEvent(const TsnxEvent &ev) {
        std::scoped_lock lk(g_mutex);
        switch (ev.kind) {
            case TSNX_EVENT_LOGIN_URL:
                g_authorized = false;
                CopySafe(g_login_url, sizeof g_login_url, ev.text);
                if (!g_paused) g_status.state = TSNX_CTL_NEEDS_LOGIN;
                AnnounceLogin(g_login_url);
                break;
            case TSNX_EVENT_AUTHORIZED:
                if (g_login_url[0]) ClearLogin();
                g_login_url[0] = 0;
                g_authorized = true;
                // Re-authorizing (after a resume or wake) doesn't re-announce
                // unchanged addresses: a known address means we're back.
                if (!g_paused) g_status.state = g_status.ipv4[0] ? TSNX_CTL_CONNECTED : TSNX_CTL_CONNECTING;
                AnnounceConnected();
                break;
            case TSNX_EVENT_ADDRESSES: {
                u32 a = 0, b = 0, c = 0, d = 0;
                const char *p = ev.text;
                auto num = [&p](u32 *out) {
                    if (*p < '0' || *p > '9') return false;
                    for (*out = 0; *p >= '0' && *p <= '9'; p++) *out = *out * 10 + static_cast<u32>(*p - '0');
                    return true;
                };
                if (num(&a) && *p++ == '.' && num(&b) && *p++ == '.' && num(&c) && *p++ == '.' && num(&d)) {
                    g_status.ipv4[0] = a, g_status.ipv4[1] = b, g_status.ipv4[2] = c, g_status.ipv4[3] = d;
                }
                if (g_authorized && !g_paused) g_status.state = TSNX_CTL_CONNECTED;
                AnnounceConnected();
                break;
            }
            case TSNX_EVENT_PEERS:
                g_status.peers = ev.value;
                break;
            case TSNX_EVENT_HOME_DERP:
                g_status.home_derp = ev.value;
                break;
            case TSNX_EVENT_CONTROL:
                if (ev.value) g_control_lost_ns = 0;
                else if (g_control_lost_ns == 0) g_control_lost_ns = NowNs();
                break;
            case TSNX_EVENT_PEER_PATH:
                if (ev.value) g_status.flags |= TSNX_CTL_FLAG_DIRECT;
                break;
            case TSNX_EVENT_ERROR:
                CopySafe(g_last_error, sizeof g_last_error, ev.text);
                break;
            default:
                break;
        }
    }

    void AnnounceFile(bool saved, const char *name, u64 bytes, const char *from, const char *why) {
        if (!Exists(NotifyDir, fs::DirectoryEntryType_Directory)) return;
        char n[96], f[48], w[200], size[24];
        JsonText(n, sizeof n, name, 48);
        JsonText(f, sizeof f, from, 24);
        JsonText(w, sizeof w, why, 120);
        if (bytes >= 1'000'000) {
            util::SNPrintf(size, sizeof size, "%lu.%lu MB", static_cast<unsigned long>(bytes / 1'000'000), static_cast<unsigned long>(bytes / 100'000 % 10));
        } else {
            util::SNPrintf(size, sizeof size, "%lu KB", static_cast<unsigned long>((bytes + 999) / 1000));
        }
        static char json[512];
        const int len = saved ? util::SNPrintf(json, sizeof json,
                                               "{\n    \"title\": \"Taildrop\",\n    \"text\": \"Received %s (%s) from %s. It's in the Taildrop folder.\",\n"
                                               "    \"font_size\": 18,\n    \"duration\": 6000,\n    \"priority\": 10\n}\n",
                                               n, size, f)
                              : util::SNPrintf(json, sizeof json,
                                               "{\n    \"title\": \"Taildrop\",\n    \"text\": \"Couldn't receive %s from %s: %s.\",\n"
                                               "    \"font_size\": 18,\n    \"duration\": 8000,\n    \"priority\": 10\n}\n",
                                               n, f, w);
        // Several files in a row: a file each, so none replaces another
        // before Ultrahand shows it.
        static u32 seq = 0;
        char path[96];
        util::SNPrintf(path, sizeof path, "%s/tailscale-nx-taildrop-%u.notify", NotifyDir, static_cast<unsigned>(seq++ % 8));
        WriteFile(path, json, static_cast<size_t>(len));
    }

    void AnnounceUpdate(const char *latest) {
        if (!Exists(NotifyDir, fs::DirectoryEntryType_Directory)) return;
        static char json[256];
        const int n = util::SNPrintf(json, sizeof json,
                                     "{\n"
                                     "    \"title\": \"Tailscale: update available\",\n"
                                     "    \"text\": \"tailscale-nx %s is out (you have %s).\",\n"
                                     "    \"font_size\": 18,\n"
                                     "    \"duration\": 10000,\n"
                                     "    \"priority\": 10\n"
                                     "}\n",
                                     latest, tsnx_version());
        WriteFile(UpdateNotifyPath, json, static_cast<size_t>(n));
    }

    TsnxCtlStatus Get() {
        std::scoped_lock lk(g_mutex);
        TsnxCtlStatus st = g_status;
        const u64 now = NowNs();
        if (st.state == TSNX_CTL_CONNECTED && g_control_lost_ns && now - g_control_lost_ns > ReconnectingAfterNs) {
            st.state = TSNX_CTL_CONNECTING;
        }
        const u64 ran = g_engine_ran_ns;
        const u64 idle_s = ran && now > ran ? (now - ran) / 1'000'000'000ull : 0;
        if (idle_s >= 3 && st.state != TSNX_CTL_PAUSED && st.state != TSNX_CTL_STOPPING) st.engine_stalled_s = static_cast<u32>(idle_s);
        return st;
    }

    void EngineRan(u64 now_ns) {
        g_engine_ran_ns = now_ns;
    }

    void SetOffline(bool offline) {
        std::scoped_lock lk(g_mutex);
        if (offline) g_status.flags |= TSNX_CTL_FLAG_OFFLINE;
        else g_status.flags &= ~TSNX_CTL_FLAG_OFFLINE;
    }

    size_t GetLoginUrl(char *out, size_t cap) {
        std::scoped_lock lk(g_mutex);
        return static_cast<size_t>(util::SNPrintf(out, cap, "%s", g_status.state == TSNX_CTL_NEEDS_LOGIN ? g_login_url : ""));
    }

    size_t GetLastError(char *out, size_t cap) {
        std::scoped_lock lk(g_mutex);
        return static_cast<size_t>(util::SNPrintf(out, cap, "%s", g_last_error));
    }

    bool IsPaused() {
        return g_paused;
    }

    void SetStopping() {
        std::scoped_lock lk(g_mutex);
        g_status.state = TSNX_CTL_STOPPING;
        g_login_url[0] = 0;
        ClearLogin();
    }

    void SetPaused(bool paused) {
        ::tsnx::Runtime *rt;
        {
            std::scoped_lock lk(g_mutex);
            if (g_paused == paused || !g_runtime || g_status.state == TSNX_CTL_STOPPING) return;
            g_paused = paused;
            rt = g_runtime;
            if (paused) {
                g_status.state = TSNX_CTL_PAUSED;
                WriteFile(PausedPath, "1", 1);
            } else {
                g_status.state = g_login_url[0] ? TSNX_CTL_NEEDS_LOGIN : TSNX_CTL_STARTING;  // until re-authorized
                static_cast<void>(fs::DeleteFile(PausedPath));
                // The loop didn't run while paused: that isn't a stall.
                g_engine_ran_ns = NowNs();
            }
        }
        // Without waiting for the engine loop: tsnx:ctl must always answer,
        // even while the loop is busy or stuck. Homebrew's tailnet sockets
        // fail at once anyway (bsd_mitm checks IsPaused), and the loop
        // closes or reopens the engine's own within a second.
        rt->RequestSuspended(::tsnx::Runtime::kPaused, paused);
        Log("status: Tailscale %s", paused ? "paused" : "resumed");
    }

}
