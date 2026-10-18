// Tailscale overlay: status, pause, stop/start and login (QR code) for the
// tailscale-nx sysmodule, through its tsnx:ctl service (native/ctl/tsnx_ctl.h).
#define TESLA_INIT_IMPL
#include <tesla.hpp>

#include <dirent.h>

#include <atomic>
#include <cstdio>
#include <cstring>

extern "C" {
#include "qrcodegen.h"
}
#include "tsnx_ctl.h"

namespace {

    // ---- tsnx:ctl client -------------------------------------------------

    // Atmosphère's sm makes a request for a service nobody has registered
    // wait until someone does (for boot ordering), so the overlay would hang
    // when tailscale-nx isn't running: ask whether it exists first.
    bool ServiceExists(const char *name) {
        u8 has = 0;
        const SmServiceName sn = smEncodeName(name);
        Result rc = 0;
        tsl::hlp::doWithSmSession([&] { rc = tipcDispatchInOut(smGetServiceSessionTipc(), 65100, sn, has); });  // see ctl::Main
        return R_SUCCEEDED(rc) && (has & 1);
    }

    // Every tsnx:ctl request runs on this thread, so a sysmodule that doesn't
    // answer (busy, or stuck) can't freeze the overlay: the panel keeps its
    // last answer and says the sysmodule isn't responding. The UI thread
    // only reads the snapshot and posts requests.
    namespace ctl {

        struct Snapshot {
            bool valid = false;  // the thread has looked at least once
            bool have = false;   // a session is open
            bool status_ok = false;
            TsnxCtlStatus status = {};
            char login_url[256] = {};
            char last_error[192] = {};
            TsnxCtlPeer peers[TSNX_CTL_MAX_PEERS] = {};
            u32 peer_count = 0;
        };

        Thread g_thread;
        bool g_started = false;
        UEvent g_wake;
        Mutex g_mutex;  // guards g_snap; never held during a request
        Snapshot g_snap;
        std::atomic<bool> g_quit{false};
        std::atomic<bool> g_wanted{true};          // false: close the session, don't reopen
        std::atomic<int> g_set_paused{-1};         // a SetPaused to send (0 or 1)
        std::atomic<bool> g_pause_pending{false};  // until a status after it is in
        std::atomic<bool> g_stop{false};           // a Stop to send
        std::atomic<bool> g_stop_done{false};
        Result g_stop_rc = 0;
        u32 g_stop_code = 0;
        std::atomic<u64> g_call_since{0};  // system tick the current request began, 0: none

        Service g_session;  // the thread's own
        bool g_open = false;

        template <class F>
        auto Call(F &&f) {
            g_call_since = armGetSystemTick();
            auto r = f();
            g_call_since = 0;
            return r;
        }

        size_t GetString(u32 cmd, char *buf, size_t cap) {
            u32 len = 0;
            const Result rc = Call([&] {
                return serviceDispatchOut(&g_session, cmd, len, .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out}, .buffers = {{buf, cap}});
            });
            if (R_FAILED(rc)) {
                buf[0] = 0;
                return 0;
            }
            buf[cap - 1] = 0;
            return len;
        }

        void Close() {
            if (g_open) serviceClose(&g_session);
            g_open = false;
        }

        void Refresh() {
            static Snapshot s;  // keeps the thread's stack small
            s = Snapshot{};
            if (g_open) {
                s.status_ok = R_SUCCEEDED(Call([] { return serviceDispatchOut(&g_session, 0, s.status); }));
                if (!s.status_ok) Close();  // the process went away
            }
            if (s.status_ok && s.status.state == TSNX_CTL_NEEDS_LOGIN) GetString(1, s.login_url, sizeof s.login_url);
            if (s.status_ok) GetString(3, s.last_error, sizeof s.last_error);
            if (s.status_ok && s.status.version >= 3 && s.status.state == TSNX_CTL_CONNECTED) {
                u32 n = 0;
                const Result rc = Call([&] {
                    return serviceDispatchOut(&g_session, 5, n, .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
                                              .buffers = {{s.peers, sizeof s.peers}});
                });
                s.peer_count = R_SUCCEEDED(rc) ? std::min<u32>(n, TSNX_CTL_MAX_PEERS) : 0;
            }
            s.have = g_open;
            s.valid = true;
            mutexLock(&g_mutex);
            g_snap = s;
            mutexUnlock(&g_mutex);
        }

        void Main(void *) {
            while (!g_quit) {
                if (!g_wanted) {
                    Close();
                } else if (!g_open) {
                    // Only once the service exists (see ServiceExists). Tesla
                    // keeps no sm session open after start-up, so open one
                    // around each use (libnx counts them, across threads too).
                    g_open = Call([] {
                        bool ok = false;
                        tsl::hlp::doWithSmSession([&] { ok = ServiceExists(TSNX_CTL_SERVICE) && R_SUCCEEDED(smGetService(&g_session, TSNX_CTL_SERVICE)); });
                        return ok;
                    });
                }
                if (g_open && g_stop) {
                    struct {
                        u32 code, detail;
                    } out = {};
                    g_stop_rc = Call([&] { return serviceDispatchOut(&g_session, 4, out); });
                    g_stop_code = out.code;
                    g_stop = false;
                    g_stop_done = true;
                }
                const int paused = g_set_paused.exchange(-1);
                if (g_open && paused >= 0) {
                    const u8 v = static_cast<u8>(paused);
                    Call([&] { return serviceDispatchIn(&g_session, 2, v); });
                }
                Refresh();
                if (paused >= 0) g_pause_pending = false;
                // About twice a second, or at once when asked.
                waitSingle(waiterForUEvent(&g_wake), 500'000'000ull);
            }
            Close();
        }

        void Wake() { ueventSignal(&g_wake); }

        void Start() {
            ueventCreate(&g_wake, true);
            mutexInit(&g_mutex);
            g_started = R_SUCCEEDED(threadCreate(&g_thread, Main, nullptr, nullptr, 0x4000, 0x2C, -2)) && R_SUCCEEDED(threadStart(&g_thread));
            // A moment for the first answer, so the panel opens with it.
            for (int i = 0; i < 30 && g_started; i++) {
                mutexLock(&g_mutex);
                const bool valid = g_snap.valid;
                mutexUnlock(&g_mutex);
                if (valid) break;
                svcSleepThread(10'000'000);
            }
        }

        void Finish() {
            if (!g_started) return;
            g_quit = true;
            Wake();
            // A request the sysmodule never answers would block forever:
            // then leave the thread to the process's exit.
            if (R_SUCCEEDED(waitSingleHandle(g_thread.handle, 1'000'000'000ull))) threadClose(&g_thread);
        }

        Snapshot Get() {
            mutexLock(&g_mutex);
            const Snapshot s = g_snap;
            mutexUnlock(&g_mutex);
            return s;
        }

        // How long the current request has waited for an answer.
        u64 BusySeconds() {
            const u64 since = g_call_since;
            return since ? armTicksToNs(armGetSystemTick() - since) / 1'000'000'000ull : 0;
        }

    }

    bool g_have_ctl = false;
    bool g_valid = false;  // ctl::Snapshot::valid
    TsnxCtlStatus g_status = {};
    bool g_status_ok = false;

    // ---- stop and start ------------------------------------------------------

    // Stop asks the sysmodule to end itself (tsnx:ctl Stop): it refuses
    // whenever exiting could disturb the console or an app. Start launches it
    // through pm. Neither touches its boot flag.
    constexpr u64 SysmoduleProgramId = 0x4200000000005453;
    constexpr const char DisabledPath[] = "sdmc:/config/tailscale-nx/disabled";
    // Our system tick, so the sysmodule's crash guard knows this start isn't
    // a boot.
    constexpr const char StartRequestedPath[] = "sdmc:/config/tailscale-nx/start_requested";

    bool SysmoduleRunning() {
        u64 pid = 0;
        return R_SUCCEEDED(pmdmntGetProcessId(&pid, SysmoduleProgramId)) && pid != 0;
    }

    enum class Phase {
        Idle,
        Stopping,  // the Stop request is under way (on the ctl thread)
        Exiting,   // accepted; waiting for the process and its service to go
        Starting,  // running, but its service isn't there yet
    };
    Phase g_phase = Phase::Idle;
    u64 g_phase_since = 0;  // system tick
    bool g_we_started = false;
    char g_msg[2][64] = {};  // the outcome of the last stop or start
    bool g_msg_problem = false;  // drawn in red

    void SetPhase(Phase p) {
        g_phase = p;
        g_phase_since = armGetSystemTick();
    }

    u64 PhaseSeconds() { return armTicksToNs(armGetSystemTick() - g_phase_since) / 1'000'000'000ull; }

    // A stop or start that didn't happen (shown in red).
    void Say(const char *first, const char *second = "") {
        std::memset(g_msg, 0, sizeof g_msg);  // see DrawMessage
        std::snprintf(g_msg[0], sizeof g_msg[0], "%s", first);
        std::snprintf(g_msg[1], sizeof g_msg[1], "%s", second);
        g_msg_problem = true;
    }

    // Progress or success.
    void Note(const char *first, const char *second = "") {
        Say(first, second);
        g_msg_problem = false;
    }

    // Stop can take a few seconds (it waits for the engine and the system);
    // the ctl thread sends it while the overlay keeps drawing.
    void BeginStop() {
        if (!g_have_ctl || g_phase != Phase::Idle) return;
        if (g_status.version < 2) {
            Say("This tailscale-nx is too old to stop here.", "Update it, or restart the console.");
            return;
        }
        ctl::g_stop_done = false;
        ctl::g_stop = true;
        ctl::Wake();
        Note("");
        SetPhase(Phase::Stopping);
    }

    void FinishStop() {
        SetPhase(Phase::Idle);
        // A failed request most likely means it exited before replying.
        if (R_FAILED(ctl::g_stop_rc) || ctl::g_stop_code == TSNX_CTL_STOP_OK) {
            ctl::g_wanted = false;
            ctl::Wake();
            g_have_ctl = g_status_ok = false;
            SetPhase(Phase::Exiting);
            return;
        }
        switch (ctl::g_stop_code) {
            case TSNX_CTL_STOP_HOMEBREW:
                Say("Close homebrew apps first: they have", "connections through tailscale-nx.");
                break;
            case TSNX_CTL_STOP_BUSY:
                Say("Busy (sleep, wake or setting up).", "Try again in a moment.");
                break;
            default:
                Say("Couldn't stop cleanly. It stays idle", "until the console restarts.");
                break;
        }
    }

    bool FileExists(const char *path) {
        bool found = false;
        tsl::hlp::doWithSDCardHandle([&] {
            if (FILE *f = std::fopen(path, "r")) {
                found = true;
                std::fclose(f);
            }
        });
        return found;
    }

    void StartSysmodule() {
        if (g_phase != Phase::Idle) return;
        if (SysmoduleRunning()) {
            SetPhase(Phase::Starting);
            return;
        }
        if (FileExists(DisabledPath)) {
            Say("config/tailscale-nx/disabled keeps it off.", "Delete that file to start it.");
            return;
        }
        tsl::hlp::doWithSDCardHandle([] {
            if (FILE *f = std::fopen(StartRequestedPath, "w")) {
                char tick[24];  // snprintf, not fprintf: that would add 17 KB
                std::snprintf(tick, sizeof tick, "%llu\n", static_cast<unsigned long long>(armGetSystemTick()));
                std::fputs(tick, f);
                std::fclose(f);
            }
        });
        Result rc = 0;
        tsl::hlp::doWithSmSession([&rc] { rc = pmshellInitialize(); });  // see ctl::Main
        if (R_SUCCEEDED(rc)) {
            const NcmProgramLocation loc = {.program_id = SysmoduleProgramId, .storageID = NcmStorageId_None};
            u64 pid = 0;
            rc = pmshellLaunchProgram(0, &loc, &pid);
            pmshellExit();
        }
        if (R_FAILED(rc)) {
            tsl::hlp::doWithSDCardHandle([] { std::remove(StartRequestedPath); });
            if (SysmoduleRunning()) {  // started by someone else meanwhile
                SetPhase(Phase::Starting);
                return;
            }
            char line[64];
            std::snprintf(line, sizeof line, "Couldn't start it (error 0x%x).", rc);
            Say(line, "Restarting the console starts it.");
            return;
        }
        Note("");
        g_we_started = true;
        SetPhase(Phase::Starting);
    }

    // ---- state shared with the drawers -------------------------------------

    // Why the sysmodule isn't running, read from the SD card when the overlay
    // opens (the crash guard's file, the kill switch, or a missing boot flag).
    constexpr const char CrashedPath[] = "sdmc:/config/tailscale-nx/crashed";
    constexpr const char Boot2Path[] = "sdmc:/atmosphere/contents/4200000000005453/flags/boot2.flag";
    char g_crashed[160] = {};   // first line of the crash guard's reason
    char g_not_started[200] = {};  // why it declined to start (too little memory)
    bool g_no_boot_flag = false;
    bool g_disabled = false;

    void ReadWhyNotRunning() {
        tsl::hlp::doWithSDCardHandle([] {
            g_crashed[0] = 0;
            if (FILE *f = std::fopen(CrashedPath, "r")) {
                if (!std::fgets(g_crashed, sizeof g_crashed, f) || !g_crashed[0]) std::snprintf(g_crashed, sizeof g_crashed, "repeated failures");
                g_crashed[std::strcspn(g_crashed, "\r\n")] = 0;
                std::fclose(f);
            }
            g_not_started[0] = 0;
            if (FILE *f = std::fopen("sdmc:/config/tailscale-nx/not_started", "r")) {
                if (std::fgets(g_not_started, sizeof g_not_started, f)) g_not_started[std::strcspn(g_not_started, "\r\n")] = 0;
                std::fclose(f);
            }
            FILE *b = std::fopen(Boot2Path, "r");
            g_no_boot_flag = b == nullptr;
            if (b) std::fclose(b);
            FILE *d = std::fopen(DisabledPath, "r");
            g_disabled = d != nullptr;
            if (d) std::fclose(d);
        });
    }

    // Clears the crash guard and starts tailscale-nx again.
    void TurnBackOn() {
        tsl::hlp::doWithSDCardHandle([] {
            for (const char *p : {CrashedPath, "sdmc:/config/tailscale-nx/starting", "sdmc:/config/tailscale-nx/sleep_failures",
                                  "sdmc:/config/tailscale-nx/sleeping"}) {
                std::remove(p);
            }
        });
        g_crashed[0] = 0;
        StartSysmodule();
    }

    // Moves the stop/start phases along (twice a second).
    void Poll() {
        switch (g_phase) {
            case Phase::Stopping:
                if (ctl::g_stop_done) FinishStop();
                break;
            case Phase::Exiting:
                // Gone from pm and from sm: a new instance can register again.
                if (!SysmoduleRunning() && !ServiceExists(TSNX_CTL_SERVICE)) {
                    ctl::g_wanted = true;
                    SetPhase(Phase::Idle);
                    ReadWhyNotRunning();
                    Note("Stopped. It starts again at the next boot.");
                } else if (PhaseSeconds() >= 10) {
                    Note("Still stopping...");
                }
                break;
            case Phase::Starting:
                if (!SysmoduleRunning()) {
                    SetPhase(Phase::Idle);
                    ReadWhyNotRunning();
                    if (g_we_started) Say("It stopped right away. See", "config/tailscale-nx/sysmodule.log.");
                    g_we_started = false;
                } else if (g_have_ctl) {  // the ctl thread opens the session
                    SetPhase(Phase::Idle);
                    g_we_started = false;
                }
                break;
            case Phase::Idle:
                // Running without its service: starting up (it waits for the
                // network first), or a stale session to an old instance.
                if (!g_have_ctl && SysmoduleRunning()) SetPhase(Phase::Starting);
                break;
        }
    }

    char g_login_url[256] = {};
    char g_last_error[192] = {};
    TsnxCtlPeer g_peers[TSNX_CTL_MAX_PEERS] = {};
    u32 g_peer_count = 0;

    // The login link as a QR code (encoded once per link).
    uint8_t g_qr[qrcodegen_BUFFER_LEN_MAX];
    uint8_t g_qr_tmp[qrcodegen_BUFFER_LEN_MAX];
    char g_qr_for[256] = {};
    bool g_qr_ok = false;

    void CtlSetPaused(bool paused) {
        if (!g_have_ctl || g_phase != Phase::Idle) return;
        ctl::g_pause_pending = true;
        ctl::g_set_paused = paused;
        ctl::Wake();
    }

    // Takes the ctl thread's latest answers.
    void Refresh() {
        const ctl::Snapshot s = ctl::Get();
        g_valid = s.valid;
        g_have_ctl = s.have && g_phase != Phase::Exiting;
        g_status_ok = s.status_ok && g_have_ctl;
        g_status = s.status;
        std::memcpy(g_peers, s.peers, sizeof g_peers);
        g_peer_count = s.peer_count;
        std::snprintf(g_login_url, sizeof g_login_url, "%s", s.login_url);
        std::snprintf(g_last_error, sizeof g_last_error, "%s", s.last_error);
        if (std::strcmp(g_login_url, g_qr_for) != 0) {
            std::snprintf(g_qr_for, sizeof g_qr_for, "%s", g_login_url);
            g_qr_ok = g_login_url[0] && qrcodegen_encodeText(g_login_url, g_qr_tmp, g_qr, qrcodegen_Ecc_LOW, qrcodegen_VERSION_MIN,
                                                             qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, true);
        }
    }

    const char *RegionName(u32 id) {
        // Tailscale's DERP region ids (the common ones).
        static const char *const names[] = {
            nullptr,       "New York",  "San Francisco", "Singapore", "Frankfurt", "Sydney",  "Bangalore",  "Tokyo",
            "London",      "Dallas",    "Seattle",       "Sao Paulo", "Chicago",   "Denver",  "Amsterdam",  "Johannesburg",
            "Miami",       "Los Angeles", "Paris",       "Madrid",    "Hong Kong", "Toronto", "Warsaw",     "Dubai",
            "Honolulu",    "Nairobi",   "Nuremberg",     "Ashburn",
        };
        return id < sizeof names / sizeof names[0] ? names[id] : nullptr;
    }

    // ---- drawing ------------------------------------------------------------

    constexpr tsl::Color White{0xF, 0xF, 0xF, 0xF};
    constexpr tsl::Color Black{0x0, 0x0, 0x0, 0xF};
    constexpr tsl::Color Grey{0xA, 0xA, 0xA, 0xF};
    constexpr tsl::Color Green{0x4, 0xE, 0x6, 0xF};
    constexpr tsl::Color Yellow{0xF, 0xC, 0x3, 0xF};
    constexpr tsl::Color Blue{0x5, 0xA, 0xF, 0xF};
    constexpr tsl::Color Red{0xF, 0x5, 0x5, 0xF};

    // Draws text over two lines at most (broken at a space, about `cols`
    // characters each; the rest is cut with "...").
    void DrawTwoLines(tsl::gfx::Renderer *r, const char *text, s32 x, s32 y, u32 size, tsl::Color c, size_t cols) {
        char first[96], second[96] = "";
        size_t cut = std::strlen(text);
        if (cut > cols) {
            cut = cols;
            while (cut > 0 && text[cut] != ' ') cut--;
            if (cut == 0) cut = cols;
        }
        std::snprintf(first, sizeof first, "%.*s", static_cast<int>(cut), text);
        const char *rest = text + cut + (text[cut] == ' ');
        if (*rest) {
            if (std::strlen(rest) > cols) std::snprintf(second, sizeof second, "%.*s...", static_cast<int>(cols - 3), rest);
            else std::snprintf(second, sizeof second, "%s", rest);
        }
        if (first[0]) r->drawString(first, false, x, y, size, r->a(c));  // see DrawMessage
        if (second[0]) r->drawString(second, false, x, y + size + 3, size, r->a(c));
    }

    // No internet connection (not while paused or stopping: then it's moot).
    bool Offline() {
        return (g_status.flags & TSNX_CTL_FLAG_OFFLINE) && g_status.state != TSNX_CTL_PAUSED && g_status.state != TSNX_CTL_STOPPING;
    }

    // Its engine loop hasn't run for a while (short pauses are normal: a
    // DNS lookup or an SD card write can take a few seconds).
    bool Stalled() { return g_status.engine_stalled_s >= 10; }

    void DrawStatus(tsl::gfx::Renderer *r, s32 x, s32 y, s32 w, s32 h) {
        const char *state = "Not running";
        tsl::Color color = Red;
        if (g_phase == Phase::Stopping || g_phase == Phase::Exiting) {
            r->drawString("Stopping...", false, x + 20, y + 40, 30, r->a(Grey));
            return;
        }
        // The sysmodule hasn't answered a request: it's busy or stuck.
        if (const u64 busy = ctl::BusySeconds(); busy >= 2) {
            char since[64];
            std::snprintf(since, sizeof since, "No reply from tailscale-nx for %llu seconds.", static_cast<unsigned long long>(busy));
            r->drawString("Not responding", false, x + 20, y + 40, 30, r->a(Red));
            r->drawString(since, false, x + 20, y + 75, 17, r->a(Grey));
            r->drawString("Restart the console if this continues.", false, x + 20, y + 100, 17, r->a(Grey));
            return;
        }
        if (!g_valid) {
            r->drawString("Checking...", false, x + 20, y + 40, 30, r->a(Grey));
            return;
        }
        if (g_phase == Phase::Starting) {
            r->drawString("Starting...", false, x + 20, y + 40, 30, r->a(Blue));
            r->drawString("The sysmodule is running and waits for", false, x + 20, y + 75, 17, r->a(Grey));
            r->drawString("the network before it can be reached.", false, x + 20, y + 100, 17, r->a(Grey));
            return;
        }
        if (g_status_ok) {
            switch (g_status.state) {
                case TSNX_CTL_STARTING:    state = "Starting...";          color = Blue;   break;
                case TSNX_CTL_NEEDS_LOGIN: state = "Log in needed";        color = Yellow; break;
                case TSNX_CTL_CONNECTING:  state = g_status.ipv4[0] ? "Reconnecting..." : "Connecting..."; color = Blue; break;
                case TSNX_CTL_CONNECTED:   state = "Connected";            color = Green;  break;
                case TSNX_CTL_PAUSED:      state = "Paused";               color = Grey;   break;
                case TSNX_CTL_STOPPING:    state = "Stopping...";          color = Grey;   break;
            }
            if (Offline()) {
                state = "Offline";
                color = Grey;
            } else if (Stalled()) {
                state = "Not responding";
                color = Red;
            }
        }
        r->drawString(state, false, x + 20, y + 40, 30, r->a(color));
        char line[128];
        if (!g_status_ok) {
            if (g_crashed[0]) {
                // "tailscale-nx stopped itself: <why>." -> show the reason.
                const char *why = std::strstr(g_crashed, ": ");
                why = why ? why + 2 : g_crashed;
                r->drawString("It turned itself off after failures:", false, x + 20, y + 75, 17, r->a(Grey));
                DrawTwoLines(r, why, x + 20, y + 98, 15, Grey, 40);
            } else if (g_not_started[0]) {
                // "Too little system memory: other sysmodules leave N KB free ..."
                r->drawString("It didn't start: too little system memory.", false, x + 20, y + 75, 17, r->a(Grey));
                r->drawString("Other sysmodules use the rest; turn one off.", false, x + 20, y + 100, 17, r->a(Grey));
            } else if (g_disabled) {
                r->drawString("config/tailscale-nx/disabled keeps it off.", false, x + 20, y + 75, 17, r->a(Grey));
                r->drawString("Delete that file to start it.", false, x + 20, y + 100, 17, r->a(Grey));
            } else if (g_no_boot_flag) {
                r->drawString("The tailscale-nx sysmodule isn't running,", false, x + 20, y + 75, 17, r->a(Grey));
                r->drawString("and its boot setting in Sysmodules is off.", false, x + 20, y + 100, 17, r->a(Grey));
            } else {
                r->drawString("The tailscale-nx sysmodule isn't running.", false, x + 20, y + 75, 17, r->a(Grey));
                r->drawString("It starts at boot, or with Start below.", false, x + 20, y + 100, 17, r->a(Grey));
            }
            return;
        }
        if (Offline()) {
            r->drawString("No internet connection.", false, x + 20, y + 75, 17, r->a(Grey));
            r->drawString("It reconnects once the Switch is back online.", false, x + 20, y + 102, 17, r->a(Grey));
            return;
        }
        if (Stalled()) {
            // It answers, but its engine loop hasn't run: it can't connect.
            std::snprintf(line, sizeof line, "It has made no progress for %u seconds.", g_status.engine_stalled_s);
            r->drawString(line, false, x + 20, y + 75, 17, r->a(Grey));
            r->drawString("Restart the console if this continues.", false, x + 20, y + 102, 17, r->a(Grey));
            return;
        }
        // Our address only while it's usable (it stays known while paused).
        const u8 *ip = g_status.ipv4;
        if (ip[0] && g_status.state == TSNX_CTL_CONNECTED) {
            std::snprintf(line, sizeof line, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
            r->drawString(line, false, x + 20, y + 75, 20, r->a(White));
        }
        if (g_status.version >= 3) {
            std::snprintf(line, sizeof line, "%u peers", g_status.peers);
        } else {
            // Older sysmodules: the home relay, and "direct" once any peer was.
            const char *region = RegionName(g_status.home_derp);
            char relay[48] = "";
            if (g_status.home_derp) {
                if (region) std::snprintf(relay, sizeof relay, ", relay %s", region);
                else std::snprintf(relay, sizeof relay, ", relay region %u", g_status.home_derp);
            }
            std::snprintf(line, sizeof line, "%u peers%s%s", g_status.peers, relay, (g_status.flags & TSNX_CTL_FLAG_DIRECT) ? ", direct" : "");
        }
        r->drawString(line, false, x + 20, y + 102, 17, r->a(Grey));
        // The peers in use, and whether each is relayed (slower) or direct.
        if (g_status.state == TSNX_CTL_CONNECTED) {
            for (u32 i = 0; i < std::min<u32>(g_peer_count, 2); i++) {
                const TsnxCtlPeer &p = g_peers[i];
                if (!p.name[0]) continue;
                // Long names are shortened so the path always shows.
                char name[24];
                if (std::strlen(p.name) > 18) std::snprintf(name, sizeof name, "%.17s...", p.name);
                else std::snprintf(name, sizeof name, "%s", p.name);
                const char *via = RegionName(p.relay_region);
                if (p.direct) std::snprintf(line, sizeof line, "%s: direct", name);
                else if (via) std::snprintf(line, sizeof line, "%s: relayed via %s", name, via);
                else std::snprintf(line, sizeof line, "%s: relayed", name);
                r->drawString(line, false, x + 20, y + 125 + static_cast<s32>(i) * 21, 15, r->a(p.direct ? Green : Yellow), w - 40);
            }
        }
        if (g_last_error[0] && g_status.state != TSNX_CTL_CONNECTED && g_status.state != TSNX_CTL_PAUSED) {
            char error[sizeof g_last_error + 16];
            std::snprintf(error, sizeof error, "Last error: %s", g_last_error);
            DrawTwoLines(r, error, x + 20, y + 130, 15, Grey, 46);
        }
    }

    // The login QR code, or what's active once connected.
    void DrawLogin(tsl::gfx::Renderer *r, s32 x, s32 y, s32 w, s32 h) {
        if (g_status_ok && g_status.state == TSNX_CTL_NEEDS_LOGIN && g_qr_ok) {
            r->drawString("Scan to log in, then approve this Switch:", false, x + 20, y + 25, 17, r->a(White));
            const int n = qrcodegen_getSize(g_qr);
            const int quiet = 3, scale = std::max(1, std::min((w - 40) / (n + 2 * quiet), (h - 80) / (n + 2 * quiet)));
            const int side = (n + 2 * quiet) * scale;
            const s32 qx = x + (w - side) / 2, qy = y + 40;
            r->drawRect(qx, qy, side, side, r->a(White));
            for (int my = 0; my < n; my++) {
                for (int mx = 0; mx < n; mx++) {
                    if (qrcodegen_getModule(g_qr, mx, my)) {
                        r->drawRect(qx + (quiet + mx) * scale, qy + (quiet + my) * scale, scale, scale, r->a(Black));
                    }
                }
            }
            // The link itself, for typing: drop the scheme to save width.
            const char *shown = std::strncmp(g_login_url, "https://", 8) == 0 ? g_login_url + 8 : g_login_url;
            r->drawString(shown, false, x + 20, qy + side + 28, 15, r->a(Grey), w - 40);
            return;
        }
        s32 ty = y + 30;
        auto line = [&](const char *text, tsl::Color c) {
            r->drawString(text, false, x + 20, ty, 17, r->a(c));
            ty += 28;
        };
        if (!g_status_ok) return;
        if (g_status.flags & TSNX_CTL_FLAG_MITM) line("Homebrew apps can reach tailnet addresses.", White);
        if (g_status.flags & TSNX_CTL_FLAG_MAGICDNS) line("Tailnet names resolve (e.g. in Moonlight).", White);
        if (g_status.state == TSNX_CTL_PAUSED) line("Paused: tailnet connections fail until resumed.", Grey);
        if (g_status.memory_kb) {
            char mem[96];
            std::snprintf(mem, sizeof mem, "Memory: %u.%u MB. System free: %u.%u MB.", g_status.memory_kb / 1024,
                          g_status.memory_kb % 1024 * 10 / 1024, g_status.system_free_kb / 1024, g_status.system_free_kb % 1024 * 10 / 1024);
            line(mem, Grey);
        }
    }

    // The outcome of the last stop or start.
    void DrawMessage(tsl::gfx::Renderer *r, s32 x, s32 y, s32 w, s32 h) {
        const tsl::Color c = g_msg_problem ? Red : White;
        // Never an empty string: Tesla's drawString reads one character past
        // its end before checking, so "" would draw whatever follows it.
        if (g_msg[0][0]) r->drawString(g_msg[0], false, x + 20, y + 22, 15, r->a(c));
        if (g_msg[1][0]) r->drawString(g_msg[1], false, x + 20, y + 42, 15, r->a(c));
    }

    void DrawTip(tsl::gfx::Renderer *r, s32 x, s32 y, s32 w, s32 h) {
        r->drawString("Stop ends tailscale-nx until the next boot.", false, x + 20, y + 25, 15, r->a(Grey));
        r->drawString("To keep it off, turn off its boot setting", false, x + 20, y + 47, 15, r->a(Grey));
        r->drawString("in Sysmodules.", false, x + 20, y + 69, 15, r->a(Grey));
    }

    // ---- settings -------------------------------------------------------------

    // Switches the sysmodule reads as marker files: present = off.
    constexpr const char NoNoticePath[] = "sdmc:/config/tailscale-nx/no-connect-notice";
    constexpr const char NoUpdateCheckPath[] = "sdmc:/config/tailscale-nx/no-update-check";

    bool MarkerExists(const char *path) {
        bool exists = false;
        tsl::hlp::doWithSDCardHandle([&] {
            if (FILE *f = std::fopen(path, "r")) {
                exists = true;
                std::fclose(f);
            }
        });
        return exists;
    }

    void SetMarker(const char *path, bool present) {
        tsl::hlp::doWithSDCardHandle([&] {
            if (present) {
                if (FILE *f = std::fopen(path, "w")) std::fclose(f);
            } else {
                std::remove(path);
            }
        });
    }

    // ---- GUI ----------------------------------------------------------------

    class MainGui : public tsl::Gui {
        public:
            tsl::elm::Element *createUI() override {
                Refresh();
                auto *frame = new tsl::elm::OverlayFrame("Tailscale", "tailscale-nx " APP_VERSION);
                auto *list = new tsl::elm::List();
                list->addItem(new tsl::elm::CustomDrawer(DrawStatus), 165);
                if (!g_status_ok) ReadWhyNotRunning();

                m_toggle = new tsl::elm::ToggleListItem("Tailscale", !(g_status_ok && g_status.state == TSNX_CTL_PAUSED));
                m_toggle->setStateChangedListener([](bool on) {
                    CtlSetPaused(!on);
                    Refresh();
                });
                list->addItem(m_toggle);

                // Stop or start the sysmodule itself (not its boot setting).
                m_power = new tsl::elm::ListItem(PowerLabel());
                m_power->setClickListener([](u64 keys) {
                    if (!(keys & HidNpadButton_A)) return false;
                    switch (PowerAction()) {
                        case Action::Stop:       BeginStop(); break;
                        case Action::Start:      StartSysmodule(); break;
                        case Action::TurnBackOn: TurnBackOn(); break;
                        case Action::None:       break;
                    }
                    return true;
                });
                list->addItem(m_power);
                list->addItem(new tsl::elm::CustomDrawer(DrawMessage), 50);

                // The sysmodule's "Connected. IP: ..." toast at boot; off is
                // a marker file it checks when it connects.
                auto *notice = new tsl::elm::ToggleListItem("Connection notice", !MarkerExists(NoNoticePath));
                notice->setStateChangedListener([](bool on) { SetMarker(NoNoticePath, !on); });
                list->addItem(notice);

                // The sysmodule's check for a newer release on GitHub, once
                // per boot soon after connecting (a toast if there is one).
                auto *updates = new tsl::elm::ToggleListItem("Check for updates", !MarkerExists(NoUpdateCheckPath));
                updates->setStateChangedListener([](bool on) { SetMarker(NoUpdateCheckPath, !on); });
                list->addItem(updates);

                list->addItem(new tsl::elm::CustomDrawer(DrawLogin), 330);
                list->addItem(new tsl::elm::CustomDrawer(DrawTip), 85);
                frame->setContent(list);
                return frame;
            }

            void update() override {
                // Poll about twice a second.
                if (++m_frames % 30 != 0) return;
                Poll();
                Refresh();
                const bool on = !(g_status_ok && g_status.state == TSNX_CTL_PAUSED);
                if (m_toggle && !ctl::g_pause_pending && m_toggle->getState() != on) m_toggle->setState(on);
                if (m_power) {
                    const char *label = PowerLabel();
                    if (label != m_power_label) {
                        m_power->setText(label);
                        m_power_label = label;
                    }
                }
            }

        private:
            enum class Action { None, Stop, Start, TurnBackOn };

            static Action PowerAction() {
                if (g_phase != Phase::Idle) return Action::None;
                if (g_have_ctl && g_status_ok) return g_status.state == TSNX_CTL_STOPPING ? Action::None : Action::Stop;
                if (SysmoduleRunning()) return Action::None;
                return g_crashed[0] ? Action::TurnBackOn : Action::Start;
            }

            static const char *PowerLabel() {
                switch (g_phase) {
                    case Phase::Stopping:
                    case Phase::Exiting:  return "Stopping...";
                    case Phase::Starting: return "Starting...";
                    case Phase::Idle:     break;
                }
                if (g_have_ctl && g_status_ok) return g_status.state == TSNX_CTL_STOPPING ? "Restart the console to finish" : "Stop tailscale-nx";
                return g_crashed[0] ? "Turn back on" : "Start tailscale-nx";
            }

            tsl::elm::ToggleListItem *m_toggle = nullptr;
            tsl::elm::ListItem *m_power = nullptr;
            const char *m_power_label = nullptr;
            u32 m_frames = 0;
    };

    // Ultrahand shows notifications (Taildrop, "Connected") only while its
    // own menu is the loaded overlay, and a hidden Tesla overlay stays loaded.
    // With Ultrahand installed, hiding exits instead, back to a hidden menu.
    bool g_exit_on_hide = false;

    class TailscaleOverlay : public tsl::Overlay {
        public:
            void initServices() override {
                ctl::Start();
                tsl::hlp::doWithSDCardHandle([] {
                    if (DIR *d = opendir("sdmc:/config/ultrahand/notifications")) {
                        g_exit_on_hide = true;
                        closedir(d);
                    }
                });
            }

            // From the combo, HOME or a touch outside us (Tesla's input thread).
            void onHide() override {
                if (!g_exit_on_hide) return;
                // Without --skipCombo the menu starts hidden, as at boot.
                envSetNextLoad("sdmc:/switch/.overlays/ovlmenu.ovl", "ovlmenu.ovl");
                close();
            }

            void exitServices() override {
                ctl::Finish();
            }

            std::unique_ptr<tsl::Gui> loadInitialGui() override {
                return initially<MainGui>();
            }
    };

}

int main(int argc, char **argv) {
    return tsl::loop<TailscaleOverlay>(argc, argv);
}
