// Tailscale overlay: status, pause, stop/start and login (QR code) for the
// tailscale-nx sysmodule, through its tsnx:ctl service (native/ctl/tsnx_ctl.h).
#define TESLA_INIT_IMPL
#include <tesla.hpp>

#include <atomic>
#include <cstdio>
#include <cstring>

extern "C" {
#include "qrcodegen.h"
}
#include "tsnx_ctl.h"

namespace {

    // ---- tsnx:ctl client -------------------------------------------------

    Service g_ctl;
    bool g_have_ctl = false;

    // Atmosphère's sm makes a request for a service nobody has registered
    // wait until someone does (for boot ordering), so the overlay would hang
    // when tailscale-nx isn't running: ask whether it exists first.
    bool ServiceExists(const char *name) {
        u8 has = 0;
        const SmServiceName sn = smEncodeName(name);
        Result rc = 0;
        tsl::hlp::doWithSmSession([&] { rc = tipcDispatchInOut(smGetServiceSessionTipc(), 65100, sn, has); });  // see OpenCtl
        return R_SUCCEEDED(rc) && (has & 1);
    }

    bool CtlGetStatus(TsnxCtlStatus *out) {
        return g_have_ctl && R_SUCCEEDED(serviceDispatchOut(&g_ctl, 0, *out));
    }

    size_t CtlGetString(u32 cmd, char *buf, size_t cap) {
        u32 len = 0;
        if (!g_have_ctl ||
            R_FAILED(serviceDispatchOut(&g_ctl, cmd, len, .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out}, .buffers = {{buf, cap}}))) {
            buf[0] = 0;
            return 0;
        }
        buf[cap - 1] = 0;
        return len;
    }

    TsnxCtlStatus g_status = {};
    bool g_status_ok = false;

    void CloseCtl() {
        if (g_have_ctl) serviceClose(&g_ctl);
        g_have_ctl = false;
        g_status_ok = false;
    }

    // Only once the service exists (see ServiceExists). Tesla keeps no sm
    // session open after start-up, so open one around each use.
    void OpenCtl() {
        if (g_have_ctl) return;
        tsl::hlp::doWithSmSession(
            [] { g_have_ctl = ServiceExists(TSNX_CTL_SERVICE) && R_SUCCEEDED(smGetService(&g_ctl, TSNX_CTL_SERVICE)); });
    }

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
        Stopping,  // the Stop request is under way (on g_stop_thread)
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
        std::snprintf(g_msg[0], sizeof g_msg[0], "%s", first);
        std::snprintf(g_msg[1], sizeof g_msg[1], "%s", second);
        g_msg_problem = true;
    }

    // Progress or success.
    void Note(const char *first, const char *second = "") {
        Say(first, second);
        g_msg_problem = false;
    }

    // Stop can take a few seconds (it waits for the engine and the system),
    // so it runs on its own thread while the overlay keeps drawing. Nothing
    // else uses the session meanwhile.
    Thread g_stop_thread;
    std::atomic<bool> g_stop_done{false};
    Result g_stop_rc = 0;
    u32 g_stop_code = 0;

    void StopThreadMain(void *) {
        struct {
            u32 code, detail;
        } out = {};
        g_stop_rc = serviceDispatchOut(&g_ctl, 4, out);
        g_stop_code = out.code;
        g_stop_done = true;
    }

    void BeginStop() {
        if (!g_have_ctl || g_phase != Phase::Idle) return;
        if (g_status.version < 2) {
            Say("This tailscale-nx is too old to stop here.", "Update it, or restart the console.");
            return;
        }
        g_stop_done = false;
        if (R_FAILED(threadCreate(&g_stop_thread, StopThreadMain, nullptr, nullptr, 0x2000, 0x2C, -2))) {
            Say("Couldn't stop it (out of memory).");
            return;
        }
        if (R_FAILED(threadStart(&g_stop_thread))) {
            threadClose(&g_stop_thread);
            Say("Couldn't stop it (out of memory).");
            return;
        }
        Note("");
        SetPhase(Phase::Stopping);
    }

    void FinishStop() {
        threadWaitForExit(&g_stop_thread);
        threadClose(&g_stop_thread);
        SetPhase(Phase::Idle);
        // A failed request most likely means it exited before replying.
        if (R_FAILED(g_stop_rc) || g_stop_code == TSNX_CTL_STOP_OK) {
            CloseCtl();
            SetPhase(Phase::Exiting);
            return;
        }
        switch (g_stop_code) {
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
        tsl::hlp::doWithSmSession([&rc] { rc = pmshellInitialize(); });  // see OpenCtl
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
                if (g_stop_done) FinishStop();
                break;
            case Phase::Exiting:
                // Gone from pm and from sm: a new instance can register again.
                if (!SysmoduleRunning() && !ServiceExists(TSNX_CTL_SERVICE)) {
                    SetPhase(Phase::Idle);
                    ReadWhyNotRunning();
                    Note("Stopped. It starts again at boot,", "or with Start tailscale-nx above.");
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
                } else {
                    OpenCtl();
                    if (g_have_ctl) {
                        SetPhase(Phase::Idle);
                        g_we_started = false;
                    }
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

    // The login link as a QR code (encoded once per link).
    uint8_t g_qr[qrcodegen_BUFFER_LEN_MAX];
    uint8_t g_qr_tmp[qrcodegen_BUFFER_LEN_MAX];
    char g_qr_for[256] = {};
    bool g_qr_ok = false;

    void CtlSetPaused(bool paused) {
        if (!g_have_ctl || g_phase != Phase::Idle) return;
        const u8 v = paused;
        serviceDispatchIn(&g_ctl, 2, v);
    }

    void Refresh() {
        if (g_phase == Phase::Stopping) return;  // the session is busy with Stop
        g_status_ok = CtlGetStatus(&g_status);
        if (g_have_ctl && !g_status_ok) CloseCtl();  // the process went away
        if (g_status_ok && g_status.state == TSNX_CTL_NEEDS_LOGIN) {
            CtlGetString(1, g_login_url, sizeof g_login_url);
        } else {
            g_login_url[0] = 0;
        }
        if (g_status_ok) CtlGetString(3, g_last_error, sizeof g_last_error);
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

    void DrawStatus(tsl::gfx::Renderer *r, s32 x, s32 y, s32 w, s32 h) {
        const char *state = "Not running";
        tsl::Color color = Red;
        if (g_phase == Phase::Stopping || g_phase == Phase::Exiting) {
            r->drawString("Stopping...", false, x + 20, y + 40, 30, r->a(Grey));
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
                case TSNX_CTL_CONNECTING:  state = "Connecting...";        color = Blue;   break;
                case TSNX_CTL_CONNECTED:   state = "Connected";            color = Green;  break;
                case TSNX_CTL_PAUSED:      state = "Paused";               color = Grey;   break;
                case TSNX_CTL_STOPPING:    state = "Stopping...";          color = Grey;   break;
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
                // Two lines at most, broken at a space.
                char first[64], second[96] = "";
                size_t cut = std::strlen(why);
                if (cut > 40) {
                    cut = 40;
                    while (cut > 0 && why[cut] != ' ') cut--;
                    if (cut == 0) cut = 40;
                }
                std::snprintf(first, sizeof first, "%.*s", static_cast<int>(cut), why);
                if (why[cut]) std::snprintf(second, sizeof second, "%s", why + cut + (why[cut] == ' '));
                r->drawString(first, false, x + 20, y + 98, 15, r->a(Grey));
                if (second[0]) r->drawString(second, false, x + 20, y + 116, 15, r->a(Grey));
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
        const u8 *ip = g_status.ipv4;
        if (ip[0]) {
            std::snprintf(line, sizeof line, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
            r->drawString(line, false, x + 20, y + 75, 20, r->a(White));
        }
        const char *region = RegionName(g_status.home_derp);
        char relay[48] = "";
        if (g_status.home_derp) {
            if (region) std::snprintf(relay, sizeof relay, ", relay %s", region);
            else std::snprintf(relay, sizeof relay, ", relay region %u", g_status.home_derp);
        }
        std::snprintf(line, sizeof line, "%u peers%s%s", g_status.peers, relay, (g_status.flags & TSNX_CTL_FLAG_DIRECT) ? ", direct" : "");
        r->drawString(line, false, x + 20, y + 102, 17, r->a(Grey));
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
        if (g_last_error[0] && g_status.state != TSNX_CTL_CONNECTED) {
            ty += 8;
            line("Last error:", Grey);
            r->drawString(g_last_error, false, x + 20, ty, 15, r->a(Grey), w - 40);
        }
    }

    // The outcome of the last stop or start.
    void DrawMessage(tsl::gfx::Renderer *r, s32 x, s32 y, s32 w, s32 h) {
        const tsl::Color c = g_msg_problem ? Red : White;
        r->drawString(g_msg[0], false, x + 20, y + 22, 15, r->a(c));
        r->drawString(g_msg[1], false, x + 20, y + 42, 15, r->a(c));
    }

    void DrawTip(tsl::gfx::Renderer *r, s32 x, s32 y, s32 w, s32 h) {
        r->drawString("Stop ends tailscale-nx until the next boot.", false, x + 20, y + 25, 15, r->a(Grey));
        r->drawString("To keep it off, turn off its boot setting", false, x + 20, y + 47, 15, r->a(Grey));
        r->drawString("in Sysmodules.", false, x + 20, y + 69, 15, r->a(Grey));
    }

    // ---- settings -------------------------------------------------------------

    constexpr const char NoNoticePath[] = "sdmc:/config/tailscale-nx/no-connect-notice";

    bool NoticeOff() {
        bool off = false;
        tsl::hlp::doWithSDCardHandle([&] {
            if (FILE *f = std::fopen(NoNoticePath, "r")) {
                off = true;
                std::fclose(f);
            }
        });
        return off;
    }

    void SetNoticeOff(bool off) {
        tsl::hlp::doWithSDCardHandle([&] {
            if (off) {
                if (FILE *f = std::fopen(NoNoticePath, "w")) std::fclose(f);
            } else {
                std::remove(NoNoticePath);
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
                list->addItem(new tsl::elm::CustomDrawer(DrawStatus), 120);
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
                auto *notice = new tsl::elm::ToggleListItem("Connection notice", !NoticeOff());
                notice->setStateChangedListener([](bool on) { SetNoticeOff(!on); });
                list->addItem(notice);

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
                if (m_toggle && m_toggle->getState() != on) m_toggle->setState(on);
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

    class TailscaleOverlay : public tsl::Overlay {
        public:
            void initServices() override {
                OpenCtl();
            }

            void exitServices() override {
                // A Stop in flight still uses the session; it ends within seconds.
                if (g_phase == Phase::Stopping) {
                    threadWaitForExit(&g_stop_thread);
                    threadClose(&g_stop_thread);
                }
                CloseCtl();
            }

            std::unique_ptr<tsl::Gui> loadInitialGui() override {
                return initially<MainGui>();
            }
    };

}

int main(int argc, char **argv) {
    return tsl::loop<TailscaleOverlay>(argc, argv);
}
