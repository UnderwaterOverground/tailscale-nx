// Tailscale overlay: status, on/off and login (QR code) for the tailscale-nx
// sysmodule, through its tsnx:ctl service (native/ctl/tsnx_ctl.h).
#define TESLA_INIT_IMPL
#include <tesla.hpp>

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
        return R_SUCCEEDED(tipcDispatchInOut(smGetServiceSessionTipc(), 65100, sn, has)) && (has & 1);
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

    void CtlSetPaused(bool paused) {
        if (!g_have_ctl) return;
        const u8 v = paused;
        serviceDispatchIn(&g_ctl, 2, v);
    }

    // ---- state shared with the drawers -------------------------------------

    TsnxCtlStatus g_status = {};
    bool g_status_ok = false;

    // Why the sysmodule isn't running, read from the SD card when the overlay
    // opens (the crash guard's file, or a missing boot flag).
    constexpr const char CrashedPath[] = "sdmc:/config/tailscale-nx/crashed";
    constexpr const char Boot2Path[] = "sdmc:/atmosphere/contents/4200000000005453/flags/boot2.flag";
    char g_crashed[160] = {};   // first line of the crash guard's reason
    bool g_no_boot_flag = false;
    bool g_turned_back_on = false;

    void ReadWhyNotRunning() {
        tsl::hlp::doWithSDCardHandle([] {
            g_crashed[0] = 0;
            if (FILE *f = std::fopen(CrashedPath, "r")) {
                if (!std::fgets(g_crashed, sizeof g_crashed, f) || !g_crashed[0]) std::snprintf(g_crashed, sizeof g_crashed, "repeated failures");
                g_crashed[std::strcspn(g_crashed, "\r\n")] = 0;
                std::fclose(f);
            }
            FILE *b = std::fopen(Boot2Path, "r");
            g_no_boot_flag = b == nullptr;
            if (b) std::fclose(b);
        });
    }

    // Clears the crash guard so the next boot starts tailscale-nx again.
    void TurnBackOn() {
        tsl::hlp::doWithSDCardHandle([] {
            for (const char *p : {CrashedPath, "sdmc:/config/tailscale-nx/starting", "sdmc:/config/tailscale-nx/sleep_failures",
                                  "sdmc:/config/tailscale-nx/sleeping"}) {
                std::remove(p);
            }
        });
        g_crashed[0] = 0;
        g_turned_back_on = true;
    }
    char g_login_url[256] = {};
    char g_last_error[192] = {};

    // The login link as a QR code (encoded once per link).
    uint8_t g_qr[qrcodegen_BUFFER_LEN_MAX];
    uint8_t g_qr_tmp[qrcodegen_BUFFER_LEN_MAX];
    char g_qr_for[256] = {};
    bool g_qr_ok = false;

    void Refresh() {
        g_status_ok = CtlGetStatus(&g_status);
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
        if (g_status_ok) {
            switch (g_status.state) {
                case TSNX_CTL_STARTING:    state = "Starting...";          color = Blue;   break;
                case TSNX_CTL_NEEDS_LOGIN: state = "Log in needed";        color = Yellow; break;
                case TSNX_CTL_CONNECTING:  state = "Connecting...";        color = Blue;   break;
                case TSNX_CTL_CONNECTED:   state = "Connected";            color = Green;  break;
                case TSNX_CTL_PAUSED:      state = "Paused";               color = Grey;   break;
            }
        }
        r->drawString(state, false, x + 20, y + 40, 30, r->a(color));
        char line[128];
        if (!g_status_ok) {
            if (g_turned_back_on) {
                r->drawString("Turned back on. Restart the console", false, x + 20, y + 75, 17, r->a(White));
                r->drawString("to start tailscale-nx.", false, x + 20, y + 100, 17, r->a(White));
            } else if (g_crashed[0]) {
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
            } else if (g_no_boot_flag) {
                r->drawString("The tailscale-nx sysmodule isn't running.", false, x + 20, y + 75, 17, r->a(Grey));
                r->drawString("Turn on its boot setting in Sysmodules, then restart.", false, x + 20, y + 100, 17, r->a(Grey));
            } else {
                r->drawString("The tailscale-nx sysmodule isn't running.", false, x + 20, y + 75, 17, r->a(Grey));
                r->drawString("Restart the console to start it.", false, x + 20, y + 100, 17, r->a(Grey));
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
        if (g_last_error[0] && g_status.state != TSNX_CTL_CONNECTED) {
            ty += 8;
            line("Last error:", Grey);
            r->drawString(g_last_error, false, x + 20, ty, 15, r->a(Grey), w - 40);
        }
    }

    void DrawTip(tsl::gfx::Renderer *r, s32 x, s32 y, s32 w, s32 h) {
        r->drawString("Don't want Tailscale or its login prompts?", false, x + 20, y + 25, 15, r->a(Grey));
        r->drawString("Turn off tailscale-nx's boot setting in Sysmodules.", false, x + 20, y + 47, 15, r->a(Grey));
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
                if (!g_status_ok && g_crashed[0]) {
                    auto *again = new tsl::elm::ListItem("Turn back on");
                    again->setClickListener([](u64 keys) {
                        if (!(keys & HidNpadButton_A)) return false;
                        TurnBackOn();
                        return true;
                    });
                    list->addItem(again);
                }

                m_toggle = new tsl::elm::ToggleListItem("Tailscale", !(g_status_ok && g_status.state == TSNX_CTL_PAUSED));
                m_toggle->setStateChangedListener([](bool on) {
                    CtlSetPaused(!on);
                    Refresh();
                });
                list->addItem(m_toggle);

                // The sysmodule's "Connected. IP: ..." toast at boot; off is
                // a marker file it checks when it connects.
                auto *notice = new tsl::elm::ToggleListItem("Notice when connected", !NoticeOff());
                notice->setStateChangedListener([](bool on) { SetNoticeOff(!on); });
                list->addItem(notice);

                list->addItem(new tsl::elm::CustomDrawer(DrawLogin), 330);
                list->addItem(new tsl::elm::CustomDrawer(DrawTip), 60);
                frame->setContent(list);
                return frame;
            }

            void update() override {
                // Poll about twice a second.
                if (++m_frames % 30 != 0) return;
                Refresh();
                const bool on = !(g_status_ok && g_status.state == TSNX_CTL_PAUSED);
                if (m_toggle && m_toggle->getState() != on) m_toggle->setState(on);
            }

        private:
            tsl::elm::ToggleListItem *m_toggle = nullptr;
            u32 m_frames = 0;
    };

    class TailscaleOverlay : public tsl::Overlay {
        public:
            void initServices() override {
                g_have_ctl = ServiceExists(TSNX_CTL_SERVICE) && R_SUCCEEDED(smGetService(&g_ctl, TSNX_CTL_SERVICE));
            }

            void exitServices() override {
                if (g_have_ctl) serviceClose(&g_ctl);
            }

            std::unique_ptr<tsl::Gui> loadInitialGui() override {
                return initially<MainGui>();
            }
    };

}

int main(int argc, char **argv) {
    return tsl::loop<TailscaleOverlay>(argc, argv);
}
