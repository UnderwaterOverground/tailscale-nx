// See ctl.hpp.
#include <stratosphere.hpp>

#include "ctl.hpp"
#include "log.hpp"
#include "stack_watch.hpp"
#include "status.hpp"

#define TSNX_CTL_INTERFACE_INFO(C, H)                                                                                                    \
    AMS_SF_METHOD_INFO(C, H, 0, Result, GetStatus,    (sf::Out<::TsnxCtlStatus> out),                       (out))                   \
    AMS_SF_METHOD_INFO(C, H, 1, Result, GetLoginUrl,  (const sf::OutBuffer &url, sf::Out<u32> out_len),       (url, out_len))          \
    AMS_SF_METHOD_INFO(C, H, 2, Result, SetPaused,    (bool paused),                                          (paused))                \
    AMS_SF_METHOD_INFO(C, H, 3, Result, GetLastError, (const sf::OutBuffer &msg, sf::Out<u32> out_len),       (msg, out_len))          \
    AMS_SF_METHOD_INFO(C, H, 4, Result, Stop,         (sf::Out<u32> out_code, sf::Out<u32> out_detail),       (out_code, out_detail))

AMS_SF_DEFINE_INTERFACE(ams::ctl, ICtl, TSNX_CTL_INTERFACE_INFO, 0x7473636C)

namespace ams::ctl {

    namespace {

        constinit StopHandler g_stop = nullptr;

    }

    class CtlService {
        public:
            Result GetStatus(sf::Out<::TsnxCtlStatus> out) {
                out.SetValue(status::Get());
                R_SUCCEED();
            }

            Result GetLoginUrl(const sf::OutBuffer &url, sf::Out<u32> out_len) {
                const size_t n = status::GetLoginUrl(reinterpret_cast<char *>(url.GetPointer()), url.GetSize());
                out_len.SetValue(static_cast<u32>(n));
                R_SUCCEED();
            }

            Result SetPaused(bool paused) {
                status::SetPaused(paused);
                R_SUCCEED();
            }

            Result GetLastError(const sf::OutBuffer &msg, sf::Out<u32> out_len) {
                const size_t n = status::GetLastError(reinterpret_cast<char *>(msg.GetPointer()), msg.GetSize());
                out_len.SetValue(static_cast<u32>(n));
                R_SUCCEED();
            }

            Result Stop(sf::Out<u32> out_code, sf::Out<u32> out_detail) {
                u32 detail = 0;
                out_code.SetValue(g_stop ? g_stop(std::addressof(detail)) : static_cast<u32>(TSNX_CTL_STOP_BUSY));
                out_detail.SetValue(detail);
                R_SUCCEED();
            }
    };
    static_assert(IsICtl<CtlService>);

    namespace {

        constexpr sm::ServiceName CtlServiceName = sm::ServiceName::Encode(TSNX_CTL_SERVICE);
        constexpr size_t MaxSessions = 4;

        sf::hipc::ServerManager<1, sf::hipc::DefaultServerManagerOptions, MaxSessions> g_server_manager;
        constinit sf::UnmanagedServiceObject<ICtl, CtlService> g_ctl_object;

        // SetPaused and Stop wait (a few seconds at most) for the engine loop
        // and other threads; nothing deep.
        alignas(os::ThreadStackAlignment) constinit u8 g_thread_stack[0x2000];
        constinit os::ThreadType g_thread;

        void ServerThread(void *) {
            g_server_manager.LoopProcess();
        }

    }

    bool Start(StopHandler stop) {
        g_stop = stop;
        // Started from the overlay right after a stop, sm may not yet have
        // dropped the old process's registration: retry for a moment.
        Result rc = ResultSuccess();
        for (int i = 0; i < 30; i++) {
            rc = g_server_manager.RegisterObjectForServer(g_ctl_object.GetShared(), CtlServiceName, MaxSessions);
            if (!sm::ResultAlreadyRegistered::Includes(rc)) break;
            os::SleepThread(TimeSpan::FromMilliSeconds(100));
        }
        if (R_FAILED(rc)) {
            Log("ctl: registering %s failed: 0x%x", TSNX_CTL_SERVICE, rc.GetValue());
            return false;
        }
        stack_watch::Paint(g_thread_stack, sizeof g_thread_stack);
        if (R_FAILED(os::CreateThread(std::addressof(g_thread), ServerThread, nullptr, g_thread_stack, sizeof g_thread_stack,
                                      os::GetThreadCurrentPriority(os::GetCurrentThread())))) {
            Log("ctl: cannot create thread");
            return false;
        }
        os::SetThreadNamePointer(std::addressof(g_thread), "tsnx.Ctl");
        stack_watch::Add("ctl", std::addressof(g_thread));
        os::StartThread(std::addressof(g_thread));
        return true;
    }

}
