// Runs a tsnx engine on its own thread and lets other threads use it.
//
// The engine and driver are not thread-safe; everything goes through one
// mutex, which the engine thread drops only while blocked in poll(). Callers
// that change engine state (overlay socket calls) get their I/O performed
// immediately and wake the engine thread so new sockets join its poll set.
// Threads waiting for socket readiness block on a condition variable that
// is signalled whenever the engine processed input.
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "tsnx.h"
#include "tsnx_driver.h"

namespace tsnx {

struct RuntimeConfig {
    std::string control_url;
    std::string auth_key;
    std::string hostname = "tailscale-nx";
    std::string state_path;
    std::string extra_root_path;  // optional DER root certificate
    std::string connect_map;      // optional dev address rewrites
    uint16_t udp_port = 0;
    // Called on the engine thread with the lock held; must not call back in.
    std::function<void(const TsnxEvent &)> on_event;
};

class Runtime {
public:
    using Clock = std::chrono::steady_clock;

#ifndef TSNX_NO_STDIO
    static std::unique_ptr<Runtime> Start(RuntimeConfig cfg, std::string *error);
#endif
    // Wraps an engine/driver the caller set up (and keeps owning); the
    // caller then runs Run() on a thread of its own. Events go to the
    // callback the caller gave tsnx_driver_new.
    static std::unique_ptr<Runtime> Adopt(TsnxEngine *engine, TsnxDriver *driver, std::string *error);
    // The engine loop, for Adopt()ed runtimes. on_tick runs at least once a
    // second with the lock held (it may use the driver). Returns after Stop().
    void Run(const std::function<void(TsnxDriver *)> &on_tick);
    void Stop();

    // Suspend() has the loop close every socket the engine and the runtime
    // own and idle without network I/O until Resume(). Independent reasons
    // (sleep, a user pause, ...) stack: I/O resumes once none is left.
    // Suspend returns once the sockets are closed (false: timed out).
    enum SuspendReason : uint32_t { kSleep = 1, kPaused = 2 };
    bool Suspend(SuspendReason why, std::chrono::milliseconds timeout);
    void Resume(SuspendReason why);
    // Before Run(): start suspended (no waiting; the loop honours it first).
    void StartSuspended(SuspendReason why) { suspend_reasons_ |= why; }
    // Suspend without taking the lock or touching the network (no wake-up
    // datagram): the loop picks it up within its poll interval (<= 1 s), and
    // IsSuspended() turns true once every socket is closed. For callers that
    // must not stall on the socket service, e.g. a sleep notification.
    void RequestSuspend(SuspendReason why) { async_suspend_.fetch_or(why); }
    bool IsSuspended() const { return suspended_flag_.load(); }
    // Run on the engine thread right after suspending / before resuming,
    // e.g. to close and reopen sockets the embedder owns.
    void SetSuspendHooks(std::function<void()> on_suspend, std::function<void()> on_resume) {
        on_suspend_ = std::move(on_suspend);
        on_resume_ = std::move(on_resume);
    }
    ~Runtime();
    Runtime(const Runtime &) = delete;
    Runtime &operator=(const Runtime &) = delete;

    // Runs f(engine) with exclusive access, then performs the I/O it queued.
    template <class F>
    auto With(F &&f) -> decltype(f(static_cast<TsnxEngine *>(nullptr))) {
        std::unique_lock<std::mutex> lock(mu_);
        InternalScope internal;
        if constexpr (std::is_void_v<decltype(f(engine_))>) {
            f(engine_);
            AfterCall();
        } else {
            auto r = f(engine_);
            AfterCall();
            return r;
        }
    }

    // Blocks until ready(engine) returns true or the deadline passes
    // (nullptr = no deadline). Returns ready()'s final value.
    bool WaitFor(const std::function<bool(TsnxEngine *)> &ready, const Clock::time_point *deadline);

    // Wakes all waiters (e.g. a socket was closed under them).
    void NotifyAll() { cv_.notify_all(); }

    // True while the current thread is executing engine/driver code (its own
    // sockets). Interposition layers must pass such calls straight through.
    static bool InInternal() { return internal_depth_ > 0; }

private:
    Runtime() = default;
    void Loop(const std::function<void(TsnxDriver *)> *on_tick);
    void AfterCall();
    void Wake();

    struct InternalScope {
        InternalScope() { internal_depth_++; }
        ~InternalScope() { internal_depth_--; }
    };
    static thread_local int internal_depth_;

    RuntimeConfig cfg_;
    std::mutex mu_;
    std::condition_variable cv_;
    TsnxEngine *engine_ = nullptr;
    TsnxDriver *driver_ = nullptr;
    bool owned_ = true;  // engine/driver freed by the destructor
    std::thread thread_;
    bool stop_ = false;
    uint32_t suspend_reasons_ = 0;
    std::atomic<uint32_t> async_suspend_{0};
    std::atomic<bool> suspended_flag_{false};
    std::function<void()> on_suspend_, on_resume_;
    bool suspended_ = false;
    int wake_rx_ = -1, wake_tx_ = -1;
};

}  // namespace tsnx
