#include "runtime.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <ctime>
#include <vector>

#include "tsnx_app.h"

namespace tsnx {

thread_local int Runtime::internal_depth_ = 0;

namespace {

#ifndef TSNX_NO_STDIO
std::vector<uint8_t> ReadFile(const std::string &path) {
    std::vector<uint8_t> out;
    FILE *f = std::fopen(path.c_str(), "rb");
    if (!f) return out;
    uint8_t buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.insert(out.end(), buf, buf + n);
    std::fclose(f);
    return out;
}
#endif

// A loopback UDP pair used to interrupt the engine thread's poll().
bool MakeWakePair(int *rx, int *tx) {
    *rx = socket(AF_INET, SOCK_DGRAM, 0);
    *tx = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof a;
    if (*rx < 0 || *tx < 0 || bind(*rx, reinterpret_cast<sockaddr *>(&a), sizeof a) != 0 ||
        getsockname(*rx, reinterpret_cast<sockaddr *>(&a), &len) != 0 ||
        connect(*tx, reinterpret_cast<sockaddr *>(&a), sizeof a) != 0) {
        if (*rx >= 0) close(*rx);
        if (*tx >= 0) close(*tx);
        *rx = *tx = -1;
        return false;
    }
    fcntl(*rx, F_SETFL, fcntl(*rx, F_GETFL, 0) | O_NONBLOCK);
    fcntl(*tx, F_SETFL, fcntl(*tx, F_GETFL, 0) | O_NONBLOCK);
    return true;
}

}  // namespace

#ifndef TSNX_NO_STDIO  // reads state/root files with stdio; embedders without it use Adopt()
std::unique_ptr<Runtime> Runtime::Start(RuntimeConfig cfg, std::string *error) {
    InternalScope internal;
    std::unique_ptr<Runtime> rt(new Runtime());
    rt->cfg_ = std::move(cfg);
    const RuntimeConfig &c = rt->cfg_;

    uint8_t seed[32];
    tsnx_platform_random(seed, sizeof seed);
    tsnx_seed_rng(seed);
    uint8_t machine[32], node[32], disco[32];
    if (tsnx_state_load_or_create(c.state_path.c_str(), machine, node, disco) != 0) {
        *error = "cannot read/write state " + c.state_path;
        return nullptr;
    }
    std::vector<uint8_t> root;
    if (!c.extra_root_path.empty() && (root = ReadFile(c.extra_root_path)).empty()) {
        *error = "cannot read " + c.extra_root_path;
        return nullptr;
    }
    TsnxConfig ec{};
    ec.control_url = c.control_url.c_str();
    ec.auth_key = c.auth_key.empty() ? nullptr : c.auth_key.c_str();
    ec.hostname = c.hostname.c_str();
    ec.machine_key = machine;
    ec.node_key = node;
    ec.disco_key = disco;
    ec.extra_root_der = root.empty() ? nullptr : root.data();
    ec.extra_root_len = root.size();
    bool corrected = false;
    uint64_t unix_time = tsnx_sane_unix_time(static_cast<uint64_t>(std::time(nullptr)), c.control_url.c_str(), &corrected);
    if (unix_time == 0) unix_time = static_cast<uint64_t>(std::time(nullptr));
    rt->engine_ = tsnx_engine_new(&ec, tsnx_driver_now_ns(), unix_time);
    if (!rt->engine_) {
        *error = "tsnx_engine_new failed (bad control URL?)";
        return nullptr;
    }
    Runtime *self = rt.get();
    rt->driver_ = tsnx_driver_new(
        rt->engine_,
        [](void *ctx, const TsnxEvent *ev) {
            auto *r = static_cast<Runtime *>(ctx);
            if (ev->kind == TSNX_EVENT_NODE_KEY) {
                uint8_t node[32];
                tsnx_engine_node_key(r->engine_, node);
                tsnx_state_set_node(r->cfg_.state_path.c_str(), node);
            }
            if (r->cfg_.on_event) r->cfg_.on_event(*ev);
        },
        self);
    if (!c.connect_map.empty()) tsnx_driver_set_connect_map(rt->driver_, c.connect_map.c_str());
    tsnx_driver_open_udp(rt->driver_, c.udp_port);  // failure: DERP only
    if (!MakeWakePair(&rt->wake_rx_, &rt->wake_tx_)) {
        *error = "cannot create wake sockets";
        return nullptr;
    }
    rt->thread_ = std::thread([self] { self->Loop(nullptr); });
    return rt;
}
#endif

std::unique_ptr<Runtime> Runtime::Adopt(TsnxEngine *engine, TsnxDriver *driver, std::string *error) {
    std::unique_ptr<Runtime> rt(new Runtime());
    rt->engine_ = engine;
    rt->driver_ = driver;
    rt->owned_ = false;
    if (!MakeWakePair(&rt->wake_rx_, &rt->wake_tx_)) {
        *error = "cannot create wake sockets";
        return nullptr;
    }
    return rt;
}

void Runtime::Run(const std::function<void(TsnxDriver *)> &on_tick) { Loop(&on_tick); }

void Runtime::Stop() {
    {
        std::lock_guard<std::mutex> lock(mu_);
        stop_ = true;
    }
    Wake();
    cv_.notify_all();
}

Runtime::~Runtime() {
    Stop();
    if (thread_.joinable()) thread_.join();
    if (owned_) {
        tsnx_driver_free(driver_);
        tsnx_engine_free(engine_);
    }
    if (wake_rx_ >= 0) close(wake_rx_);
    if (wake_tx_ >= 0) close(wake_tx_);
}

void Runtime::Wake() {
    if (wake_tx_ < 0) return;
    char b = 0;
    send(wake_tx_, &b, 1, 0);
}

void Runtime::AfterCall() {
    if (suspended_) return;  // I/O resumes (and gets pumped) on Resume()
    tsnx_driver_pump(driver_);
    Wake();
}

bool Runtime::Suspend(SuspendReason why, std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mu_);
    suspend_reasons_ |= why;
    Wake();
    return cv_.wait_for(lock, timeout, [&] { return suspended_ || stop_; });
}

void Runtime::Resume(SuspendReason why) {
    std::lock_guard<std::mutex> lock(mu_);
    async_suspend_.fetch_and(~static_cast<uint32_t>(why));
    suspend_reasons_ &= ~static_cast<uint32_t>(why);
    cv_.notify_all();
}

bool Runtime::WaitFor(const std::function<bool(TsnxEngine *)> &ready, const Clock::time_point *deadline) {
    std::unique_lock<std::mutex> lock(mu_);
    for (;;) {
        if (ready(engine_)) return true;
        if (stop_) return false;
        if (deadline) {
            if (cv_.wait_until(lock, *deadline) == std::cv_status::timeout) return ready(engine_);
        } else {
            cv_.wait(lock);
        }
    }
}

void Runtime::Loop(const std::function<void(TsnxDriver *)> *on_tick) {
    InternalScope internal;  // this thread only ever does engine work
    pollfd fds[TSNX_DRIVER_MAX_FDS + 1];
    std::unique_lock<std::mutex> lock(mu_);
    while (!stop_) {
        suspend_reasons_ |= async_suspend_.exchange(0);
        if (suspend_reasons_ != 0) {
            tsnx_driver_suspend(driver_);
            close(wake_rx_);
            close(wake_tx_);
            wake_rx_ = wake_tx_ = -1;
            if (on_suspend_) on_suspend_();
            suspended_ = true;
            suspended_flag_ = true;
            cv_.notify_all();
            cv_.wait(lock, [&] { return suspend_reasons_ == 0 || stop_; });
            // Without a wake pair the loop still runs, just with up to a
            // second of latency for new overlay sockets.
            if (on_resume_) on_resume_();
            MakeWakePair(&wake_rx_, &wake_tx_);
            tsnx_driver_resume(driver_);
            suspended_ = false;
            suspended_flag_ = false;
            cv_.notify_all();
            continue;
        }
        if (on_tick && *on_tick) (*on_tick)(driver_);
        int wait = 0;
        int n = tsnx_driver_prepare(driver_, fds, TSNX_DRIVER_MAX_FDS, 1000, &wait);
        fds[n].fd = wake_rx_;
        fds[n].events = POLLIN;
        fds[n].revents = 0;
        const int nfds = n + (wake_rx_ >= 0 ? 1 : 0);
        lock.unlock();
        int rc = poll(fds, static_cast<nfds_t>(nfds), wait);
        lock.lock();
        if (wake_rx_ >= 0 && (fds[n].revents & POLLIN)) {
            char buf[64];
            while (recv(wake_rx_, buf, sizeof buf, 0) > 0) {
            }
        }
        if (rc > 0) tsnx_driver_dispatch(driver_, fds);
        // Socket readiness may have changed; let waiters re-check.
        cv_.notify_all();
    }
}

}  // namespace tsnx
