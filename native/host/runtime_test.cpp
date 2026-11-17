// Tests for the runtime's non-blocking pause, RequestSuspended, and sockets
// the system drops (make runtime-test).
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cassert>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <thread>
#include <vector>

#include "runtime.hpp"

extern "C" void tsnx_platform_random(uint8_t *buf, size_t len);

using tsnx::Runtime;

static bool WaitSuspended(Runtime &rt, bool want) {
    for (int i = 0; i < 30; i++) {
        if (rt.IsSuspended() == want) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

template <class F>
static bool Eventually(F &&f, std::chrono::milliseconds limit) {
    const auto end = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < end) {
        if (f()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return f();
}

// The datagram socket bound to `port`, or -1.
static int FindUdpOnPort(uint16_t port) {
    for (int fd = 3; fd < 256; fd++) {
        sockaddr_in a{};
        socklen_t len = sizeof a;
        int type = 0;
        socklen_t tlen = sizeof type;
        if (getsockname(fd, reinterpret_cast<sockaddr *>(&a), &len) == 0 && a.sin_family == AF_INET && ntohs(a.sin_port) == port &&
            getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tlen) == 0 && type == SOCK_DGRAM)
            return fd;
    }
    return -1;
}

// The runtime's wake pair: the loopback socket another one is connected to.
// Returns its receiving end, or -1.
static int FindWakeRx() {
    for (int fd = 3; fd < 256; fd++) {
        sockaddr_in peer{};
        socklen_t len = sizeof peer;
        if (getpeername(fd, reinterpret_cast<sockaddr *>(&peer), &len) != 0 || peer.sin_family != AF_INET ||
            peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
            continue;
        for (int rx = 3; rx < 256; rx++) {
            sockaddr_in local{};
            len = sizeof local;
            if (rx != fd && getsockname(rx, reinterpret_cast<sockaddr *>(&local), &len) == 0 && local.sin_family == AF_INET &&
                local.sin_addr.s_addr == peer.sin_addr.s_addr && local.sin_port == peer.sin_port)
                return rx;
        }
    }
    return -1;
}

int main() {
    uint8_t seed[32], machine[32], node[32], disco[32];
    for (uint8_t *k : {seed, machine, node, disco}) tsnx_platform_random(k, 32);
    tsnx_seed_rng(seed);
    // Nothing listens there: the engine just keeps retrying.
    TsnxConfig cfg = {};
    cfg.control_url = "https://127.0.0.1:9";
    cfg.hostname = "runtime-test";
    cfg.machine_key = machine;
    cfg.node_key = node;
    cfg.disco_key = disco;
    TsnxEngine *engine = tsnx_engine_new(&cfg, tsnx_driver_now_ns(), static_cast<uint64_t>(time(nullptr)));
    TsnxDriver *driver = tsnx_driver_new(engine, nullptr, nullptr);
    // The tests below close sockets under the loop, as the system does. So
    // that a new socket (the engine dialling) doesn't reuse a closed one's
    // number meanwhile, the UDP socket and the wake pair get numbers above
    // some free ones.
    std::vector<int> spacers;
    for (int i = 0; i < 8; i++) spacers.push_back(socket(AF_INET, SOCK_DGRAM, 0));
    assert(tsnx_driver_open_udp(driver, 0) == 0);
    const uint16_t port = tsnx_driver_udp_port(driver);
    std::string error;
    auto rt = Runtime::Adopt(engine, driver, &error);
    assert(rt);
    for (int fd : spacers) close(fd);
    std::thread loop([&] { rt->Run([](TsnxDriver *) {}); });
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // ---- the system drops the UDP socket (Airplane Mode on the console) ----
    // poll() then reports it invalid at once: the loop must not spin on it,
    // and must open another on the same port, once a second at most.
    {
        const auto reopens = [&] { return rt->Read([&](TsnxEngine *) { return tsnx_driver_udp_reopens(driver); }); };
        const auto udp_port = [&] { return rt->Read([&](TsnxEngine *) { return tsnx_driver_udp_port(driver); }); };
        int fd = FindUdpOnPort(port);
        assert(fd >= 0);
        uint64_t rounds = rt->Rounds();
        close(fd);
        assert(Eventually([&] { return reopens() == 1; }, std::chrono::milliseconds(3000)));
        const auto first = std::chrono::steady_clock::now();
        assert(udp_port() == port && FindUdpOnPort(port) >= 0);
        assert(rt->Rounds() - rounds < 100);
        // Dropped again at once: the next one waits out the second.
        fd = FindUdpOnPort(port);
        rounds = rt->Rounds();
        close(fd);
        assert(Eventually([&] { return reopens() == 2; }, std::chrono::milliseconds(3000)));
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - first).count();
        assert(ms >= 900);
        assert(udp_port() == port && FindUdpOnPort(port) >= 0);
        // An idle loop: a few rounds a second, not thousands.
        assert(rt->Rounds() - rounds < 100);
        std::printf("ok: a dropped UDP socket is reopened on the same port (again after %lld ms), %llu rounds meanwhile\n",
                    static_cast<long long>(ms), static_cast<unsigned long long>(rt->Rounds() - rounds));
        // Ready round after round with nothing to read and no error (Airplane
        // Mode did this for ~6 s on the console): a UDP socket shut for
        // reading stands in, always readable and every read empty.
        fd = FindUdpOnPort(port);
        rounds = rt->Rounds();
        {
            const int empty = socket(AF_INET, SOCK_DGRAM, 0);
            sockaddr_in to{};
            to.sin_family = AF_INET;
            to.sin_port = htons(9);
            to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            assert(empty >= 0 && connect(empty, reinterpret_cast<sockaddr *>(&to), sizeof to) == 0 && shutdown(empty, SHUT_RD) == 0);
            assert(dup2(empty, fd) == fd);
            close(empty);
        }
        assert(Eventually([&] { return reopens() == 3; }, std::chrono::milliseconds(3000)));
        assert(udp_port() == port && FindUdpOnPort(port) >= 0);
        const uint64_t empty_rounds = rt->Rounds() - rounds;
        assert(empty_rounds < 300);  // 64 to notice, then an idle wait for the reopen
        std::printf("ok: a socket that is always ready with nothing to read is reopened, %llu rounds meanwhile\n",
                    static_cast<unsigned long long>(empty_rounds));
    }

    // ---- the system drops the wake pair ------------------------------------
    {
        const int rx = FindWakeRx();
        assert(rx >= 0);
        const uint64_t remakes = rt->WakeRemakes(), rounds = rt->Rounds();
        close(rx);  // the loop's next poll() finds it invalid
        assert(Eventually([&] { return rt->WakeRemakes() == remakes + 1; }, std::chrono::milliseconds(3000)));
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        assert(rt->Rounds() - rounds < 100);
        assert(FindWakeRx() >= 0);
        // Wake-ups work again: a suspend is answered long before the loop's
        // one-second poll would have ended.
        const auto t0 = std::chrono::steady_clock::now();
        assert(rt->Suspend(Runtime::kPaused, std::chrono::milliseconds(2000)));
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        assert(ms < 300);
        rt->Resume(Runtime::kPaused);
        assert(WaitSuspended(*rt, false));
        std::printf("ok: a dropped wake pair is remade (%llu rounds meanwhile); a wake-up then took %lld ms\n",
                    static_cast<unsigned long long>(rt->Rounds() - rounds), static_cast<long long>(ms));
    }

    rt->RequestSuspended(Runtime::kPaused, true);
    assert(WaitSuspended(*rt, true));
    rt->RequestSuspended(Runtime::kPaused, false);
    assert(WaitSuspended(*rt, false));

    // The latest request wins, however quickly they follow each other.
    rt->RequestSuspended(Runtime::kPaused, true);
    rt->RequestSuspended(Runtime::kPaused, false);
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    assert(!rt->IsSuspended());
    rt->RequestSuspended(Runtime::kPaused, false);
    rt->RequestSuspended(Runtime::kPaused, true);
    assert(WaitSuspended(*rt, true));

    // Reasons stack: resuming the pause during a sleep stays suspended
    // until the wake.
    rt->RequestSuspend(Runtime::kSleep);
    rt->RequestSuspended(Runtime::kPaused, false);
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    assert(rt->IsSuspended());
    rt->Resume(Runtime::kSleep);
    assert(WaitSuspended(*rt, false));

    rt->Stop();
    loop.join();
    rt.reset();
    tsnx_driver_free(driver);
    tsnx_engine_free(engine);
    std::puts("runtime tests passed");
    return 0;
}
