// Tests for the runtime's non-blocking pause, RequestSuspended (make runtime-test).
#include <cassert>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <thread>

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
    std::string error;
    auto rt = Runtime::Adopt(engine, driver, &error);
    assert(rt);
    std::thread loop([&] { rt->Run([](TsnxDriver *) {}); });

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
