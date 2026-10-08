// Tests for the socket layer's subnet-route check (make routes-test).
#include <arpa/inet.h>
#include <cassert>
#include <cstdio>
#include <cstring>

#include "vsock.hpp"

using tsnx::VSock;

static bool Routed(const char *ip) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &a.sin_addr);
    return VSock::IsTailnet(reinterpret_cast<sockaddr *>(&a));
}

static TsnxPrefix V4(const char *ip, uint8_t len) {
    TsnxPrefix p{};
    p.family = 4;
    p.len = len;
    inet_pton(AF_INET, ip, p.ip);
    return p;
}

int main() {
    assert(Routed("100.100.1.2") && !Routed("192.168.1.10"));
    const TsnxPrefix routes[] = {V4("192.168.1.0", 24), V4("10.0.0.0", 8), V4("172.16.5.0", 24)};
    VSock::SetRoutes(routes, 3);
    assert(Routed("192.168.1.10") && Routed("10.200.0.1") && Routed("172.16.5.9"));
    assert(!Routed("192.168.2.1") && !Routed("172.16.6.1"));
    // At home on 192.168.1.0/24: that route stays local, the others don't.
    VSock::SetLocalNet(ntohl(inet_addr("192.168.1.50")), 24);
    assert(!Routed("192.168.1.10") && Routed("10.200.0.1"));
    // On 10.5.0.0/16 (inside the 10/8 route): the whole overlapping route stays local.
    VSock::SetLocalNet(ntohl(inet_addr("10.5.3.3")), 16);
    assert(Routed("192.168.1.10") && !Routed("10.200.0.1"));
    // On 172.16.0.0/16 (containing the 172.16.5/24 route).
    VSock::SetLocalNet(ntohl(inet_addr("172.16.9.9")), 16);
    assert(!Routed("172.16.5.9"));
    // Offline: every route is used.
    VSock::SetLocalNet(0, 32);
    assert(Routed("192.168.1.10") && Routed("172.16.5.9"));
    VSock::SetRoutes(nullptr, 0);
    assert(!Routed("192.168.1.10") && Routed("100.64.0.1"));
    std::puts("routes-test: ok");
}
