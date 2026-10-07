#include "vsock.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/time.h>

#include <cstring>
#include <vector>

namespace tsnx {

namespace {

// TCP connect timeout when the caller set none (like a typical kernel).
constexpr int kConnectTimeoutMs = 75000;
// Slice for polls that mix real and virtual sockets.
constexpr int kMixedPollSliceMs = 5;

bool ToAddr(const sockaddr *sa, TsnxAddr *out) {
    std::memset(out, 0, sizeof *out);
    if (sa->sa_family == AF_INET) {
        auto *in = reinterpret_cast<const sockaddr_in *>(sa);
        out->family = 4;
        std::memcpy(out->ip, &in->sin_addr, 4);
        out->port = ntohs(in->sin_port);
        return true;
    }
    if (sa->sa_family == AF_INET6) {
        auto *in6 = reinterpret_cast<const sockaddr_in6 *>(sa);
        out->family = 6;
        std::memcpy(out->ip, &in6->sin6_addr, 16);
        out->port = ntohs(in6->sin6_port);
        return true;
    }
    return false;
}

// Writes a TsnxAddr as a sockaddr (in the caller's family where possible).
void FromAddr(const TsnxAddr &a, sockaddr *sa, socklen_t *len) {
    if (!sa || !len) return;
    if (a.family == 4) {
        sockaddr_in in{};
#if defined(__APPLE__) || defined(__SWITCH__)
        in.sin_len = sizeof in;
#endif
        in.sin_family = AF_INET;
        std::memcpy(&in.sin_addr, a.ip, 4);
        in.sin_port = htons(a.port);
        std::memcpy(sa, &in, *len < sizeof in ? *len : sizeof in);
        *len = sizeof in;
    } else {
        sockaddr_in6 in6{};
#if defined(__APPLE__)  // libnx's sockaddr_in6 has no length field
        in6.sin6_len = sizeof in6;
#endif
        in6.sin6_family = AF_INET6;
        std::memcpy(&in6.sin6_addr, a.ip, 16);
        in6.sin6_port = htons(a.port);
        std::memcpy(sa, &in6, *len < sizeof in6 ? *len : sizeof in6);
        *len = sizeof in6;
    }
}

bool IsWildcard(const sockaddr *sa) {
    if (sa->sa_family == AF_INET)
        return reinterpret_cast<const sockaddr_in *>(sa)->sin_addr.s_addr == htonl(INADDR_ANY);
    if (sa->sa_family == AF_INET6) {
        static const in6_addr any{};  // ::
        return std::memcmp(&reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_addr, &any, sizeof any) == 0;
    }
    return false;
}

uint16_t PortOf(const sockaddr *sa) {
    if (sa->sa_family == AF_INET) return ntohs(reinterpret_cast<const sockaddr_in *>(sa)->sin_port);
    if (sa->sa_family == AF_INET6) return ntohs(reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_port);
    return 0;
}

Runtime::Clock::time_point DeadlineFrom(int timeout_ms) {
    return Runtime::Clock::now() + std::chrono::milliseconds(timeout_ms);
}

}  // namespace

bool VSock::IsTailnet(const sockaddr *addr) {
    if (!addr) return false;
    if (addr->sa_family == AF_INET) {
        uint32_t ip = ntohl(reinterpret_cast<const sockaddr_in *>(addr)->sin_addr.s_addr);
        return (ip & 0xffc00000u) == 0x64400000u;  // 100.64.0.0/10
    }
    if (addr->sa_family == AF_INET6) {
        static const uint8_t prefix[6] = {0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0};  // fd7a:115c:a1e0::/48
        return std::memcmp(&reinterpret_cast<const sockaddr_in6 *>(addr)->sin6_addr, prefix, 6) == 0;
    }
    return false;
}

bool VSock::Get(int fd, VFd *out) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = fds_.find(fd);
    if (it == fds_.end()) return false;
    *out = it->second;
    return true;
}

void VSock::Put(int fd, const VFd &v) {
    std::lock_guard<std::mutex> lock(mu_);
    fds_[fd] = v;
}

bool VSock::IsKnown(int fd) {
    std::lock_guard<std::mutex> lock(mu_);
    return fds_.count(fd) != 0;
}

bool VSock::IsVirtual(int fd) {
    VFd v;
    return Get(fd, &v) && (v.tcp || v.listen || v.udp);
}

Result VSock::EngineErr(int32_t code) {
    switch (code) {
        case TSNX_EAGAIN: return Fail(Err::Again);
        case TSNX_ENOTCONN: return Fail(Err::NotConn);
        case TSNX_EBADF: return Fail(Err::BadF);
        case TSNX_EADDRINUSE: return Fail(Err::AddrInUse);
        case TSNX_ECONNREFUSED: return Fail(Err::ConnRefused);
        case TSNX_ECONNRESET: return Fail(Err::ConnReset);
        case TSNX_ENOBUFS: return Fail(Err::NoBufs);
        default: return Fail(Err::Inval);
    }
}

bool VSock::WaitEngine(int32_t id, uint32_t mask, int timeout_ms) {
    auto ready = [&](TsnxEngine *e) { return (tsnx_net_readiness(e, id) & mask) != 0; };
    if (timeout_ms < 0) return WaitSliced(ready, nullptr);
    auto deadline = DeadlineFrom(timeout_ms);
    return WaitSliced(ready, &deadline);
}

bool VSock::WaitSliced(const std::function<bool(TsnxEngine *)> &ready, const Runtime::Clock::time_point *deadline) {
    if (!alive_) return rt_.WaitFor(ready, deadline);
    for (;;) {
        auto slice = Runtime::Clock::now() + std::chrono::seconds(1);
        bool last = deadline && *deadline <= slice;
        if (rt_.WaitFor(ready, last ? deadline : &slice)) return true;
        if (last || !alive_()) return false;
    }
}

void VSock::CloseAll() {
    std::map<int, VFd> all;
    {
        std::lock_guard<std::mutex> lock(mu_);
        all.swap(fds_);
    }
    rt_.With([&](TsnxEngine *e) {
        for (auto &[fd, v] : all) {
            if (v.tcp) tsnx_net_close(e, v.tcp);
            if (v.listen) tsnx_net_close(e, v.listen);
            if (v.udp) tsnx_net_close(e, v.udp);
        }
    });
    rt_.NotifyAll();
}

bool VSock::EnsureUdp(int fd, VFd &v) {
    if (v.udp) return true;
    if (!v.port) {
        // Unbound: bind the real socket to an ephemeral port first so both
        // sides share one port number (replies come back to the same port).
        sockaddr_in any{};
#if defined(__APPLE__) || defined(__SWITCH__)
        any.sin_len = sizeof any;
#endif
        any.sin_family = AF_INET;
        real_.Bind(fd, reinterpret_cast<sockaddr *>(&any), sizeof any);
        sockaddr_storage ss{};
        socklen_t len = sizeof ss;
        if (real_.GetSockName(fd, reinterpret_cast<sockaddr *>(&ss), &len).ret == 0)
            v.port = PortOf(reinterpret_cast<sockaddr *>(&ss));
        v.bound_any = true;
    }
    int32_t id = rt_.With([&](TsnxEngine *e) { return tsnx_net_udp_bind(e, v.port); });
    if (id <= 0) return false;
    v.udp = id;
    Put(fd, v);
    return true;
}

size_t VSock::Tracked() {
    std::lock_guard<std::mutex> lock(mu_);
    return fds_.size();
}

Result VSock::Socket(int domain, int type, int protocol) {
    Result r = real_.Socket(domain, type, protocol);
    int base = type & 0xff;  // strip SOCK_NONBLOCK/SOCK_CLOEXEC-style flags
    if (r.ret >= 0 && (domain == AF_INET || domain == AF_INET6) && (base == SOCK_STREAM || base == SOCK_DGRAM)) {
        VFd v;
        v.type = base;
        v.domain = domain;
#ifdef SOCK_NONBLOCK
        v.nonblock = (type & SOCK_NONBLOCK) != 0;
#endif
        Put(static_cast<int>(r.ret), v);
    }
    return r;
}

Result VSock::Close(int fd) {
    VFd v;
    if (Get(fd, &v)) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            fds_.erase(fd);
        }
        if (v.tcp || v.listen || v.udp) {
            rt_.With([&](TsnxEngine *e) {
                if (v.tcp) tsnx_net_close(e, v.tcp);
                if (v.listen) tsnx_net_close(e, v.listen);
                if (v.udp) tsnx_net_close(e, v.udp);
            });
            rt_.NotifyAll();
        }
    }
    return real_.Close(fd);
}

Result VSock::Connect(int fd, const sockaddr *addr, socklen_t len) {
    VFd v;
    if (!Get(fd, &v) || !IsTailnet(addr)) {
        if (Get(fd, &v)) {
            v.real_used = true;
            Put(fd, v);
        }
        return real_.Connect(fd, addr, len);
    }
    TsnxAddr dst;
    ToAddr(addr, &dst);
    if (v.type == SOCK_DGRAM) {
        if (!EnsureUdp(fd, v)) return Fail(Err::Inval);
        v.udp_peer = dst;
        v.has_udp_peer = true;
        Put(fd, v);
        return Result::Ok(0);
    }
    if (v.tcp) return Fail(v.connecting ? Err::InProgress : Err::IsConn);
    int32_t id = rt_.With([&](TsnxEngine *e) { return tsnx_net_tcp_connect(e, &dst); });
    if (id <= 0) return EngineErr(id);
    v.tcp = id;
    v.virtual_only = true;
    v.connecting = true;
    Put(fd, v);
    if (v.nonblock) return Fail(Err::InProgress);

    int timeout = v.snd_timeout_ms > 0 ? v.snd_timeout_ms : kConnectTimeoutMs;
    bool ok = WaitEngine(id, TSNX_WRITABLE | TSNX_HUP, timeout);
    uint32_t r = rt_.With([&](TsnxEngine *e) { return tsnx_net_readiness(e, id); });
    v.connecting = false;
    if (ok && (r & TSNX_WRITABLE)) {
        v.connected_virtual = true;
        Put(fd, v);
        return Result::Ok(0);
    }
    Put(fd, v);
    return Fail(ok ? Err::ConnRefused : Err::TimedOut);
}

Result VSock::Bind(int fd, const sockaddr *addr, socklen_t len) {
    VFd v;
    if (!Get(fd, &v)) return real_.Bind(fd, addr, len);
    if (IsTailnet(addr)) {
        // Binding to our tailnet address: the real stack doesn't have it.
        v.port = PortOf(addr);
        v.virtual_only = true;
        // Give back socket memory the app reserved for the real side (e.g.
        // SO_SNDBUF set before bind): it will never carry data.
        const int small = 0x800;
        real_.SetSockOpt(fd, SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
        real_.SetSockOpt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
        if (v.port == 0) {
            // Ephemeral (servers like ftpd bind their passive-mode socket this
            // way and ask getsockname for the port): let the real stack pick
            // one, which also keeps it from handing that port out itself.
            sockaddr_storage any{};
            any.ss_family = addr->sa_family;
            const socklen_t any_len = addr->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
            sockaddr_storage ss{};
            socklen_t sl = sizeof ss;
            if (real_.Bind(fd, reinterpret_cast<sockaddr *>(&any), any_len).ret == 0 &&
                real_.GetSockName(fd, reinterpret_cast<sockaddr *>(&ss), &sl).ret == 0)
                v.port = PortOf(reinterpret_cast<sockaddr *>(&ss));
            if (v.port == 0) return Fail(Err::AddrInUse);
        }
    } else {
        Result r = real_.Bind(fd, addr, len);
        if (r.ret < 0) return r;
        v.bound_any = IsWildcard(addr);
        sockaddr_storage ss{};
        socklen_t sl = sizeof ss;
        v.port = real_.GetSockName(fd, reinterpret_cast<sockaddr *>(&ss), &sl).ret == 0
                     ? PortOf(reinterpret_cast<sockaddr *>(&ss))
                     : PortOf(addr);
        if (!v.bound_any) {
            v.real_used = true;  // bound to a specific real address: real only
            Put(fd, v);
            return r;
        }
    }
    // Wildcard- or tailnet-bound datagram sockets receive tailnet traffic too.
    if (v.type == SOCK_DGRAM && (eager_dual_udp_ || v.virtual_only) && !EnsureUdp(fd, v)) return Fail(Err::AddrInUse);
    Put(fd, v);
    return Result::Ok(0);
}

Result VSock::Listen(int fd, int backlog) {
    VFd v;
    if (!Get(fd, &v) || v.type != SOCK_STREAM || (!v.bound_any && !v.virtual_only))
        return real_.Listen(fd, backlog);
    if (!v.virtual_only) {
        Result r = real_.Listen(fd, backlog);
        if (r.ret < 0) return r;
    }
    int32_t id = rt_.With([&](TsnxEngine *e) { return tsnx_net_tcp_listen(e, v.port, backlog > 0 ? backlog : 8); });
    // Dual sockets still listen on the real side if the overlay can't.
    if (id <= 0 && v.virtual_only) return Fail(id == TSNX_ENOBUFS ? Err::NoBufs : Err::AddrInUse);
    if (id > 0) v.listen = id;
    Put(fd, v);
    return Result::Ok(0);
}

Result VSock::Accept(int fd, sockaddr *addr, socklen_t *len) {
    VFd v;
    if (!Get(fd, &v) || !v.listen) return real_.Accept(fd, addr, len);
    for (;;) {
        TsnxAddr peer{};
        int32_t conn = rt_.With([&](TsnxEngine *e) { return tsnx_net_tcp_accept(e, v.listen, &peer); });
        if (conn > 0) {
            // A real placeholder socket gives the connection an fd number.
            Result s = real_.Socket(v.domain, SOCK_STREAM, 0);
            if (s.ret < 0) {
                rt_.With([&](TsnxEngine *e) { tsnx_net_close(e, conn); });
                return s;
            }
            VFd c;
            c.type = SOCK_STREAM;
            c.domain = v.domain;
            c.tcp = conn;
            c.connected_virtual = true;
            c.virtual_only = true;
            Put(static_cast<int>(s.ret), c);
            FromAddr(peer, addr, len);
            return s;
        }
        if (!v.virtual_only) {
            // Real side: non-blocking attempt.
            pollfd p{fd, POLLIN, 0};
            if (real_.Poll(&p, 1, 0).ret > 0) return real_.Accept(fd, addr, len);
        }
        if (v.nonblock) return Fail(Err::Again);
        if (v.virtual_only) {
            if (!WaitEngine(v.listen, TSNX_READABLE, -1)) return Fail(Err::Again);
        } else {
            pollfd p{fd, POLLIN, 0};
            real_.Poll(&p, 1, kMixedPollSliceMs);
        }
        if (!Get(fd, &v)) return Fail(Err::BadF);
    }
}

Result VSock::Send(int fd, const void *buf, size_t len, int flags) {
    VFd v;
    if (!Get(fd, &v) || (!v.tcp && !(v.udp && v.has_udp_peer))) return real_.Send(fd, buf, len, flags);
    if (v.type == SOCK_DGRAM) return SendTo(fd, buf, len, flags, nullptr, 0);
    bool dontwait = v.nonblock || (flags & real_.DontWaitFlag());
    int timeout = v.snd_timeout_ms;
    for (;;) {
        int32_t n = rt_.With([&](TsnxEngine *e) {
            return tsnx_net_send(e, v.tcp, static_cast<const uint8_t *>(buf), len);
        });
        if (n >= 0) return Result::Ok(n);
        if (n != TSNX_EAGAIN || dontwait) return n == TSNX_ENOTCONN ? Fail(Err::Pipe) : EngineErr(n);
        if (!WaitEngine(v.tcp, TSNX_WRITABLE | TSNX_HUP, timeout)) return Fail(Err::Again);
    }
}

Result VSock::SendTo(int fd, const void *buf, size_t len, int flags, const sockaddr *to, socklen_t tolen) {
    VFd v;
    bool known = Get(fd, &v);
    if (!known || v.type != SOCK_DGRAM) {
        if (known && v.tcp) return Send(fd, buf, len, flags);
        return real_.SendTo(fd, buf, len, flags, to, tolen);
    }
    TsnxAddr dst;
    if (to) {
        if (!IsTailnet(to)) {
            v.real_used = true;
            Put(fd, v);
            return real_.SendTo(fd, buf, len, flags, to, tolen);
        }
        ToAddr(to, &dst);
    } else if (v.has_udp_peer) {
        dst = v.udp_peer;
    } else {
        return real_.SendTo(fd, buf, len, flags, to, tolen);
    }
    if (!EnsureUdp(fd, v)) return Fail(Err::Inval);
    int32_t n = rt_.With([&](TsnxEngine *e) {
        return tsnx_net_udp_sendto(e, v.udp, static_cast<const uint8_t *>(buf), len, &dst);
    });
    return n >= 0 ? Result::Ok(n) : EngineErr(n);
}

Result VSock::Recv(int fd, void *buf, size_t len, int flags) {
    VFd v;
    if (!Get(fd, &v) || (!v.tcp && !v.udp)) return real_.Recv(fd, buf, len, flags);
    if (v.type == SOCK_DGRAM) return RecvFrom(fd, buf, len, flags, nullptr, nullptr);
    bool dontwait = v.nonblock || (flags & real_.DontWaitFlag());
    for (;;) {
        int32_t n = rt_.With([&](TsnxEngine *e) { return tsnx_net_recv(e, v.tcp, static_cast<uint8_t *>(buf), len); });
        if (n >= 0) return Result::Ok(n);
        if (n != TSNX_EAGAIN || dontwait) return EngineErr(n);
        if (!WaitEngine(v.tcp, TSNX_READABLE | TSNX_HUP, v.rcv_timeout_ms)) return Fail(Err::Again);
    }
}

Result VSock::RecvFrom(int fd, void *buf, size_t len, int flags, sockaddr *from, socklen_t *fromlen) {
    VFd v;
    if (!Get(fd, &v) || !v.udp) {
        if (Get(fd, &v) && v.tcp) {
            Result r = Recv(fd, buf, len, flags);
            if (r.ret >= 0 && from && fromlen) GetPeerName(fd, from, fromlen);
            return r;
        }
        return real_.RecvFrom(fd, buf, len, flags, from, fromlen);
    }
    bool dontwait = v.nonblock || (flags & real_.DontWaitFlag());
    auto deadline = DeadlineFrom(v.rcv_timeout_ms >= 0 ? v.rcv_timeout_ms : 0);
    for (;;) {
        TsnxAddr src{};
        int32_t n = rt_.With([&](TsnxEngine *e) {
            return tsnx_net_udp_recvfrom(e, v.udp, static_cast<uint8_t *>(buf), len, &src);
        });
        if (n >= 0) {
            FromAddr(src, from, fromlen);
            return Result::Ok(n);
        }
        // Dual socket: the real side may have a datagram too.
        if (!v.virtual_only) {
            Result r = real_.RecvFrom(fd, buf, len, flags | real_.DontWaitFlag(), from, fromlen);
            if (r.ret >= 0) {
                v.real_used = true;
                Put(fd, v);
                return r;
            }
        }
        if (dontwait) return Fail(Err::Again);
        if (v.rcv_timeout_ms >= 0 && Runtime::Clock::now() >= deadline) return Fail(Err::Again);
        pollfd p{fd, POLLIN, 0};
        Result pr = Poll(&p, 1, v.rcv_timeout_ms >= 0 ? v.rcv_timeout_ms : -1);
        if (pr.ret < 0) return pr;
        if (!Get(fd, &v)) return Fail(Err::BadF);
    }
}

// Readiness of a socket's virtual side as poll() revents. Caller holds the
// runtime lock (passes the engine).
static uint32_t EngineRevents(TsnxEngine *e, int32_t tcp, int32_t listen, int32_t udp, bool connecting, short events) {
    uint32_t out = 0;
    auto check = [&](int32_t id) {
        uint32_t r = tsnx_net_readiness(e, id);
        if ((events & POLLIN) && (r & TSNX_READABLE)) out |= POLLIN;
        if ((events & POLLOUT) && (r & TSNX_WRITABLE)) out |= POLLOUT;
        if (r & TSNX_HUP) out |= POLLHUP;
    };
    if (tcp) check(tcp);
    if (listen) check(listen);
    if (udp) {
        uint32_t r = tsnx_net_readiness(e, udp);
        if ((events & POLLIN) && (r & TSNX_READABLE)) out |= POLLIN;
        if (events & POLLOUT) out |= POLLOUT;  // datagrams: always writable
    }
    // A TCP connect that failed reports error+hup, like the kernel.
    if (connecting && (out & POLLHUP) && !(out & POLLOUT)) out |= POLLERR;
    return out;
}

uint32_t VSock::VirtualRevents(const VFd &v, short events) {
    return rt_.With([&](TsnxEngine *e) { return EngineRevents(e, v.tcp, v.listen, v.udp, v.connecting, events); });
}

Result VSock::Poll(pollfd *fds, nfds_t n, int timeout_ms) {
    std::vector<VFd> state(n);
    std::vector<bool> virt(n), real_side(n);
    bool any_virtual = false, any_real = false;
    for (nfds_t i = 0; i < n; i++) {
        bool known = fds[i].fd >= 0 && Get(fds[i].fd, &state[i]);
        virt[i] = known && (state[i].tcp || state[i].listen || state[i].udp);
        // Poll the real side unless the socket only lives in the overlay (or
        // is dual but has never seen real traffic: then polling it would only
        // add latency to the virtual side). A dual listener's real side is
        // always polled: a server only accepts there once poll says it's
        // ready, so it would otherwise never see LAN connections.
        real_side[i] = !virt[i] || (!state[i].virtual_only && (state[i].real_used || state[i].listen));
        any_virtual |= virt[i];
        any_real |= real_side[i] && fds[i].fd >= 0;
    }
    if (!any_virtual) return real_.Poll(fds, n, timeout_ms);

    auto deadline = DeadlineFrom(timeout_ms < 0 ? 0 : timeout_ms);
    std::vector<pollfd> realfds(fds, fds + n);
    for (;;) {
        int ready = 0;
        for (nfds_t i = 0; i < n; i++) {
            fds[i].revents = 0;
            if (virt[i]) fds[i].revents = static_cast<short>(VirtualRevents(state[i], fds[i].events));
        }
        // Real side: a non-blocking check, or a short slice when nothing is
        // ready yet (mixed sets can't sleep on both sides at once).
        int slice = 0;
        bool any_ready = false;
        for (nfds_t i = 0; i < n; i++) any_ready |= fds[i].revents != 0;
        auto now = Runtime::Clock::now();
        int remaining = timeout_ms < 0 ? kMixedPollSliceMs
                                       : static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        if (!any_ready && any_real) slice = remaining > kMixedPollSliceMs ? kMixedPollSliceMs : (remaining > 0 ? remaining : 0);
        if (any_real) {
            for (nfds_t i = 0; i < n; i++) {
                realfds[i] = fds[i];
                realfds[i].fd = real_side[i] ? fds[i].fd : -1;  // poll ignores negative fds
                realfds[i].revents = 0;
            }
            Result r = real_.Poll(realfds.data(), n, slice);
            if (r.ret < 0) return r;
            for (nfds_t i = 0; i < n; i++)
                if (real_side[i]) fds[i].revents = static_cast<short>(fds[i].revents | realfds[i].revents);
        }
        for (nfds_t i = 0; i < n; i++) ready += fds[i].revents != 0;
        if (ready > 0) return Result::Ok(ready);
        if (timeout_ms == 0 || (timeout_ms > 0 && Runtime::Clock::now() >= deadline)) return Result::Ok(0);
        if (!any_real) {
            // Pure overlay: sleep until one of the sockets becomes ready.
            auto any_ready_fn = [&](TsnxEngine *e) {
                for (nfds_t i = 0; i < n; i++) {
                    const VFd &v = state[i];
                    if (virt[i] && EngineRevents(e, v.tcp, v.listen, v.udp, v.connecting, fds[i].events)) return true;
                }
                return false;
            };
            if (!WaitSliced(any_ready_fn, timeout_ms < 0 ? nullptr : &deadline) && alive_ && !alive_())
                return Fail(Err::Again);
        }
    }
}

Result VSock::Shutdown(int fd, int how) {
    VFd v;
    if (!Get(fd, &v) || !v.tcp) return real_.Shutdown(fd, how);
    if (how == SHUT_WR || how == SHUT_RDWR) rt_.With([&](TsnxEngine *e) { tsnx_net_shutdown(e, v.tcp); });
    return Result::Ok(0);
}

Result VSock::GetSockName(int fd, sockaddr *addr, socklen_t *len) {
    VFd v;
    if (!Get(fd, &v) || !(v.tcp || v.virtual_only)) return real_.GetSockName(fd, addr, len);
    // The overlay side: our tailnet address and the overlay port.
    int32_t id = v.tcp ? v.tcp : (v.udp ? v.udp : v.listen);
    TsnxAddr a{};
    if (rt_.With([&](TsnxEngine *e) { return tsnx_net_local_addr(e, id, &a); }) != 0) return Fail(Err::Inval);
    FromAddr(a, addr, len);
    return Result::Ok(0);
}

Result VSock::GetPeerName(int fd, sockaddr *addr, socklen_t *len) {
    VFd v;
    if (!Get(fd, &v) || (!v.tcp && !v.has_udp_peer)) return real_.GetPeerName(fd, addr, len);
    if (v.has_udp_peer) {
        FromAddr(v.udp_peer, addr, len);
        return Result::Ok(0);
    }
    if (!v.tcp) return Fail(Err::NotConn);
    TsnxAddr a{};
    if (rt_.With([&](TsnxEngine *e) { return tsnx_net_peer_addr(e, v.tcp, &a); }) != 0) return Fail(Err::NotConn);
    FromAddr(a, addr, len);
    return Result::Ok(0);
}

Result VSock::GetSockOpt(int fd, int level, int name, void *val, socklen_t *len) {
    VFd v;
    if (Get(fd, &v) && v.tcp && level == SOL_SOCKET && name == SO_ERROR && val && len && *len >= sizeof(int)) {
        // Completion status of a non-blocking virtual connect.
        int err = 0;
        if (v.connecting) {
            uint32_t r = rt_.With([&](TsnxEngine *e) { return tsnx_net_readiness(e, v.tcp); });
            if (r & TSNX_WRITABLE) {
                v.connecting = false;
                v.connected_virtual = true;
                Put(fd, v);
            } else if (r & TSNX_HUP) {
                v.connecting = false;
                Put(fd, v);
                err = real_.Errno(Err::ConnRefused);
            } else {
                err = real_.Errno(Err::InProgress);
            }
        }
        *static_cast<int *>(val) = err;
        *len = sizeof(int);
        return Result::Ok(0);
    }
    return real_.GetSockOpt(fd, level, name, val, len);
}

Result VSock::SetSockOpt(int fd, int level, int name, const void *val, socklen_t len) {
    VFd v;
    if (Get(fd, &v) && level == SOL_SOCKET && (name == SO_RCVTIMEO || name == SO_SNDTIMEO) && val &&
        len >= sizeof(timeval)) {
        auto *tv = static_cast<const timeval *>(val);
        int ms = static_cast<int>(tv->tv_sec * 1000 + tv->tv_usec / 1000);
        if (name == SO_RCVTIMEO) v.rcv_timeout_ms = ms > 0 ? ms : -1;
        else v.snd_timeout_ms = ms > 0 ? ms : -1;
        Put(fd, v);
    }
    // A tailnet-only socket's real side is just a placeholder for its fd
    // number: buffer sizes there would only reserve the app's socket memory
    // (sys-ftpd's pool is small enough that this made its accepts fail).
    if (Get(fd, &v) && v.virtual_only && level == SOL_SOCKET && (name == SO_SNDBUF || name == SO_RCVBUF))
        return Result::Ok(0);
    Result r = real_.SetSockOpt(fd, level, name, val, len);
    // Options the placeholder can't take (e.g. TCP_NODELAY on an unconnected
    // virtual socket) must not fail the caller.
    if (r.ret < 0 && IsVirtual(fd)) return Result::Ok(0);
    return r;
}

Result VSock::Fcntl(int fd, int cmd, int arg) {
    if (cmd == F_SETFL) NoteNonBlocking(fd, (arg & real_.NonBlockFlag()) != 0);
    return real_.Fcntl(fd, cmd, arg);
}

void VSock::NoteNonBlocking(int fd, bool on) {
    VFd v;
    if (Get(fd, &v)) {
        v.nonblock = on;
        Put(fd, v);
    }
}

}  // namespace tsnx
