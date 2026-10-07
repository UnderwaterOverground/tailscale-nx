// Socket virtualization: the decision layer between an application's BSD
// socket calls and either the real network stack or the tailnet overlay.
//
// Every socket is created for real, so fd numbers stay unique and plain
// traffic is untouched. A socket becomes (partly) virtual when it is
// connected/sent to a tailnet address (100.64.0.0/10, fd7a:115c:a1e0::/48),
// bound to a tailnet address, or bound to the wildcard address (then it is
// reachable from both sides: a "dual" socket). Virtual traffic goes through
// the tsnx engine's overlay sockets.
//
// The same code serves the macOS/Linux interpose shim (tests on the dev
// machine) and the Switch bsd:u MITM; `Backend` abstracts the real stack and
// errno numbering, which differ between them.
#pragma once

#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>

#include "runtime.hpp"

namespace tsnx {

// Outcome of a socket call: `ret` as the call would return, `err` an errno
// value in the backend's numbering when ret < 0.
struct Result {
    int64_t ret;
    int err;
    static Result Ok(int64_t r) { return {r, 0}; }
};

enum class Err { Again, InProgress, ConnRefused, ConnReset, NotConn, BadF, Inval, AddrInUse, IsConn, TimedOut, Pipe, AfNoSupport, NoBufs };

// The real socket API (libc on hosts, forwarded bsd:u requests on Horizon).
class Backend {
public:
    virtual ~Backend() = default;
    virtual Result Socket(int domain, int type, int protocol) = 0;
    virtual Result Close(int fd) = 0;
    virtual Result Connect(int fd, const sockaddr *addr, socklen_t len) = 0;
    virtual Result Bind(int fd, const sockaddr *addr, socklen_t len) = 0;
    virtual Result Listen(int fd, int backlog) = 0;
    virtual Result Accept(int fd, sockaddr *addr, socklen_t *len) = 0;
    virtual Result Send(int fd, const void *buf, size_t len, int flags) = 0;
    virtual Result SendTo(int fd, const void *buf, size_t len, int flags, const sockaddr *to, socklen_t tolen) = 0;
    virtual Result Recv(int fd, void *buf, size_t len, int flags) = 0;
    virtual Result RecvFrom(int fd, void *buf, size_t len, int flags, sockaddr *from, socklen_t *fromlen) = 0;
    virtual Result Poll(pollfd *fds, nfds_t n, int timeout_ms) = 0;
    virtual Result Shutdown(int fd, int how) = 0;
    virtual Result GetSockName(int fd, sockaddr *addr, socklen_t *len) = 0;
    virtual Result GetPeerName(int fd, sockaddr *addr, socklen_t *len) = 0;
    virtual Result GetSockOpt(int fd, int level, int name, void *val, socklen_t *len) = 0;
    virtual Result SetSockOpt(int fd, int level, int name, const void *val, socklen_t len) = 0;
    virtual Result Fcntl(int fd, int cmd, int arg) = 0;
    // errno value for a virtual-socket error, in this backend's numbering.
    virtual int Errno(Err e) = 0;
    // Flag for "don't block" in recv flags (MSG_DONTWAIT).
    virtual int DontWaitFlag() = 0;
    // O_NONBLOCK as F_GETFL/F_SETFL carry it.
    virtual int NonBlockFlag() = 0;
};

class VSock {
public:
    VSock(Backend &real, Runtime &rt) : real_(real), rt_(rt) {}

    Result Socket(int domain, int type, int protocol);
    Result Close(int fd);
    Result Connect(int fd, const sockaddr *addr, socklen_t len);
    Result Bind(int fd, const sockaddr *addr, socklen_t len);
    Result Listen(int fd, int backlog);
    Result Accept(int fd, sockaddr *addr, socklen_t *len);
    Result Send(int fd, const void *buf, size_t len, int flags);
    Result SendTo(int fd, const void *buf, size_t len, int flags, const sockaddr *to, socklen_t tolen);
    Result Recv(int fd, void *buf, size_t len, int flags);
    Result RecvFrom(int fd, void *buf, size_t len, int flags, sockaddr *from, socklen_t *fromlen);
    Result Poll(pollfd *fds, nfds_t n, int timeout_ms);
    Result Shutdown(int fd, int how);
    Result GetSockName(int fd, sockaddr *addr, socklen_t *len);
    Result GetPeerName(int fd, sockaddr *addr, socklen_t *len);
    Result GetSockOpt(int fd, int level, int name, void *val, socklen_t *len);
    Result SetSockOpt(int fd, int level, int name, const void *val, socklen_t len);
    Result Fcntl(int fd, int cmd, int arg);
    // FIONBIO-style non-blocking toggle (ioctl), tracked like O_NONBLOCK.
    void NoteNonBlocking(int fd, bool on);

    // True if fd is known to this layer and has a virtual side.
    bool IsVirtual(int fd);
    // True if fd was created through this layer.
    bool IsKnown(int fd);
    // Sockets tracked for this client (diagnostics: a leak shows as growth).
    size_t Tracked();
    // Long waits re-check this once a second and give up (EAGAIN) once it
    // returns false, e.g. when the calling process has exited.
    void SetAliveCheck(std::function<bool()> alive) { alive_ = std::move(alive); }
    // Closes the virtual side of every socket (the client went away).
    void CloseAll();
    // Whether a datagram socket bound to the wildcard address gets its
    // overlay side right away (receives from the tailnet before sending
    // there) or only once it sends to a tailnet address, which saves its
    // buffers for the many sockets that never do. Default: right away.
    void SetEagerDualUdp(bool eager) { eager_dual_udp_ = eager; }
    static bool IsTailnet(const sockaddr *addr);

private:
    struct VFd {
        int type = 0;  // SOCK_STREAM or SOCK_DGRAM
        int domain = AF_INET;
        bool nonblock = false;
        int32_t tcp = 0;     // engine TCP connection id
        int32_t listen = 0;  // engine TCP listener id
        int32_t udp = 0;     // engine UDP socket id
        bool connecting = false;
        bool connected_virtual = false;
        bool has_udp_peer = false;
        TsnxAddr udp_peer{};
        uint16_t port = 0;       // locally bound port
        bool bound_any = false;  // bound to the wildcard address
        bool virtual_only = false;  // no usable real side (tailnet-bound, accepted)
        bool real_used = false;     // real side carried traffic (must be polled)
        int so_error = 0;
        int rcv_timeout_ms = -1, snd_timeout_ms = -1;
    };

    // Copies the state for fd (false if unknown).
    bool Get(int fd, VFd *out);
    void Put(int fd, const VFd &v);
    Result Fail(Err e) { return {-1, real_.Errno(e)}; }
    Result EngineErr(int32_t code);
    // Ensures the socket has an engine UDP socket on its port.
    bool EnsureUdp(int fd, VFd &v);
    // Waits for virtual readiness bits (TSNX_READABLE/WRITABLE/HUP) on id.
    bool WaitEngine(int32_t id, uint32_t mask, int timeout_ms);
    // rt_.WaitFor in slices, stopping early if the caller is no longer alive.
    bool WaitSliced(const std::function<bool(TsnxEngine *)> &ready, const Runtime::Clock::time_point *deadline);
    uint32_t VirtualRevents(const VFd &v, short events);

    Backend &real_;
    Runtime &rt_;
    std::function<bool()> alive_;
    bool eager_dual_udp_ = true;
    std::mutex mu_;
    std::map<int, VFd> fds_;
};

}  // namespace tsnx
