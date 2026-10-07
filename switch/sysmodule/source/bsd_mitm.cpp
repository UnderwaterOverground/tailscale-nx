// See bsd_mitm.hpp.
//
// Request layouts follow libnx's bsd.c (what homebrew sends). A handler either
// serves the call through VSock or returns ResultShouldForwardToSession, which
// passes the original request to the real bsd:u untouched. Only sockets VSock
// tracks (created while the MITM was active) can become virtual; for all
// others every command is forwarded, so plain networking costs one extra hop.
#include <stratosphere.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "bsd_mitm.hpp"
#include "log.hpp"
#include "runtime.hpp"
#include "stack_watch.hpp"
#include "status.hpp"
#include "vsock.hpp"

namespace ams::bsd_mitm {

    // RecvMMsg's request data (libnx bsdRecvMMsg).
    struct RecvMMsgArgs {
        s32 fd;
        s32 vlen;
        s32 flags;
        u32 pad;
        s64 timeout_sec;
        s64 timeout_nsec;
    };
    static_assert(sizeof(RecvMMsgArgs) == 0x20 && alignof(RecvMMsgArgs) == 8);

}

#define TSNX_BSD_MITM_INTERFACE_INFO(C, H)                                                                                                                                                                            \
    AMS_SF_METHOD_INFO(C, H,  2, Result, Socket,      (sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 domain, s32 type, s32 protocol),                                                                         (out_ret, out_errno, domain, type, protocol))                  \
    AMS_SF_METHOD_INFO(C, H,  6, Result, Poll,        (sf::Out<s32> out_ret, sf::Out<s32> out_errno, u32 nfds, s32 timeout, const sf::InAutoSelectBuffer &fds_in, const sf::OutAutoSelectBuffer &fds_out),          (out_ret, out_errno, nfds, timeout, fds_in, fds_out))          \
    AMS_SF_METHOD_INFO(C, H,  8, Result, Recv,        (sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 flags, const sf::OutAutoSelectBuffer &buf),                                                       (out_ret, out_errno, fd, flags, buf))                          \
    AMS_SF_METHOD_INFO(C, H,  9, Result, RecvFrom,    (sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_len, s32 fd, s32 flags, const sf::OutAutoSelectBuffer &buf, const sf::OutAutoSelectBuffer &addr), (out_ret, out_errno, out_len, fd, flags, buf, addr))     \
    AMS_SF_METHOD_INFO(C, H, 10, Result, Send,        (sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 flags, const sf::InAutoSelectBuffer &buf),                                                        (out_ret, out_errno, fd, flags, buf))                          \
    AMS_SF_METHOD_INFO(C, H, 11, Result, SendTo,      (sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 flags, const sf::InAutoSelectBuffer &buf, const sf::InAutoSelectBuffer &addr),                   (out_ret, out_errno, fd, flags, buf, addr))                    \
    AMS_SF_METHOD_INFO(C, H, 12, Result, Accept,      (sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_len, s32 fd, const sf::OutAutoSelectBuffer &addr),                                           (out_ret, out_errno, out_len, fd, addr))                       \
    AMS_SF_METHOD_INFO(C, H, 13, Result, Bind,        (sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer &addr),                                                                  (out_ret, out_errno, fd, addr))                                \
    AMS_SF_METHOD_INFO(C, H, 14, Result, Connect,     (sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer &addr),                                                                  (out_ret, out_errno, fd, addr))                                \
    AMS_SF_METHOD_INFO(C, H, 15, Result, GetPeerName, (sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_len, s32 fd, const sf::OutAutoSelectBuffer &addr),                                           (out_ret, out_errno, out_len, fd, addr))                       \
    AMS_SF_METHOD_INFO(C, H, 16, Result, GetSockName, (sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_len, s32 fd, const sf::OutAutoSelectBuffer &addr),                                           (out_ret, out_errno, out_len, fd, addr))                       \
    AMS_SF_METHOD_INFO(C, H, 17, Result, GetSockOpt,  (sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_len, s32 fd, s32 level, s32 name, const sf::OutAutoSelectBuffer &val),                       (out_ret, out_errno, out_len, fd, level, name, val))           \
    AMS_SF_METHOD_INFO(C, H, 18, Result, Listen,      (sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 backlog),                                                                                         (out_ret, out_errno, fd, backlog))                             \
    AMS_SF_METHOD_INFO(C, H, 20, Result, Fcntl,       (sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 cmd, s32 flags),                                                                                  (out_ret, out_errno, fd, cmd, flags))                          \
    AMS_SF_METHOD_INFO(C, H, 21, Result, SetSockOpt,  (sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 level, s32 name, const sf::InAutoSelectBuffer &val),                                              (out_ret, out_errno, fd, level, name, val))                    \
    AMS_SF_METHOD_INFO(C, H, 22, Result, Shutdown,    (sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 how),                                                                                             (out_ret, out_errno, fd, how))                                 \
    AMS_SF_METHOD_INFO(C, H, 24, Result, Write,       (sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer &buf),                                                                   (out_ret, out_errno, fd, buf))                                 \
    AMS_SF_METHOD_INFO(C, H, 25, Result, Read,        (sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::OutAutoSelectBuffer &buf),                                                                  (out_ret, out_errno, fd, buf))                                 \
    AMS_SF_METHOD_INFO(C, H, 26, Result, Close,       (sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd),                                                                                                      (out_ret, out_errno, fd))                                      \
    AMS_SF_METHOD_INFO(C, H, 29, Result, RecvMMsg,    (sf::Out<s32> out_ret, sf::Out<s32> out_errno, ::ams::bsd_mitm::RecvMMsgArgs args, const sf::OutBuffer &buf),                                                                 (out_ret, out_errno, args, buf))                               \
    AMS_SF_METHOD_INFO(C, H, 30, Result, SendMMsg,    (sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 vlen, s32 flags, const sf::OutBuffer &buf),                                                       (out_ret, out_errno, fd, vlen, flags, buf))

AMS_SF_DEFINE_MITM_INTERFACE(ams::bsd_mitm, IBsdMitm, TSNX_BSD_MITM_INTERFACE_INFO, 0x7473626D)

namespace ams::bsd_mitm {

    namespace {

        using VResult = ::tsnx::Result;

        constinit ::tsnx::Runtime *g_runtime = nullptr;
        constinit Scope g_scope = Scope::Off;
        constinit bool g_installed = false;
        constinit bool g_sys_ftpd = false;
        constinit bool g_installed_s = false;
        constexpr sm::ServiceName BsdUName = sm::ServiceName::Encode("bsd:u");
        constexpr sm::ServiceName BsdSName = sm::ServiceName::Encode("bsd:s");
        constexpr u64 SysFtpdProgramId = 0x420000000000000E;

        // bsd:u speaks Linux errno numbers and O_NONBLOCK = 0x800 (libnx
        // translates both for its callers); everything else matches libnx's
        // FreeBSD-derived headers.
        constexpr int WireEIO = 5;
        constexpr int WireENetUnreach = 101;  // tailnet traffic while the user paused Tailscale
        constexpr int WireNonBlock = 0x800;

        // ---- the real bsd:u ------------------------------------------------

        // Real socket calls for VSock, over a session private to us (a clone
        // of the client's), so they never queue behind a call the client has
        // blocked in on one of its own sessions.
        class HorizonBackend final : public ::tsnx::Backend {
            public:
                explicit HorizonBackend(::Service *srv) : m_srv(srv) {}

                VResult Socket(int domain, int type, int protocol) override {
                    const struct { s32 domain, type, protocol; } in = {domain, type, protocol};
                    return Call(2, in, Params());
                }
                VResult Close(int fd) override { return Call(26, static_cast<s32>(fd), Params()); }
                VResult Connect(int fd, const sockaddr *addr, socklen_t len) override {
                    return Call(14, static_cast<s32>(fd), Params().In(addr, len));
                }
                VResult Bind(int fd, const sockaddr *addr, socklen_t len) override {
                    return Call(13, static_cast<s32>(fd), Params().In(addr, len));
                }
                VResult Listen(int fd, int backlog) override {
                    const struct { s32 fd, backlog; } in = {fd, backlog};
                    return Call(18, in, Params());
                }
                VResult Accept(int fd, sockaddr *addr, socklen_t *len) override {
                    return CallLen(12, static_cast<s32>(fd), Params().Out(addr, len ? *len : 0), len);
                }
                VResult Send(int fd, const void *buf, size_t len, int flags) override {
                    const struct { s32 fd, flags; } in = {fd, flags};
                    return Call(10, in, Params().In(buf, len));
                }
                VResult SendTo(int fd, const void *buf, size_t len, int flags, const sockaddr *to, socklen_t tolen) override {
                    const struct { s32 fd, flags; } in = {fd, flags};
                    return Call(11, in, Params().In(buf, len).In(to, to ? tolen : 0));
                }
                VResult Recv(int fd, void *buf, size_t len, int flags) override {
                    const struct { s32 fd, flags; } in = {fd, flags};
                    return Call(8, in, Params().Out(buf, len));
                }
                VResult RecvFrom(int fd, void *buf, size_t len, int flags, sockaddr *from, socklen_t *fromlen) override {
                    const struct { s32 fd, flags; } in = {fd, flags};
                    return CallLen(9, in, Params().Out(buf, len).Out(from, fromlen ? *fromlen : 0), fromlen);
                }
                VResult Poll(pollfd *fds, nfds_t n, int timeout_ms) override {
                    const struct { u32 nfds; s32 timeout; } in = {static_cast<u32>(n), timeout_ms};
                    return Call(6, in, Params().In(fds, n * sizeof(pollfd)).Out(fds, n * sizeof(pollfd)));
                }
                VResult Shutdown(int fd, int how) override {
                    const struct { s32 fd, how; } in = {fd, how};
                    return Call(22, in, Params());
                }
                VResult GetSockName(int fd, sockaddr *addr, socklen_t *len) override {
                    return CallLen(16, static_cast<s32>(fd), Params().Out(addr, len ? *len : 0), len);
                }
                VResult GetPeerName(int fd, sockaddr *addr, socklen_t *len) override {
                    return CallLen(15, static_cast<s32>(fd), Params().Out(addr, len ? *len : 0), len);
                }
                VResult GetSockOpt(int fd, int level, int name, void *val, socklen_t *len) override {
                    const struct { s32 fd, level, name; } in = {fd, level, name};
                    return CallLen(17, in, Params().Out(val, len ? *len : 0), len);
                }
                VResult SetSockOpt(int fd, int level, int name, const void *val, socklen_t len) override {
                    const struct { s32 fd, level, name; } in = {fd, level, name};
                    return Call(21, in, Params().In(val, len));
                }
                VResult Fcntl(int fd, int cmd, int arg) override {
                    const struct { s32 fd, cmd, flags; } in = {fd, cmd, arg};
                    return Call(20, in, Params());
                }

                int Errno(::tsnx::Err e) override {
                    using ::tsnx::Err;
                    switch (e) {
                        case Err::Again:       return 11;
                        case Err::InProgress:  return 115;
                        case Err::ConnRefused: return 111;
                        case Err::ConnReset:   return 104;
                        case Err::NotConn:     return 107;
                        case Err::BadF:        return 9;
                        case Err::Inval:       return 22;
                        case Err::AddrInUse:   return 98;
                        case Err::IsConn:      return 106;
                        case Err::TimedOut:    return 110;
                        case Err::Pipe:        return 32;
                        case Err::AfNoSupport: return 97;
                        case Err::NoBufs:      return 105;
                    }
                    return 22;
                }
                int DontWaitFlag() override { return MSG_DONTWAIT; }
                int NonBlockFlag() override { return WireNonBlock; }

            private:
                // Up to two AutoSelect buffers, in request order.
                struct Params {
                    SfDispatchParams d = {};
                    int n = 0;
                    Params &In(const void *p, size_t size) { return Add(SfBufferAttr_HipcAutoSelect | SfBufferAttr_In, p, size); }
                    Params &Out(void *p, size_t size) { return Add(SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out, p, size); }
                    Params &Add(u32 attr, const void *p, size_t size) {
                        (n == 0 ? d.buffer_attrs.attr0 : d.buffer_attrs.attr1) = attr;
                        d.buffers[n++] = SfBuffer{p, size};
                        return *this;
                    }
                };

                template<typename In>
                VResult Call(u32 id, const In &in, const Params &p) {
                    struct { s32 ret, err; } out = {};
                    if (serviceDispatchImpl(m_srv, id, std::addressof(in), sizeof(in), std::addressof(out), sizeof(out), p.d) != 0) {
                        return {-1, WireEIO};
                    }
                    return {out.ret, out.ret < 0 ? out.err : 0};
                }

                // Calls that also return a length (addresses, option values).
                template<typename In>
                VResult CallLen(u32 id, const In &in, const Params &p, socklen_t *len) {
                    struct { s32 ret, err; u32 len; } out = {};
                    if (serviceDispatchImpl(m_srv, id, std::addressof(in), sizeof(in), std::addressof(out), sizeof(out), p.d) != 0) {
                        return {-1, WireEIO};
                    }
                    if (out.ret >= 0 && len) *len = out.len;
                    return {out.ret, out.ret < 0 ? out.err : 0};
                }

                ::Service *m_srv;
        };

        bool ProcessAlive(u64 pid) {
            u64 pids[0x100];
            s32 n = 0;
            if (svcGetProcessList(std::addressof(n), pids, 0x100) != 0) return true;
            for (s32 i = 0; i < n; i++) {
                if (pids[i] == pid) return true;
            }
            return false;
        }

        // A socket address in a client buffer, if it is complete enough for
        // VSock to read.
        const sockaddr *AddrIn(const sf::InAutoSelectBuffer &buf) {
            const size_t size = buf.GetSize();
            if (size < 2) return nullptr;
            const auto *sa = reinterpret_cast<const sockaddr *>(buf.GetPointer());
            if (sa->sa_family == AF_INET && size >= sizeof(sockaddr_in)) return sa;
            if (sa->sa_family == AF_INET6 && size >= sizeof(sockaddr_in6)) return sa;
            return nullptr;
        }

        void FormatAddr(const sockaddr *sa, char *out, size_t cap) {
            char ip[INET6_ADDRSTRLEN] = "?";
            u16 port = 0;
            if (sa->sa_family == AF_INET) {
                const auto *in = reinterpret_cast<const sockaddr_in *>(sa);
                inet_ntop(AF_INET, std::addressof(in->sin_addr), ip, sizeof ip);
                port = ntohs(in->sin_port);
            } else if (sa->sa_family == AF_INET6) {
                const auto *in6 = reinterpret_cast<const sockaddr_in6 *>(sa);
                inet_ntop(AF_INET6, std::addressof(in6->sin6_addr), ip, sizeof ip);
                port = ntohs(in6->sin6_port);
            }
            util::SNPrintf(out, cap, "%s:%u", ip, port);
        }

        // ---- sendmsg/recvmsg ------------------------------------------------

        // libnx serializes struct mmsghdr arrays (sendmmsg/recvmmsg, and so
        // sendmsg/recvmsg) into one buffer: a 0x08 byte, then per message
        //   u32 namelen, name, s32 iovlen, iovlen x (u64 len, data),
        //   u32 controllen, control, s32 flags, s32 msg_len.
        // For receives the lengths are capacities and the reply rewrites the
        // buffer with the actual ones.
        struct MMsg {
            size_t name_off = 0;
            u32 name_len = 0;
            std::vector<std::pair<size_t, u64>> iovs;  // data offset, length
            size_t msg_len_off = 0;
        };

        bool ParseMMsgs(const u8 *buf, size_t size, s32 vlen, std::vector<MMsg> &out) {
            if (vlen < 1 || vlen > 0x20 || size < 1) return false;
            size_t off = 1;
            auto take = [&](size_t n) { const size_t at = off; off += n; return off <= size ? at : SIZE_MAX; };
            for (s32 i = 0; i < vlen; i++) {
                MMsg m;
                size_t at = take(sizeof(u32));
                if (at == SIZE_MAX) return false;
                std::memcpy(std::addressof(m.name_len), buf + at, sizeof(u32));
                if ((m.name_off = take(m.name_len)) == SIZE_MAX) return false;
                s32 iovlen;
                if ((at = take(sizeof(s32))) == SIZE_MAX) return false;
                std::memcpy(std::addressof(iovlen), buf + at, sizeof(s32));
                if (iovlen < 0 || iovlen > 64) return false;
                for (s32 v = 0; v < iovlen; v++) {
                    u64 len;
                    if ((at = take(sizeof(u64))) == SIZE_MAX) return false;
                    std::memcpy(std::addressof(len), buf + at, sizeof(u64));
                    if (len > size) return false;
                    const size_t data = take(static_cast<size_t>(len));
                    if (data == SIZE_MAX) return false;
                    m.iovs.emplace_back(data, len);
                }
                u32 controllen;
                if ((at = take(sizeof(u32))) == SIZE_MAX) return false;
                std::memcpy(std::addressof(controllen), buf + at, sizeof(u32));
                if (take(controllen) == SIZE_MAX || take(sizeof(s32)) == SIZE_MAX) return false;
                if ((m.msg_len_off = take(sizeof(s32))) == SIZE_MAX) return false;
                out.push_back(std::move(m));
            }
            return true;
        }

        // ---- per-client state ----------------------------------------------

        struct ClientState {
            ::Service fwd = {};
            std::unique_ptr<HorizonBackend> backend;
            std::unique_ptr<::tsnx::VSock> vsock;

            ~ClientState() {
                if (vsock) vsock->CloseAll();
                serviceClose(std::addressof(fwd));
            }
        };

    }

    class BsdMitmService : public sf::MitmServiceImplBase {
        private:
            // Null if we couldn't set up (then every call is forwarded).
            std::unique_ptr<ClientState> m_state;

        public:
            BsdMitmService(std::shared_ptr<::Service> &&s, const sm::MitmProcessInfo &c) : MitmServiceImplBase(std::move(s), c) {
                auto st = std::make_unique<ClientState>();
                if (R_FAILED(serviceClone(m_forward_service.get(), std::addressof(st->fwd)))) {
                    Log("bsd mitm: cannot clone session of program %016lx; forwarding everything", m_client_info.program_id.value);
                    return;
                }
                st->backend = std::make_unique<HorizonBackend>(std::addressof(st->fwd));
                st->vsock = std::make_unique<::tsnx::VSock>(*st->backend, *g_runtime);
                const u64 pid = m_client_info.process_id.value;
                st->vsock->SetAliveCheck([pid] { return ProcessAlive(pid); });
                st->vsock->SetEagerDualUdp(false);
                m_state = std::move(st);
                Log("bsd mitm: session from program %016lx (pid %lu)", m_client_info.program_id.value, pid);
            }

            static bool ShouldMitm(const sm::MitmProcessInfo &c) {
                // sys-ftpd builds whose libnx prefers bsd:u come through here.
                return (g_scope == Scope::Homebrew && c.override_status.IsHbl()) ||
                       (g_sys_ftpd && c.program_id.value == SysFtpdProgramId);
            }

        private:
            ::tsnx::VSock *V() { return m_state ? m_state->vsock.get() : nullptr; }
            bool Known(s32 fd) { return V() && V()->IsKnown(fd); }
            bool Virtual(s32 fd) { return V() && V()->IsVirtual(fd); }

            static Result Reply(sf::Out<s32> &ret, sf::Out<s32> &err, const VResult &r) {
                ret.SetValue(static_cast<s32>(r.ret));
                err.SetValue(r.ret < 0 ? r.err : 0);
                R_SUCCEED();
            }

            // Reply, logging real failures of calls that set sockets up
            // (would-block and in-progress are normal), a few per session.
            Result ReplyLogged(const char *call, s32 fd, sf::Out<s32> &ret, sf::Out<s32> &err, const VResult &r) {
                if (r.ret < 0 && r.err != 11 && r.err != 115 && m_failures_logged < 32) {
                    m_failures_logged++;
                    Log("bsd mitm: pid %lu %s(fd %d) failed: errno %d", m_client_info.process_id.value, call, fd, r.err);
                }
                return Reply(ret, err, r);
            }
            int m_failures_logged = 0;

        public:
            Result Socket(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 domain, s32 type, s32 protocol) {
                R_UNLESS(V() != nullptr, sm::mitm::ResultShouldForwardToSession());
                R_RETURN(ReplyLogged("socket", -1, out_ret, out_errno, V()->Socket(domain, type, protocol)));
            }

            Result Poll(sf::Out<s32> out_ret, sf::Out<s32> out_errno, u32 nfds, s32 timeout, const sf::InAutoSelectBuffer &fds_in, const sf::OutAutoSelectBuffer &fds_out) {
                const size_t size = static_cast<size_t>(nfds) * sizeof(pollfd);
                R_UNLESS(V() != nullptr && nfds > 0 && fds_in.GetSize() >= size && fds_out.GetSize() >= size, sm::mitm::ResultShouldForwardToSession());
                std::vector<pollfd> fds(nfds);
                std::memcpy(fds.data(), fds_in.GetPointer(), size);
                bool any_virtual = false;
                for (const auto &p : fds) any_virtual |= p.fd >= 0 && Virtual(p.fd);
                R_UNLESS(any_virtual, sm::mitm::ResultShouldForwardToSession());

                const VResult r = V()->Poll(fds.data(), nfds, timeout);
                std::memcpy(fds_out.GetPointer(), fds.data(), size);
                R_RETURN(Reply(out_ret, out_errno, r));
            }

            Result Recv(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 flags, const sf::OutAutoSelectBuffer &buf) {
                R_UNLESS(Virtual(fd), sm::mitm::ResultShouldForwardToSession());
                R_RETURN(Reply(out_ret, out_errno, V()->Recv(fd, buf.GetPointer(), buf.GetSize(), flags)));
            }

            Result RecvFrom(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_len, s32 fd, s32 flags, const sf::OutAutoSelectBuffer &buf, const sf::OutAutoSelectBuffer &addr) {
                R_UNLESS(Virtual(fd), sm::mitm::ResultShouldForwardToSession());
                socklen_t len = static_cast<socklen_t>(addr.GetSize());
                auto *sa = len ? reinterpret_cast<sockaddr *>(addr.GetPointer()) : nullptr;
                const VResult r = V()->RecvFrom(fd, buf.GetPointer(), buf.GetSize(), flags, sa, sa ? std::addressof(len) : nullptr);
                out_len.SetValue(r.ret >= 0 && sa ? len : 0);
                R_RETURN(Reply(out_ret, out_errno, r));
            }

            Result Send(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 flags, const sf::InAutoSelectBuffer &buf) {
                R_UNLESS(Virtual(fd), sm::mitm::ResultShouldForwardToSession());
                R_RETURN(Reply(out_ret, out_errno, V()->Send(fd, buf.GetPointer(), buf.GetSize(), flags)));
            }

            Result SendTo(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 flags, const sf::InAutoSelectBuffer &buf, const sf::InAutoSelectBuffer &addr) {
                const sockaddr *to = AddrIn(addr);
                R_UNLESS(Virtual(fd) || (Known(fd) && ::tsnx::VSock::IsTailnet(to)), sm::mitm::ResultShouldForwardToSession());
                if (status::IsPaused() && (to == nullptr || ::tsnx::VSock::IsTailnet(to))) R_RETURN(Reply(out_ret, out_errno, VResult{-1, WireENetUnreach}));
                R_RETURN(Reply(out_ret, out_errno, V()->SendTo(fd, buf.GetPointer(), buf.GetSize(), flags, to, to ? static_cast<socklen_t>(addr.GetSize()) : 0)));
            }

            Result Accept(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_len, s32 fd, const sf::OutAutoSelectBuffer &addr) {
                R_UNLESS(Virtual(fd), sm::mitm::ResultShouldForwardToSession());
                socklen_t len = static_cast<socklen_t>(addr.GetSize());
                auto *sa = len ? reinterpret_cast<sockaddr *>(addr.GetPointer()) : nullptr;
                const VResult r = V()->Accept(fd, sa, sa ? std::addressof(len) : nullptr);
                out_len.SetValue(r.ret >= 0 && sa ? len : 0);
                // Dual listeners also accept plain LAN connections here.
                if (r.ret >= 0 && sa && ::tsnx::VSock::IsTailnet(sa)) {
                    char peer[64];
                    FormatAddr(sa, peer, sizeof peer);
                    Log("bsd mitm: pid %lu accepted tailnet connection from %s on fd %d (new fd %d; %zu sockets tracked)", m_client_info.process_id.value, peer, fd,
                        static_cast<int>(r.ret), V()->Tracked());
                }
                R_RETURN(ReplyLogged("accept", fd, out_ret, out_errno, r));
            }

            Result Bind(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer &addr) {
                const sockaddr *sa = AddrIn(addr);
                R_UNLESS(Known(fd) && sa != nullptr, sm::mitm::ResultShouldForwardToSession());
                R_RETURN(ReplyLogged("bind", fd, out_ret, out_errno, V()->Bind(fd, sa, static_cast<socklen_t>(addr.GetSize()))));
            }

            Result Connect(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer &addr) {
                const sockaddr *sa = AddrIn(addr);
                const bool tailnet = ::tsnx::VSock::IsTailnet(sa);
                R_UNLESS(Known(fd) && sa != nullptr && (tailnet || Virtual(fd)), sm::mitm::ResultShouldForwardToSession());
                if (tailnet && status::IsPaused()) R_RETURN(Reply(out_ret, out_errno, VResult{-1, WireENetUnreach}));
                const VResult r = V()->Connect(fd, sa, static_cast<socklen_t>(addr.GetSize()));
                if (tailnet) {
                    char dst[64];
                    FormatAddr(sa, dst, sizeof dst);
                    Log("bsd mitm: pid %lu fd %d connect to %s over the tailnet: %s (errno %d)", m_client_info.process_id.value, fd, dst,
                        r.ret >= 0 ? "ok" : "failed", r.ret < 0 ? r.err : 0);
                }
                R_RETURN(Reply(out_ret, out_errno, r));
            }

            Result GetPeerName(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_len, s32 fd, const sf::OutAutoSelectBuffer &addr) {
                R_UNLESS(Virtual(fd), sm::mitm::ResultShouldForwardToSession());
                socklen_t len = static_cast<socklen_t>(addr.GetSize());
                const VResult r = V()->GetPeerName(fd, reinterpret_cast<sockaddr *>(addr.GetPointer()), std::addressof(len));
                out_len.SetValue(r.ret >= 0 ? len : 0);
                R_RETURN(Reply(out_ret, out_errno, r));
            }

            Result GetSockName(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_len, s32 fd, const sf::OutAutoSelectBuffer &addr) {
                R_UNLESS(Known(fd), sm::mitm::ResultShouldForwardToSession());
                socklen_t len = static_cast<socklen_t>(addr.GetSize());
                const VResult r = V()->GetSockName(fd, reinterpret_cast<sockaddr *>(addr.GetPointer()), std::addressof(len));
                out_len.SetValue(r.ret >= 0 ? len : 0);
                R_RETURN(ReplyLogged("getsockname", fd, out_ret, out_errno, r));
            }

            Result GetSockOpt(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_len, s32 fd, s32 level, s32 name, const sf::OutAutoSelectBuffer &val) {
                R_UNLESS(Virtual(fd), sm::mitm::ResultShouldForwardToSession());
                socklen_t len = static_cast<socklen_t>(val.GetSize());
                const VResult r = V()->GetSockOpt(fd, level, name, val.GetPointer(), std::addressof(len));
                out_len.SetValue(r.ret >= 0 ? len : 0);
                R_RETURN(Reply(out_ret, out_errno, r));
            }

            Result Listen(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 backlog) {
                R_UNLESS(Known(fd), sm::mitm::ResultShouldForwardToSession());
                const VResult r = V()->Listen(fd, backlog);
                if (r.ret >= 0 && Virtual(fd)) Log("bsd mitm: pid %lu fd %d listening on the tailnet too", m_client_info.process_id.value, fd);
                R_RETURN(ReplyLogged("listen", fd, out_ret, out_errno, r));
            }

            Result Fcntl(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 cmd, s32 flags) {
                R_UNLESS(Known(fd), sm::mitm::ResultShouldForwardToSession());
                R_RETURN(Reply(out_ret, out_errno, V()->Fcntl(fd, cmd, flags)));
            }

            Result SetSockOpt(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 level, s32 name, const sf::InAutoSelectBuffer &val) {
                R_UNLESS(Known(fd), sm::mitm::ResultShouldForwardToSession());
                R_RETURN(ReplyLogged("setsockopt", fd, out_ret, out_errno, V()->SetSockOpt(fd, level, name, val.GetPointer(), static_cast<socklen_t>(val.GetSize()))));
            }

            Result Shutdown(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 how) {
                R_UNLESS(Virtual(fd), sm::mitm::ResultShouldForwardToSession());
                R_RETURN(Reply(out_ret, out_errno, V()->Shutdown(fd, how)));
            }

            Result Write(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer &buf) {
                R_UNLESS(Virtual(fd), sm::mitm::ResultShouldForwardToSession());
                R_RETURN(Reply(out_ret, out_errno, V()->Send(fd, buf.GetPointer(), buf.GetSize(), 0)));
            }

            Result Read(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::OutAutoSelectBuffer &buf) {
                R_UNLESS(Virtual(fd), sm::mitm::ResultShouldForwardToSession());
                R_RETURN(Reply(out_ret, out_errno, V()->Recv(fd, buf.GetPointer(), buf.GetSize(), 0)));
            }

            Result Close(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd) {
                R_UNLESS(Known(fd), sm::mitm::ResultShouldForwardToSession());
                R_RETURN(ReplyLogged("close", fd, out_ret, out_errno, V()->Close(fd)));
            }

            Result SendMMsg(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 vlen, s32 flags, const sf::OutBuffer &buf) {
                R_UNLESS(Known(fd), sm::mitm::ResultShouldForwardToSession());
                u8 *data = buf.GetPointer();
                std::vector<MMsg> msgs;
                R_UNLESS(ParseMMsgs(data, buf.GetSize(), vlen, msgs), sm::mitm::ResultShouldForwardToSession());
                auto dest = [&](const MMsg &m) -> const sockaddr * {
                    if (m.name_len < 2) return nullptr;
                    const auto *sa = reinterpret_cast<const sockaddr *>(data + m.name_off);
                    if (sa->sa_family == AF_INET && m.name_len >= sizeof(sockaddr_in)) return sa;
                    if (sa->sa_family == AF_INET6 && m.name_len >= sizeof(sockaddr_in6)) return sa;
                    return nullptr;
                };
                R_UNLESS(Virtual(fd) || ::tsnx::VSock::IsTailnet(dest(msgs[0])), sm::mitm::ResultShouldForwardToSession());

                s32 sent = 0;
                VResult last = VResult::Ok(0);
                std::vector<u8> payload;
                for (const auto &m : msgs) {
                    payload.clear();
                    for (const auto &[off, len] : m.iovs) payload.insert(payload.end(), data + off, data + off + len);
                    const sockaddr *to = dest(m);
                    last = V()->SendTo(fd, payload.data(), payload.size(), flags, to, to ? m.name_len : 0);
                    if (last.ret < 0) break;
                    const s32 n = static_cast<s32>(last.ret);
                    std::memcpy(data + m.msg_len_off, std::addressof(n), sizeof n);
                    sent++;
                }
                R_RETURN(Reply(out_ret, out_errno, sent > 0 ? VResult::Ok(sent) : last));
            }

            Result RecvMMsg(sf::Out<s32> out_ret, sf::Out<s32> out_errno, ::ams::bsd_mitm::RecvMMsgArgs args, const sf::OutBuffer &buf) {
                R_UNLESS(Virtual(args.fd), sm::mitm::ResultShouldForwardToSession());
                u8 *data = buf.GetPointer();
                std::vector<MMsg> msgs;
                R_UNLESS(ParseMMsgs(data, buf.GetSize(), args.vlen, msgs), sm::mitm::ResultShouldForwardToSession());

                // Receive first (the parse refers to the buffer), then rewrite.
                struct Got {
                    std::vector<u8> bytes;
                    sockaddr_storage from;
                    socklen_t from_len;
                };
                std::vector<Got> got;
                VResult last = VResult::Ok(0);
                for (const auto &m : msgs) {
                    u64 cap = 0;
                    for (const auto &iov : m.iovs) cap += iov.second;
                    Got g{std::vector<u8>(cap), {}, static_cast<socklen_t>(std::min<size_t>(m.name_len, sizeof(sockaddr_storage)))};
                    // Block (per the socket's mode) for the first message only.
                    const int flags = got.empty() ? args.flags : (args.flags | MSG_DONTWAIT);
                    last = V()->RecvFrom(args.fd, g.bytes.data(), g.bytes.size(), flags, g.from_len ? reinterpret_cast<sockaddr *>(std::addressof(g.from)) : nullptr,
                                         g.from_len ? std::addressof(g.from_len) : nullptr);
                    if (last.ret < 0) break;
                    g.bytes.resize(static_cast<size_t>(last.ret));
                    got.push_back(std::move(g));
                }
                if (got.empty()) R_RETURN(Reply(out_ret, out_errno, last));

                size_t off = 1;
                auto put = [&](const void *p, size_t n) { std::memcpy(data + off, p, n); off += n; };
                for (size_t i = 0; i < got.size(); i++) {
                    const Got &g = got[i];
                    const u32 name_len = g.from_len;
                    put(std::addressof(name_len), sizeof name_len);
                    put(std::addressof(g.from), name_len);
                    const s32 iovlen = static_cast<s32>(msgs[i].iovs.size());
                    put(std::addressof(iovlen), sizeof iovlen);
                    size_t done = 0;
                    for (const auto &iov : msgs[i].iovs) {
                        const u64 n = std::min<u64>(iov.second, g.bytes.size() - done);
                        put(std::addressof(n), sizeof n);
                        put(g.bytes.data() + done, static_cast<size_t>(n));
                        done += static_cast<size_t>(n);
                    }
                    const u32 controllen = 0;
                    const s32 msg_flags = 0, msg_len = static_cast<s32>(g.bytes.size());
                    put(std::addressof(controllen), sizeof controllen);
                    put(std::addressof(msg_flags), sizeof msg_flags);
                    put(std::addressof(msg_len), sizeof msg_len);
                }
                R_RETURN(Reply(out_ret, out_errno, VResult::Ok(static_cast<s32>(got.size()))));
            }
    };
    static_assert(IsIBsdMitm<BsdMitmService>);

    namespace {

        enum PortIndex {
            PortIndex_BsdU,
            PortIndex_Count,
        };

        // Matches what other bsd MITMs use; Start() checks the real service's
        // pointer buffer fits (a smaller one would abort on every session).
        constexpr size_t PointerBufferSize = 0x1000;
        // A homebrew app opens ~4 sessions (main + clones + monitor), and
        // homebrew runs one app at a time.
        constexpr size_t MaxSessions = 16;

        struct ServerOptions {
            static constexpr size_t PointerBufferSize   = bsd_mitm::PointerBufferSize;
            static constexpr size_t MaxDomains          = 0;
            static constexpr size_t MaxDomainObjects    = 0;
            static constexpr bool CanDeferInvokeRequest = false;
            static constexpr bool CanManageMitmServers  = true;
        };

        class ServerManager final : public sf::hipc::ServerManager<PortIndex_Count, ServerOptions, MaxSessions> {
            private:
                virtual Result OnNeedsToAccept(int port_index, Server *server) override {
                    AMS_UNUSED(port_index);
                    std::shared_ptr<::Service> fsrv;
                    sm::MitmProcessInfo client_info;
                    server->AcknowledgeMitmSession(std::addressof(fsrv), std::addressof(client_info));
                    R_RETURN(this->AcceptMitmImpl(server, sf::CreateSharedObjectEmplaced<IBsdMitm, BsdMitmService>(decltype(fsrv)(fsrv), client_info), fsrv));
                }
        };

        ServerManager g_server_manager;

        // ---- bsd:s, for sys-ftpd only ----------------------------------------

        // Every system service that uses sockets opens bsd:s, and sm asks us
        // about each new session: this manager has its own threads so those
        // queries never wait behind a homebrew app's blocking call, and it
        // only takes sys-ftpd (which keeps its sockets non-blocking).
        class BsdSystemMitmService : public BsdMitmService {
            public:
                using BsdMitmService::BsdMitmService;
                static bool ShouldMitm(const sm::MitmProcessInfo &c) {
                    return g_sys_ftpd && c.program_id.value == SysFtpdProgramId;
                }
        };

        // sys-ftpd opens a few sessions (main, clones, monitor); too few here
        // would make its socketInitialize fail, and it aborts on that.
        constexpr size_t SystemMaxSessions = 8;

        class SystemServerManager final : public sf::hipc::ServerManager<1, ServerOptions, SystemMaxSessions> {
            private:
                virtual Result OnNeedsToAccept(int port_index, Server *server) override {
                    AMS_UNUSED(port_index);
                    std::shared_ptr<::Service> fsrv;
                    sm::MitmProcessInfo client_info;
                    server->AcknowledgeMitmSession(std::addressof(fsrv), std::addressof(client_info));
                    R_RETURN(this->AcceptMitmImpl(server, sf::CreateSharedObjectEmplaced<IBsdMitm, BsdSystemMitmService>(decltype(fsrv)(fsrv), client_info), fsrv));
                }
        };

        // Allocated only when sys-ftpd is served (it's ~30 KB of session
        // storage plus the thread stacks).
        constinit SystemServerManager *g_system_server_manager = nullptr;
        constexpr size_t SystemNumThreads = 2;  // one may sit in sys-ftpd's 250 ms poll

        // Each thread serves one request at a time, and a blocking socket call
        // holds its thread until it completes: allow a few at once.
        constexpr size_t NumThreads = 6;
        constexpr size_t ThreadStackSize = 0x5000;  // measured: ~9 KB through the socket test suite
        alignas(os::MemoryPageSize) constinit u8 g_thread_stacks[NumThreads][ThreadStackSize];
        constinit os::ThreadType g_threads[NumThreads];

        void LoopServerThread(void *) {
            g_server_manager.LoopProcess();
        }

        void LoopSystemServerThread(void *) {
            g_system_server_manager->LoopProcess();
        }

        size_t RealPointerBuffer(const char *name) {
            ::Service probe;
            if (R_FAILED(smGetService(std::addressof(probe), name))) return SIZE_MAX;
            const size_t size = probe.pointer_buffer_size;
            serviceClose(std::addressof(probe));
            return size;
        }

        // GCC speculatively devirtualizes the server manager's calls to the
        // bsd:u manager's type (16 sessions) and then warns that our smaller
        // heap object can't hold one; that path is never taken.
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Warray-bounds"
        bool StartSystemMitm(s32 priority) {
            if (const size_t real = RealPointerBuffer("bsd:s"); real > PointerBufferSize) {
                Log("bsd mitm: bsd:s unusable (pointer buffer 0x%zx); sys-ftpd stays LAN-only", real);
                return false;
            }
            g_system_server_manager = new (std::nothrow) SystemServerManager();
            if (!g_system_server_manager) {
                Log("bsd mitm: no memory for the bsd:s server; sys-ftpd stays LAN-only");
                return false;
            }
            if (const Result rc = g_system_server_manager->RegisterMitmServer<BsdSystemMitmService>(0, BsdSName); R_FAILED(rc)) {
                Log("bsd mitm: registering bsd:s failed: 0x%x", rc.GetValue());
                return false;
            }
            g_installed_s = true;
            static os::ThreadType threads[SystemNumThreads];
            for (size_t i = 0; i < SystemNumThreads; i++) {
                void *stack = std::aligned_alloc(os::ThreadStackAlignment, ThreadStackSize);
                // Paint before CreateThread: it mirrors the stack and locks
                // the original pages (see stack_watch.hpp).
                if (stack) stack_watch::Paint(stack, ThreadStackSize);
                if (!stack || R_FAILED(os::CreateThread(threads + i, LoopSystemServerThread, nullptr, stack, ThreadStackSize, priority))) {
                    Log("bsd mitm: cannot create bsd:s thread %zu", i);
                    if (i == 0) {
                        static_cast<void>(sm::mitm::UninstallMitm(BsdSName));  // nobody would answer sm's queries
                        g_installed_s = false;
                    }
                    return i > 0;
                }
                os::SetThreadNamePointer(threads + i, "tsnx.BsdSMitm");
                stack_watch::Add("mitm:s", threads + i);
                os::StartThread(threads + i);
            }
            return true;
        }
        #pragma GCC diagnostic pop

        // sys-ftpd opened its sockets at boot, before the MITM existed;
        // restart it so its new sessions come through us.
        void RestartSysFtpd() {
            if (R_FAILED(pmshellInitialize())) {
                Log("bsd mitm: no pm:shell; restart sys-ftpd to reach it over the tailnet");
                return;
            }
            u64 pid = 0;
            if (R_FAILED(pmshellGetProcessId(std::addressof(pid), SysFtpdProgramId)) || pid == 0) {
                Log("bsd mitm: sys-ftpd not running; it will use the MITM when started");
            } else if (const Result rc = pmshellTerminateProgram(SysFtpdProgramId); R_FAILED(rc)) {
                Log("bsd mitm: could not stop sys-ftpd (0x%x); restart it to reach it over the tailnet", rc.GetValue());
            } else {
                const NcmProgramLocation loc = {.program_id = SysFtpdProgramId, .storageID = NcmStorageId_None};
                for (int i = 0; i < 20; i++) {  // pm refuses while the old process is still going away
                    os::SleepThread(TimeSpan::FromMilliSeconds(100));
                    if (R_SUCCEEDED(pmshellLaunchProgram(0, std::addressof(loc), std::addressof(pid)))) {
                        Log("bsd mitm: sys-ftpd restarted (pid %lu) to serve it on the tailnet", pid);
                        pmshellExit();
                        return;
                    }
                }
                Log("bsd mitm: sys-ftpd stopped but did not start again; toggle it in the overlay");
            }
            pmshellExit();
        }

    }

    bool Start(::tsnx::Runtime &rt, Scope scope, bool sys_ftpd) {
        if (scope == Scope::Off) {
            Log("bsd mitm: off (mitm=off in config.ini)");
            return false;
        }

        // Our pointer buffer must be at least as large as the real service's.
        ::Service probe;
        if (R_FAILED(smGetService(std::addressof(probe), "bsd:u"))) {
            Log("bsd mitm: cannot open bsd:u; not starting");
            return false;
        }
        const size_t real_pointer_buffer = probe.pointer_buffer_size;
        serviceClose(std::addressof(probe));
        if (real_pointer_buffer > PointerBufferSize) {
            Log("bsd mitm: bsd:u pointer buffer is 0x%zx (> 0x%zx); not starting", real_pointer_buffer, PointerBufferSize);
            return false;
        }

        g_runtime = std::addressof(rt);
        g_scope = scope;
        g_sys_ftpd = sys_ftpd;
        if (const Result rc = g_server_manager.RegisterMitmServer<BsdMitmService>(PortIndex_BsdU, BsdUName); R_FAILED(rc)) {
            Log("bsd mitm: registering failed: 0x%x", rc.GetValue());
            return false;
        }
        g_installed = true;

        const s32 priority = os::GetThreadCurrentPriority(os::GetCurrentThread());
        for (size_t i = 0; i < NumThreads; i++) {
            stack_watch::Paint(g_thread_stacks[i], ThreadStackSize);
            if (R_FAILED(os::CreateThread(g_threads + i, LoopServerThread, nullptr, g_thread_stacks[i], ThreadStackSize, priority))) {
                Log("bsd mitm: cannot create server thread %zu", i);
                if (i == 0) UninstallForExit();  // nobody would answer sm's queries
                return i > 0;
            }
            os::SetThreadNamePointer(g_threads + i, "tsnx.BsdMitm");
            stack_watch::Add("mitm", g_threads + i);
            os::StartThread(g_threads + i);
        }
        Log("bsd mitm: active for homebrew (real pointer buffer 0x%zx, %zu threads)", real_pointer_buffer, NumThreads);
        if (sys_ftpd && StartSystemMitm(priority)) {
            Log("bsd mitm: active for sys-ftpd");
            RestartSysFtpd();
        }
        return true;
    }

    void UninstallForExit() {
        if (!g_installed) return;
        g_installed = false;
        static_cast<void>(sm::mitm::UninstallMitm(BsdUName));
        if (g_installed_s) {
            g_installed_s = false;
            static_cast<void>(sm::mitm::UninstallMitm(BsdSName));
        }
    }

}
