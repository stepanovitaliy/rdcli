#include "net/socket.h"
#include "net/udp.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#include <memory>

namespace rdcli::net {

namespace {

bool ensure_winsock() {
    static const bool ok = [] {
        WSADATA data;
        return ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
    return ok;
}

class WinSocket : public Stream {
public:
    explicit WinSocket(SOCKET s) : s_(s) {}
    ~WinSocket() override { close(); }

    WinSocket(const WinSocket&) = delete;
    WinSocket& operator=(const WinSocket&) = delete;

    int64_t read(uint8_t* buf, size_t n) override {
        const int r = ::recv(s_, reinterpret_cast<char*>(buf), static_cast<int>(n), 0);
        return r == SOCKET_ERROR ? -1 : r;
    }

    int64_t write(const uint8_t* buf, size_t n) override {
        const int w = ::send(s_, reinterpret_cast<const char*>(buf), static_cast<int>(n), 0);
        return w == SOCKET_ERROR ? -1 : w;
    }

    void close() override {
        if (s_ != INVALID_SOCKET) {
            ::shutdown(s_, SD_BOTH);
            ::closesocket(s_);
            s_ = INVALID_SOCKET;
        }
    }

    void shutdown() override {
        if (s_ != INVALID_SOCKET) {
            ::shutdown(s_, SD_BOTH);
        }
    }

    bool set_timeout(std::chrono::milliseconds timeout) override {
        const DWORD ms = timeout.count() > 0 ? static_cast<DWORD>(timeout.count()) : 0;
        if (::setsockopt(s_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms),
                         sizeof(ms)) != 0) {
            return false;
        }
        if (::setsockopt(s_, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms),
                         sizeof(ms)) != 0) {
            return false;
        }
        return true;
    }

    Endpoint local_addr() const override {
        Endpoint ep;
        sockaddr_storage ss{};
        int len = sizeof(ss);
        if (::getsockname(s_, reinterpret_cast<sockaddr*>(&ss), &len) != 0) {
            return ep;
        }
        if (ss.ss_family == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(&ss);
            ep.ip.assign(reinterpret_cast<const char*>(&sin->sin_addr), 4);
            ep.port = ntohs(sin->sin_port);
        } else if (ss.ss_family == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(&ss);
            ep.ip.assign(reinterpret_cast<const char*>(&sin6->sin6_addr), 16);
            ep.port = ntohs(sin6->sin6_port);
        }
        return ep;
    }

private:
    SOCKET s_ = INVALID_SOCKET;
};

// SO_RCVTIMEO/SO_SNDTIMEO only bound send()/recv() on Winsock, not connect()
// itself — a blocking connect() to a dead host stalls for the OS-level TCP
// retry timeout (tens of seconds to minutes), ignoring --timeout entirely.
// Mirrors the poll()-based approach in socket_posix.cpp's connect_with_timeout.
int connect_with_timeout(SOCKET s, const sockaddr* addr, int addr_len,
                         std::chrono::milliseconds timeout) {
    u_long nonblocking = 1;
    ::ioctlsocket(s, FIONBIO, &nonblocking);

    int rc = ::connect(s, addr, addr_len);
    if (rc == 0) {
        u_long blocking = 0;
        ::ioctlsocket(s, FIONBIO, &blocking);
        return 0;
    }
    if (::WSAGetLastError() != WSAEWOULDBLOCK) {
        return SOCKET_ERROR;
    }

    const int ms = timeout.count() > 0 ? static_cast<int>(timeout.count()) : -1;
    WSAPOLLFD pfd{};
    pfd.fd = s;
    pfd.events = POLLOUT;
    const int pr = ::WSAPoll(&pfd, 1, ms);
    if (pr <= 0) {
        return SOCKET_ERROR;
    }
    if (pfd.revents & (POLLERR | POLLHUP)) {
        return SOCKET_ERROR;
    }
    int so_err = 0;
    int len = sizeof(so_err);
    if (::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &len) != 0 ||
        so_err != 0) {
        return SOCKET_ERROR;
    }
    u_long blocking = 0;
    ::ioctlsocket(s, FIONBIO, &blocking);
    return 0;
}

}  // namespace

std::unique_ptr<Stream> dial_tcp(const std::string& addr, std::chrono::milliseconds timeout) {
    return dial_tcp_opts(addr, timeout, DialOptions{});
}

std::unique_ptr<Stream> dial_tcp_opts(const std::string& addr, std::chrono::milliseconds timeout,
                                      const DialOptions& opts) {
    if (!ensure_winsock()) {
        return nullptr;
    }
    std::string host, port;
    if (!split_hostport(addr, &host, &port)) {
        return nullptr;
    }

    int bind_family = 0;
    sockaddr_storage bind_sa{};
    int bind_len = 0;
    if (!opts.bind_ip.empty() && opts.bind_port > 0) {
        if (opts.bind_ip.size() == 4) {
            bind_family = AF_INET;
            auto* sin = reinterpret_cast<sockaddr_in*>(&bind_sa);
            std::memset(sin, 0, sizeof(*sin));
            sin->sin_family = AF_INET;
            sin->sin_port = htons(opts.bind_port);
            std::memcpy(&sin->sin_addr, opts.bind_ip.data(), 4);
            bind_len = sizeof(*sin);
        } else if (opts.bind_ip.size() == 16) {
            bind_family = AF_INET6;
            auto* sin6 = reinterpret_cast<sockaddr_in6*>(&bind_sa);
            std::memset(sin6, 0, sizeof(*sin6));
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = htons(opts.bind_port);
            std::memcpy(&sin6->sin6_addr, opts.bind_ip.data(), 16);
            bind_len = sizeof(*sin6);
        }
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) {
        return nullptr;
    }

    SOCKET s = INVALID_SOCKET;
    for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) {
            continue;
        }
        const DWORD ms = timeout.count() > 0 ? static_cast<DWORD>(timeout.count()) : 0;
        if (ms > 0) {
            ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms),
                         sizeof(ms));
            ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms),
                         sizeof(ms));
        }
        if (opts.reuse_addr) {
            char one = 1;
            ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        }
        if (bind_family != 0 && ai->ai_family == bind_family) {
            if (::bind(s, reinterpret_cast<sockaddr*>(&bind_sa), bind_len) != 0) {
                ::closesocket(s);
                s = INVALID_SOCKET;
                continue;
            }
        }
        if (connect_with_timeout(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen), timeout) ==
            0) {
            break;
        }
        ::closesocket(s);
        s = INVALID_SOCKET;
    }
    ::freeaddrinfo(res);

    if (s == INVALID_SOCKET) {
        return nullptr;
    }
    return std::make_unique<WinSocket>(s);
}

std::optional<std::string> udp_send_recv(const std::string& host, uint16_t port,
                                         const std::string& payload,
                                         std::chrono::milliseconds timeout) {
    if (!ensure_winsock()) {
        return std::nullopt;
    }
    const std::string port_str = std::to_string(port);
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
        return std::nullopt;
    }

    SOCKET s = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        ::freeaddrinfo(res);
        return std::nullopt;
    }

    std::optional<std::string> result;
    if (::sendto(s, payload.data(), static_cast<int>(payload.size()), 0, res->ai_addr,
                 static_cast<int>(res->ai_addrlen)) != SOCKET_ERROR) {
        const DWORD ms = timeout.count() > 0 ? static_cast<DWORD>(timeout.count()) : 0;
        ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
        char buf[4096];
        const int n = ::recv(s, buf, sizeof(buf), 0);
        if (n > 0) {
            result = std::string(buf, static_cast<size_t>(n));
        }
    }
    ::closesocket(s);
    ::freeaddrinfo(res);
    return result;
}

namespace {

class WinListener : public Listener {
public:
    explicit WinListener(SOCKET s) : s_(s) {}
    ~WinListener() override { ::closesocket(s_); }

    std::unique_ptr<Stream> accept() override {
        const SOCKET c = ::accept(s_, nullptr, nullptr);
        if (c == INVALID_SOCKET) {
            return nullptr;
        }
        return std::make_unique<WinSocket>(c);
    }

private:
    SOCKET s_;
};

}  // namespace

std::unique_ptr<Listener> listen_loopback(uint16_t port) {
    if (!ensure_winsock()) {
        return nullptr;
    }
    const SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        return nullptr;
    }
    // Refuse a second listener on the same port instead of silently sharing it.
    BOOL exclusive = TRUE;
    ::setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive),
                 sizeof(exclusive));
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(s, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa)) != 0 ||
        ::listen(s, 16) != 0) {
        ::closesocket(s);
        return nullptr;
    }
    return std::make_unique<WinListener>(s);
}

}  // namespace rdcli::net
