#include "net/socket.h"
#include "net/udp.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace rdcli::net {

namespace {

class PosixSocket : public Stream {
public:
    explicit PosixSocket(int fd) : fd_(fd) {}
    ~PosixSocket() override { close(); }

    PosixSocket(const PosixSocket&) = delete;
    PosixSocket& operator=(const PosixSocket&) = delete;

    int64_t read(uint8_t* buf, size_t n) override {
        const ssize_t r = ::recv(fd_, buf, n, 0);
        return r < 0 ? -1 : static_cast<int64_t>(r);
    }

    int64_t write(const uint8_t* buf, size_t n) override {
#if defined(MSG_NOSIGNAL)
        const ssize_t w = ::send(fd_, buf, n, MSG_NOSIGNAL);
#else
        const ssize_t w = ::send(fd_, buf, n, 0);
#endif
        return w < 0 ? -1 : static_cast<int64_t>(w);
    }

    void close() override {
        if (fd_ >= 0) {
            ::shutdown(fd_, SHUT_RDWR);
            ::close(fd_);
            fd_ = -1;
        }
    }

    void shutdown() override {
        if (fd_ >= 0) {
            ::shutdown(fd_, SHUT_RDWR);
        }
    }

    bool set_timeout(std::chrono::milliseconds timeout) override {
        timeval tv{};
        if (timeout.count() > 0) {
            tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
            tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
        }
        if (::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
            return false;
        }
        if (::setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
            return false;
        }
        return true;
    }

    Endpoint local_addr() const override {
        Endpoint ep;
        sockaddr_storage ss{};
        socklen_t len = sizeof(ss);
        if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&ss), &len) != 0) {
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
    int fd_ = -1;
};

int connect_with_timeout(int fd, const sockaddr* addr, socklen_t addr_len,
                         std::chrono::milliseconds timeout) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int rc = ::connect(fd, addr, addr_len);
    if (rc == 0) {
        ::fcntl(fd, F_SETFL, flags);
        return 0;
    }
    if (errno != EINPROGRESS) {
        return -1;
    }

    const int ms = timeout.count() > 0 ? static_cast<int>(timeout.count()) : -1;
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    const int pr = ::poll(&pfd, 1, ms);
    if (pr <= 0) {
        return -1;
    }
    int so_err = 0;
    socklen_t len = sizeof(so_err);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &len) != 0 || so_err != 0) {
        return -1;
    }
    ::fcntl(fd, F_SETFL, flags);
    return 0;
}

}  // namespace

std::unique_ptr<Stream> dial_tcp(const std::string& addr, std::chrono::milliseconds timeout) {
    return dial_tcp_opts(addr, timeout, DialOptions{});
}

std::unique_ptr<Stream> dial_tcp_opts(const std::string& addr, std::chrono::milliseconds timeout,
                                      const DialOptions& opts) {
    std::string host, port;
    if (!split_hostport(addr, &host, &port)) {
        return nullptr;
    }

    int bind_family = 0;
    sockaddr_storage bind_sa{};
    socklen_t bind_len = 0;
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

    int fd = -1;
    for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
#if defined(SO_NOSIGPIPE)
        {
            int one = 1;
            ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        }
#endif
        if (opts.reuse_addr) {
            int one = 1;
            ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#if defined(SO_REUSEPORT)
            // Hole punching rebinds the rendezvous socket's local port while it
            // may still be open; on BSD/macOS that needs SO_REUSEPORT too.
            ::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
        }
        if (bind_family != 0 && ai->ai_family == bind_family) {
            if (::bind(fd, reinterpret_cast<sockaddr*>(&bind_sa), bind_len) != 0) {
                ::close(fd);
                fd = -1;
                continue;
            }
        }
        if (connect_with_timeout(fd, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen),
                                 timeout) == 0) {
            break;
        }
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(res);

    if (fd < 0) {
        return nullptr;
    }
    return std::make_unique<PosixSocket>(fd);
}

std::optional<std::string> udp_send_recv(const std::string& host, uint16_t port,
                                         const std::string& payload,
                                         std::chrono::milliseconds timeout) {
    const std::string port_str = std::to_string(port);
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
        return std::nullopt;
    }

    int fd = -1;
    for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd >= 0) {
            break;
        }
    }
    if (fd < 0) {
        ::freeaddrinfo(res);
        return std::nullopt;
    }

    const sockaddr* target = res->ai_addr;
    const socklen_t target_len = static_cast<socklen_t>(res->ai_addrlen);

    std::optional<std::string> result;
    if (::sendto(fd, payload.data(), payload.size(), 0, target, target_len) >= 0) {
        const int ms = timeout.count() > 0 ? static_cast<int>(timeout.count()) : -1;
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        if (::poll(&pfd, 1, ms) > 0) {
            char buf[4096];
            const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n > 0) {
                result = std::string(buf, static_cast<size_t>(n));
            }
        }
    }
    ::close(fd);
    ::freeaddrinfo(res);
    return result;
}

namespace {

class PosixListener : public Listener {
public:
    explicit PosixListener(int fd) : fd_(fd) {}
    ~PosixListener() override { ::close(fd_); }

    std::unique_ptr<Stream> accept() override {
        while (true) {
            const int c = ::accept(fd_, nullptr, nullptr);
            if (c >= 0) {
                return std::make_unique<PosixSocket>(c);
            }
            if (errno != EINTR) {
                return nullptr;
            }
        }
    }

private:
    int fd_;
};

}  // namespace

std::unique_ptr<Listener> listen_loopback(uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return nullptr;
    }
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa)) != 0 ||
        ::listen(fd, 16) != 0) {
        ::close(fd);
        return nullptr;
    }
    return std::make_unique<PosixListener>(fd);
}

}  // namespace rdcli::net

