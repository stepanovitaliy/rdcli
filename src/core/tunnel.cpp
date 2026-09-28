#include "core/tunnel.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <thread>

namespace rdcli::core {

namespace {

// Copies until either side stops. Never closes anything itself: the caller
// shuts both endpoints down once, so the opposite direction's blocked read
// wakes up and the thread can be joined.
template <typename From, typename To>
void pump(From* from, To* to) {
    uint8_t buf[8192];
    while (true) {
        const int64_t n = from->read(buf, sizeof(buf));
        if (n <= 0) {
            return;
        }
        size_t written = 0;
        while (written < static_cast<size_t>(n)) {
            const int64_t w = to->write(buf + written, static_cast<size_t>(n) - written);
            if (w <= 0) {
                return;
            }
            written += static_cast<size_t>(w);
        }
    }
}

}  // namespace

Tunnel::~Tunnel() { Close(); }

std::unique_ptr<Tunnel> Tunnel::Open(const DialOpts& opts, const std::string& host, int32_t port,
                                     std::string* err) {
    DialOpts o = opts;
    o.conn_type = hbb::PORT_FORWARD;
    auto c = Conn::Connect(o, err);
    if (!c) {
        return nullptr;
    }
    LoginSpec spec;
    spec.host = host;
    spec.port = port;
    auto pi = c->Login(LoginKind::Tunnel, spec, err);
    if (!pi) {
        return nullptr;
    }
    if (std::getenv("RDC_DEBUG") != nullptr) {
        std::fprintf(stderr, "hbb debug: tunnel login ok, forwarding to %s:%d\n", host.c_str(),
                     port);
    }
    c->SetRaw();
    auto t = std::unique_ptr<Tunnel>(new Tunnel());
    t->conn_ = std::move(c);
    return t;
}

void Tunnel::Pipe(net::Stream* local) {
    std::atomic<bool> stopped{false};
    auto stop_both = [&] {
        if (!stopped.exchange(true)) {
            local->shutdown();
            conn_->Shutdown();
        }
    };
    std::thread a([&] {
        pump(local, conn_->sc());
        stop_both();
    });
    std::thread b([&] {
        pump(conn_->sc(), local);
        stop_both();
    });
    a.join();
    b.join();
}

void Tunnel::Close() {
    if (conn_) {
        conn_->Close();
    }
}

}  // namespace rdcli::core
