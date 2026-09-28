#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

namespace rdcli::net {

struct Endpoint {
    std::string ip;  // binary: 4 bytes (IPv4) or 16 bytes (IPv6)
    uint16_t port = 0;
    bool valid() const { return port != 0; }
};

// Minimal blocking byte-stream abstraction (TCP socket). Returns >0 bytes read
// or written, 0 for EOF (read only), and <0 on error.
class Stream {
public:
    virtual ~Stream() = default;

    virtual int64_t read(uint8_t* buf, size_t n) = 0;
    virtual int64_t write(const uint8_t* buf, size_t n) = 0;
    virtual void close() = 0;

    // Unblocks a read or write in flight on another thread. Unlike close() it
    // leaves the descriptor valid, so the peer thread observes EOF instead of
    // racing against descriptor reuse. Default: no-op.
    virtual void shutdown() {}

    // Sets read/write timeouts (relative). A zero/negative timeout clears it.
    virtual bool set_timeout(std::chrono::milliseconds timeout) = 0;

    // Local socket address, for NAT hole punching.
    virtual Endpoint local_addr() const = 0;
};

}  // namespace rdcli::net

