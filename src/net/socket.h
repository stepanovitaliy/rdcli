#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include "net/stream.h"

namespace rdcli::net {

// Connects a TCP stream to `addr` (host:port). Returns nullptr on failure.
std::unique_ptr<Stream> dial_tcp(const std::string& addr, std::chrono::milliseconds timeout);

struct DialOptions {
    bool reuse_addr = false;   // SO_REUSEADDR before connect
    std::string bind_ip;       // optional local IP to bind (4/16 bytes binary)
    uint16_t bind_port = 0;    // optional local port to bind
};

std::unique_ptr<Stream> dial_tcp_opts(const std::string& addr,
                                      std::chrono::milliseconds timeout,
                                      const DialOptions& opts);

// A TCP listener on the loopback interface (tunnel -L).
class Listener {
public:
    virtual ~Listener() = default;
    // Blocks until a client connects; nullptr once the listener has failed.
    virtual std::unique_ptr<Stream> accept() = 0;
};

// Binds and listens on 127.0.0.1:port. Returns nullptr on failure.
std::unique_ptr<Listener> listen_loopback(uint16_t port);

// Normalizes a bare host to host:default_port (mirrors Go JoinHostPort).
std::string normalize_hostport(const std::string& addr, const std::string& default_port);

// Splits a host:port string. Rejects bare IPv6 literals (use brackets), as
// Go's net.SplitHostPort does.
bool split_hostport(const std::string& addr, std::string* host, std::string* port);

// Parses a decimal port in 1..65535. Returns false instead of throwing.
bool parse_port(const std::string& port, uint16_t* out);

}  // namespace rdcli::net
