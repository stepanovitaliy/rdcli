#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace rdcli::net {

// Sends a single UDP datagram to host:port and returns the first reply, or
// nullopt on timeout/error.
std::optional<std::string> udp_send_recv(const std::string& host, uint16_t port,
                                         const std::string& payload,
                                         std::chrono::milliseconds timeout);

}  // namespace rdcli::net
