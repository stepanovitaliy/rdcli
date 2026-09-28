#pragma once

#include <chrono>
#include <memory>
#include <optional>

#include "net/stream.h"
#include "proto/rendezvous.pb.h"

namespace rdcli::core {

// Determines local NAT behaviour (asymmetric vs symmetric) by comparing the
// server-observed source port on the rendezvous port and port-1.
std::optional<hbb::NatType> test_nat_type(const std::string& server,
                                          std::chrono::milliseconds timeout);

// TCP simultaneous-open hole punch. Falls back to a plain dial on failure.
std::unique_ptr<net::Stream> dial_punch(const net::Endpoint& local,
                                        const net::Endpoint& peer,
                                        std::chrono::milliseconds timeout);

// Formats a binary-IP endpoint as "a.b.c.d:port" or "[v6]:port".
std::string endpoint_to_string(const net::Endpoint& ep);

}  // namespace rdcli::core
