#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "net/stream.h"
#include "proto/rendezvous.pb.h"

namespace rdcli::core {

constexpr const char* kDefaultRendezvousServer = "rs-ny.rustdesk.com:21116";

std::string normalize_server_addr(const std::string& server);

// Framed rendezvous-message I/O over a raw stream.
bool write_rendezvous_message(net::Stream* s, const hbb::RendezvousMessage& msg);
std::optional<hbb::RendezvousMessage> read_rendezvous_message(net::Stream* s);

struct OnlineResult {
    std::map<std::string, bool> online;
    std::chrono::milliseconds latency{0};
};

std::optional<OnlineResult> query_online(const std::string& server,
                                         const std::vector<std::string>& ids,
                                         std::chrono::milliseconds timeout);

std::optional<bool> check_online(const std::string& server, const std::string& peer_id,
                                 std::chrono::milliseconds timeout);

}  // namespace rdcli::core
