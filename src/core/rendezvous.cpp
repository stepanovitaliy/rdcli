#include "core/rendezvous.h"

#include <algorithm>
#include <cstring>

#include "core/codec.h"
#include "net/socket.h"
#include "net/udp.h"

namespace rdcli::core {

namespace {

bool write_all(net::Stream* s, const std::string& data) {
    size_t written = 0;
    while (written < data.size()) {
        const int64_t n =
            s->write(reinterpret_cast<const uint8_t*>(data.data() + written),
                     data.size() - written);
        if (n <= 0) {
            return false;
        }
        written += static_cast<size_t>(n);
    }
    return true;
}

}  // namespace

std::string normalize_server_addr(const std::string& server) {
    if (server.empty()) {
        return kDefaultRendezvousServer;
    }
    return net::normalize_hostport(server, "21116");
}

bool write_rendezvous_message(net::Stream* s, const hbb::RendezvousMessage& msg) {
    const std::string data = msg.SerializeAsString();
    const std::string framed = encode(data);
    return write_all(s, framed);
}

std::optional<hbb::RendezvousMessage> read_rendezvous_message(net::Stream* s) {
    std::string read_buf;
    uint8_t tmp[4096];
    while (true) {
        auto frame = decode_frame(read_buf);
        if (frame) {
            hbb::RendezvousMessage msg;
            if (!msg.ParseFromString(*frame)) {
                return std::nullopt;
            }
            return msg;
        }
        const int64_t n = s->read(tmp, sizeof(tmp));
        if (n > 0) {
            read_buf.append(reinterpret_cast<const char*>(tmp), n);
        }
        if (n <= 0) {
            return std::nullopt;
        }
    }
}

namespace {

std::optional<std::pair<std::string, std::chrono::milliseconds>> query_online_udp(
    const std::string& host, uint16_t port_num, const std::string& data,
    std::chrono::milliseconds timeout) {
    auto udp_timeout = std::chrono::milliseconds(700);
    if (timeout.count() > 0 && timeout < udp_timeout) {
        udp_timeout = timeout;
    }
    const auto start = std::chrono::steady_clock::now();
    for (int attempt = 0; attempt < 2; attempt++) {
        auto resp = net::udp_send_recv(host, port_num, data, udp_timeout);
        if (!resp) {
            continue;
        }
        hbb::RendezvousMessage msg;
        if (!msg.ParseFromString(*resp) || !msg.has_online_response()) {
            continue;
        }
        const auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return std::make_pair(msg.online_response().states(), latency);
    }
    return std::nullopt;
}

std::optional<std::pair<std::string, std::chrono::milliseconds>> query_online_tcp(
    const std::string& addr, const std::string& framed, std::chrono::milliseconds timeout) {
    auto s = net::dial_tcp(addr, timeout);
    if (!s) {
        return std::nullopt;
    }
    if (timeout.count() > 0) {
        s->set_timeout(timeout);
    }
    const auto start = std::chrono::steady_clock::now();
    if (!write_all(s.get(), framed)) {
        return std::nullopt;
    }
    while (true) {
        auto msg = read_rendezvous_message(s.get());
        if (!msg) {
            return std::nullopt;
        }
        if (msg->has_online_response()) {
            const auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            return std::make_pair(msg->online_response().states(), latency);
        }
    }
}

}  // namespace
std::optional<OnlineResult> query_online(const std::string& server,
                                         const std::vector<std::string>& ids,
                                         std::chrono::milliseconds timeout) {
    OnlineResult result;
    for (const auto& id : ids) {
        result.online[id] = false;
    }
    if (ids.empty()) {
        return result;
    }

    const std::string addr = normalize_server_addr(server);
    std::string host, port;
    if (!net::split_hostport(addr, &host, &port)) {
        return std::nullopt;
    }

    uint16_t port_num = 0;
    if (!net::parse_port(port, &port_num) || port_num == 1) {
        return std::nullopt;
    }
    // hbbs answers OnlineRequest over UDP on the rendezvous port and over TCP
    // one port below it.
    const std::string tcp_port = std::to_string(port_num - 1);
    const std::string tcp_addr = net::normalize_hostport(host, tcp_port);

    hbb::RendezvousMessage req;
    for (const auto& id : ids) {
        req.mutable_online_request()->add_peers(id);
    }
    const std::string data = req.SerializeAsString();
    const std::string framed = encode(data);

    auto apply = [&](const std::string& states) {
        for (size_t i = 0; i < ids.size(); i++) {
            const size_t byte_idx = i / 8;
            if (byte_idx < states.size()) {
                const uint8_t bit = static_cast<uint8_t>(0x01 << (7 - (i % 8)));
                result.online[ids[i]] = (static_cast<uint8_t>(states[byte_idx]) & bit) != 0;
            }
        }
    };

    if (auto udp = query_online_udp(host, port_num, data, timeout)) {
        apply(udp->first);
        result.latency = udp->second;
        return result;
    }

    if (auto tcp = query_online_tcp(tcp_addr, framed, timeout)) {
        apply(tcp->first);
        result.latency = tcp->second;
        return result;
    }
    if (auto tcp2 = query_online_tcp(normalize_server_addr(server), framed, timeout)) {
        apply(tcp2->first);
        result.latency = tcp2->second;
        return result;
    }
    return std::nullopt;
}

std::optional<bool> check_online(const std::string& server, const std::string& peer_id,
                                 std::chrono::milliseconds timeout) {
    auto res = query_online(server, {peer_id}, timeout);
    if (!res) {
        return std::nullopt;
    }
    auto it = res->online.find(peer_id);
    if (it == res->online.end()) {
        return false;
    }
    return it->second;
}

}  // namespace rdcli::core


