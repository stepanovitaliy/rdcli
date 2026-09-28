#include "core/nat.h"

#include <cstdio>
#include <cstring>

#include "core/codec.h"
#include "core/rendezvous.h"
#include "net/socket.h"

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

std::string ip_to_string(const std::string& ip) {
    if (ip.size() == 4) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                      static_cast<unsigned>(static_cast<uint8_t>(ip[0])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[1])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[2])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[3])));
        return buf;
    }
    if (ip.size() == 16) {
        char buf[64];
        std::snprintf(buf, sizeof(buf),
                      "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                      static_cast<unsigned>(static_cast<uint8_t>(ip[0])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[1])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[2])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[3])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[4])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[5])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[6])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[7])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[8])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[9])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[10])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[11])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[12])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[13])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[14])),
                      static_cast<unsigned>(static_cast<uint8_t>(ip[15])));
        return buf;
    }
    return {};
}

}  // namespace

std::string endpoint_to_string(const net::Endpoint& ep) {
    const std::string ip = ip_to_string(ep.ip);
    if (ip.empty()) {
        return {};
    }
    if (ep.ip.size() == 16) {
        return "[" + ip + "]:" + std::to_string(ep.port);
    }
    return ip + ":" + std::to_string(ep.port);
}

std::optional<hbb::NatType> test_nat_type(const std::string& server,
                                          std::chrono::milliseconds timeout) {
    const std::string addr = normalize_server_addr(server);
    std::string host, port;
    if (!net::split_hostport(addr, &host, &port)) {
        return std::nullopt;
    }
    uint16_t port_num = 0;
    if (!net::parse_port(port, &port_num) || port_num == 1) {
        return std::nullopt;
    }
    const std::string nat_port = std::to_string(port_num - 1);
    const std::string server2 = net::normalize_hostport(host, nat_port);

    hbb::RendezvousMessage req;
    req.mutable_test_nat_request();
    const std::string framed = encode(req.SerializeAsString());

    int32_t port1 = 0;
    int32_t port2 = 0;
    net::Endpoint local;
    for (int i = 0; i < 2; i++) {
        const std::string target = (i == 0) ? addr : server2;
        net::DialOptions dopts;
        dopts.reuse_addr = true;
        dopts.bind_ip = local.ip;
        dopts.bind_port = local.port;
        auto s = net::dial_tcp_opts(target, timeout, dopts);
        if (!s) {
            return std::nullopt;
        }
        if (timeout.count() > 0) {
            s->set_timeout(timeout);
        }
        if (i == 0) {
            local = s->local_addr();
        }
        if (!write_all(s.get(), framed)) {
            return std::nullopt;
        }
        auto msg = read_rendezvous_message(s.get());
        s->close();
        if (!msg || !msg->has_test_nat_response()) {
            return std::nullopt;
        }
        if (i == 0) {
            port1 = msg->test_nat_response().port();
        } else {
            port2 = msg->test_nat_response().port();
        }
    }
    if (port1 <= 0 || port2 <= 0) {
        return std::nullopt;
    }
    return port1 == port2 ? hbb::ASYMMETRIC : hbb::SYMMETRIC;
}

std::unique_ptr<net::Stream> dial_punch(const net::Endpoint& local, const net::Endpoint& peer,
                                        std::chrono::milliseconds timeout) {
    const std::string peer_addr = endpoint_to_string(peer);
    if (peer_addr.empty()) {
        return nullptr;
    }
    if (local.valid()) {
        net::DialOptions dopts;
        dopts.reuse_addr = true;
        dopts.bind_ip = local.ip;
        dopts.bind_port = local.port;
        auto s = net::dial_tcp_opts(peer_addr, timeout, dopts);
        if (s) {
            return s;
        }
    }
    return net::dial_tcp(peer_addr, timeout);
}

}  // namespace rdcli::core
