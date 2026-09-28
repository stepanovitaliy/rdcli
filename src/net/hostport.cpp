#include "net/socket.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace rdcli::net {

bool split_hostport(const std::string& addr, std::string* host, std::string* port) {
    // IPv6 literal: [::1]:port
    if (!addr.empty() && addr[0] == '[') {
        const size_t close = addr.find(']');
        if (close == std::string::npos || close + 1 >= addr.size() || addr[close + 1] != ':') {
            return false;
        }
        *host = addr.substr(1, close - 1);
        *port = addr.substr(close + 2);
        return true;
    }
    const size_t colon = addr.rfind(':');
    if (colon == std::string::npos) {
        return false;
    }
    // More than one colon without brackets is a bare IPv6 literal, not
    // host:port (mirrors Go net.SplitHostPort's "too many colons").
    if (addr.find(':') != colon) {
        return false;
    }
    *host = addr.substr(0, colon);
    *port = addr.substr(colon + 1);
    return true;
}

std::string normalize_hostport(const std::string& addr, const std::string& default_port) {
    std::string host, port;
    if (split_hostport(addr, &host, &port)) {
        return addr;
    }
    if (addr.find(':') != std::string::npos && addr[0] != '[') {
        // Bare IPv6 literal without port.
        return "[" + addr + "]:" + default_port;
    }
    return addr + ":" + default_port;
}

bool parse_port(const std::string& port, uint16_t* out) {
    if (port.empty() || port.size() > 5 ||
        !std::all_of(port.begin(), port.end(),
                     [](char c) { return std::isdigit(static_cast<unsigned char>(c)); })) {
        return false;
    }
    const unsigned long v = std::strtoul(port.c_str(), nullptr, 10);
    if (v == 0 || v > 65535) {
        return false;
    }
    *out = static_cast<uint16_t>(v);
    return true;
}

}  // namespace rdcli::net
