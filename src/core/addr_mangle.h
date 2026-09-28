#pragma once

#include <cstdint>
#include <string>

namespace rdcli::core {

// Encodes a socket address the way RustDesk does for hole-punch messages.
// `ip` is 4 bytes (IPv4) or 16 bytes (IPv6), `port` is the numeric port.
std::string encode_addr(const uint8_t* ip, size_t ip_len, uint16_t port);

// Decodes a mangled address. On success fills ip_out (must hold >=16 bytes),
// sets *ip_len_out (4 or 16) and *port_out. Returns false on invalid input.
bool decode_addr(const std::string& b, uint8_t* ip_out, size_t* ip_len_out, uint16_t* port_out);

}  // namespace rdcli::core
