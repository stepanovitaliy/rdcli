#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace rdcli::core {

// Variable-length little-endian framing, ported from hbb BytesCodec.
// Header: 1-4 bytes, bottom 2 bits = header length, remaining bits = payload
// length.
class BytesCodec {
public:
    bool raw = false;
    int max_packet_length = 0;

    // Encodes data into a framed buffer (or returns it verbatim in raw mode).
    std::string encode(const std::string& data) const;

    // Decodes one frame from the front of `src`; consumes it on success.
    std::optional<std::string> decode_frame(std::string& src) const;
};

std::string encode(const std::string& data);
std::optional<std::string> decode_frame(std::string& src);

}  // namespace rdcli::core
