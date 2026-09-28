#include "core/codec.h"

#include <stdexcept>

namespace rdcli::core {

std::string BytesCodec::encode(const std::string& data) const {
    if (raw) {
        return data;
    }
    const uint64_t length = data.size();
    std::string out;
    if (length <= 0x3F) {
        out.push_back(static_cast<char>(length << 2));
    } else if (length <= 0x3FFF) {
        const uint16_t h = static_cast<uint16_t>((length << 2) | 0x1);
        out.push_back(static_cast<char>(h & 0xFF));
        out.push_back(static_cast<char>((h >> 8) & 0xFF));
    } else if (length <= 0x3FFFFF) {
        const uint32_t h = static_cast<uint32_t>((length << 2) | 0x2);
        out.push_back(static_cast<char>(h & 0xFF));
        out.push_back(static_cast<char>((h >> 8) & 0xFF));
        out.push_back(static_cast<char>((h >> 16) & 0xFF));
    } else if (length <= 0x3FFFFFFF) {
        const uint32_t h = static_cast<uint32_t>((length << 2) | 0x3);
        for (int i = 0; i < 4; i++) {
            out.push_back(static_cast<char>((h >> (8 * i)) & 0xFF));
        }
    } else {
        throw std::length_error("hbb: payload length exceeds maximum limit (0x3FFFFFFF)");
    }
    out.append(data);
    return out;
}

std::optional<std::string> BytesCodec::decode_frame(std::string& src) const {
    if (src.empty()) {
        return std::nullopt;
    }
    if (raw) {
        std::string data = std::move(src);
        src.clear();
        return data;
    }

    const int head_len = (static_cast<uint8_t>(src[0]) & 0x3) + 1;
    if (static_cast<int>(src.size()) < head_len) {
        return std::nullopt;
    }

    uint32_t n = 0;
    switch (head_len) {
    case 1:
        n = static_cast<uint8_t>(src[0]);
        break;
    case 2:
        n = static_cast<uint8_t>(src[0]) | (static_cast<uint8_t>(src[1]) << 8);
        break;
    case 3:
        n = static_cast<uint8_t>(src[0]) | (static_cast<uint8_t>(src[1]) << 8) |
            (static_cast<uint8_t>(src[2]) << 16);
        break;
    case 4:
        n = static_cast<uint8_t>(src[0]) | (static_cast<uint8_t>(src[1]) << 8) |
            (static_cast<uint8_t>(src[2]) << 16) | (static_cast<uint32_t>(src[3]) << 24);
        break;
    }

    const int payload_len = static_cast<int>(n >> 2);
    if (max_packet_length > 0 && payload_len > max_packet_length) {
        return std::nullopt;
    }

    const size_t total = static_cast<size_t>(head_len) + static_cast<size_t>(payload_len);
    if (src.size() < total) {
        return std::nullopt;
    }

    std::string frame(src.data() + head_len, payload_len);
    src.erase(0, total);
    return frame;
}

std::string encode(const std::string& data) {
    return BytesCodec{}.encode(data);
}

std::optional<std::string> decode_frame(std::string& src) {
    return BytesCodec{}.decode_frame(src);
}

}  // namespace rdcli::core
