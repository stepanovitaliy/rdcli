#include "core/addr_mangle.h"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace rdcli::core {

namespace {

// Minimal 128-bit unsigned arithmetic, sufficient for the 82-bit address
// mangling used by RustDesk (portable across MSVC/GCC/Clang).
struct Uint128 {
    uint64_t lo = 0;
    uint64_t hi = 0;
};

Uint128 from_u64(uint64_t x) {
    Uint128 r;
    r.lo = x;
    return r;
}

Uint128 shl(const Uint128& a, int s) {
    if (s <= 0) {
        return a;
    }
    if (s >= 128) {
        return Uint128{};
    }
    Uint128 r;
    if (s >= 64) {
        r.hi = a.lo << (s - 64);
        r.lo = 0;
    } else {
        r.hi = (a.hi << s) | (a.lo >> (64 - s));
        r.lo = a.lo << s;
    }
    return r;
}

Uint128 shr(const Uint128& a, int s) {
    if (s <= 0) {
        return a;
    }
    if (s >= 128) {
        return Uint128{};
    }
    Uint128 r;
    if (s >= 64) {
        r.lo = a.hi >> (s - 64);
        r.hi = 0;
    } else {
        r.lo = (a.lo >> s) | (a.hi << (64 - s));
        r.hi = a.hi >> s;
    }
    return r;
}

Uint128 bit_or(const Uint128& a, const Uint128& b) {
    Uint128 r;
    r.lo = a.lo | b.lo;
    r.hi = a.hi | b.hi;
    return r;
}

Uint128 from_le_bytes(const std::string& b) {
    Uint128 r;
    const size_t n = std::min<size_t>(b.size(), 8);
    for (size_t i = 0; i < n; i++) {
        r.lo |= static_cast<uint64_t>(static_cast<uint8_t>(b[i])) << (8 * i);
    }
    if (b.size() > 8) {
        const size_t m = std::min<size_t>(b.size() - 8, 8);
        for (size_t i = 0; i < m; i++) {
            r.hi |= static_cast<uint64_t>(static_cast<uint8_t>(b[8 + i])) << (8 * i);
        }
    }
    return r;
}

void to_le16(const Uint128& a, uint8_t out[16]) {
    for (int i = 0; i < 8; i++) {
        out[i] = static_cast<uint8_t>((a.lo >> (8 * i)) & 0xFF);
        out[8 + i] = static_cast<uint8_t>((a.hi >> (8 * i)) & 0xFF);
    }
}

uint64_t unix_micros_low32() {
    using namespace std::chrono;
    const auto us = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
    return static_cast<uint64_t>(static_cast<uint32_t>(us));
}

}  // namespace

std::string encode_addr(const uint8_t* ip, size_t ip_len, uint16_t port) {
    if (ip_len == 4) {
        const uint64_t tm = unix_micros_low32();
        uint32_t ip_le = 0;
        for (int i = 0; i < 4; i++) {
            ip_le |= static_cast<uint32_t>(ip[i]) << (8 * i);
        }
        const uint64_t ipu = ip_le;
        const uint64_t pu = port;

        // v = (ip + tm) << 49 | tm << 17 | (port + (tm & 0xffff)). The three
        // parts occupy disjoint bit ranges, so bitwise OR is exact.
        const Uint128 part1 = shl(from_u64(ipu + tm), 49);
        const Uint128 part2 = shl(from_u64(tm), 17);
        const Uint128 part3 = from_u64(pu + (tm & 0xffff));
        const Uint128 v = bit_or(bit_or(part1, part2), part3);

        uint8_t buf[16];
        to_le16(v, buf);
        int len = 16;
        while (len > 0 && buf[len - 1] == 0) {
            len--;
        }
        return std::string(reinterpret_cast<char*>(buf), len);
    }

    // IPv6: raw 16 bytes + 2-byte little-endian port.
    std::string res(reinterpret_cast<const char*>(ip), 16);
    res.push_back(static_cast<char>(port & 0xFF));
    res.push_back(static_cast<char>((port >> 8) & 0xFF));
    return res;
}

bool decode_addr(const std::string& b, uint8_t* ip_out, size_t* ip_len_out, uint16_t* port_out) {
    if (b.size() > 16) {
        if (b.size() != 18) {
            return false;
        }
        std::memcpy(ip_out, b.data(), 16);
        *ip_len_out = 16;
        *port_out = static_cast<uint16_t>(static_cast<uint8_t>(b[16]) |
                                          (static_cast<uint8_t>(b[17]) << 8));
        return true;
    }

    const Uint128 number = from_le_bytes(b);
    const uint64_t tm = shr(number, 17).lo & 0xffffffffULL;
    const uint32_t ip = static_cast<uint32_t>(shr(number, 49).lo - tm);
    const uint64_t port = (number.lo & 0xffffffULL) - (tm & 0xffffULL);

    ip_out[0] = static_cast<uint8_t>(ip & 0xFF);
    ip_out[1] = static_cast<uint8_t>((ip >> 8) & 0xFF);
    ip_out[2] = static_cast<uint8_t>((ip >> 16) & 0xFF);
    ip_out[3] = static_cast<uint8_t>((ip >> 24) & 0xFF);
    *ip_len_out = 4;
    *port_out = static_cast<uint16_t>(port);
    return true;
}

}  // namespace rdcli::core
