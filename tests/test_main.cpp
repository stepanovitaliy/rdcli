#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>

#include <sodium.h>

#include "core/addr_mangle.h"
#include "core/codec.h"
#include "core/crypt.h"
#include "core/devices.h"
#include "core/secure.h"
#include "config/config.h"
#include "net/socket.h"
#include "net/stream.h"
#include "proto/message.pb.h"

#include <atomic>
#include <thread>

#if !defined(_WIN32)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

int failures = 0;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        if (!(cond)) {                                                                 \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                \
            failures++;                                                                \
        }                                                                              \
    } while (0)

#define CHECK_EQ(a, b)                                                                 \
    do {                                                                               \
        const auto va = (a);                                                           \
        const auto vb = (b);                                                           \
        if (!(va == vb)) {                                                             \
            std::printf("FAIL %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b);         \
            failures++;                                                                \
        }                                                                              \
    } while (0)

class MemoryStream : public rdcli::net::Stream {
public:
    int64_t read(uint8_t* buf, size_t n) override {
        if (pos_ >= data_.size()) {
            return 0;
        }
        const size_t c = std::min(n, data_.size() - pos_);
        std::memcpy(buf, data_.data() + pos_, c);
        pos_ += c;
        return static_cast<int64_t>(c);
    }
    int64_t write(const uint8_t* buf, size_t n) override {
        data_.append(reinterpret_cast<const char*>(buf), n);
        return static_cast<int64_t>(n);
    }
    void close() override {}
    bool set_timeout(std::chrono::milliseconds) override { return true; }
    rdcli::net::Endpoint local_addr() const override { return {}; }

private:
    std::string data_;
    size_t pos_ = 0;
};

std::array<uint8_t, 32> a32(const unsigned char* p) {
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), p, 32);
    return out;
}

void test_codec() {
    const size_t sizes[] = {0, 1, 63, 64, 16383, 16384, 4194303, 4194304, 1 << 20};
    for (const size_t size : sizes) {
        std::string payload(size, 'a');
        for (size_t i = 0; i < size; i++) {
            payload[i] = static_cast<char>('a' + (i % 26));
        }
        const std::string framed = rdcli::core::encode(payload);
        std::string src = framed;
        auto decoded = rdcli::core::decode_frame(src);
        CHECK(decoded.has_value());
        CHECK_EQ(*decoded, payload);
        CHECK(src.empty());
    }

    std::string stream;
    stream += rdcli::core::encode("one");
    stream += rdcli::core::encode("two");
    stream += rdcli::core::encode("three");
    CHECK_EQ(*rdcli::core::decode_frame(stream), std::string("one"));
    CHECK_EQ(*rdcli::core::decode_frame(stream), std::string("two"));
    CHECK_EQ(*rdcli::core::decode_frame(stream), std::string("three"));
    CHECK(stream.empty());
    CHECK(!rdcli::core::decode_frame(stream).has_value());
}

void test_addr_mangle() {
    {
        const uint8_t ip[4] = {192, 168, 1, 2};
        const std::string enc = rdcli::core::encode_addr(ip, 4, 1234);
        uint8_t out[16];
        size_t out_len = 0;
        uint16_t port = 0;
        CHECK(rdcli::core::decode_addr(enc, out, &out_len, &port));
        CHECK_EQ(out_len, static_cast<size_t>(4));
        CHECK_EQ(std::memcmp(out, ip, 4), 0);
        CHECK_EQ(port, static_cast<uint16_t>(1234));
    }
    {
        const uint8_t ip[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        const std::string enc = rdcli::core::encode_addr(ip, 16, 21117);
        CHECK_EQ(enc.size(), static_cast<size_t>(18));
        uint8_t out[16];
        size_t out_len = 0;
        uint16_t port = 0;
        CHECK(rdcli::core::decode_addr(enc, out, &out_len, &port));
        CHECK_EQ(out_len, static_cast<size_t>(16));
        CHECK_EQ(std::memcmp(out, ip, 16), 0);
        CHECK_EQ(port, static_cast<uint16_t>(21117));
    }
}

void test_crypt() {
    const auto a = rdcli::core::generate_keypair();
    const auto b = rdcli::core::generate_keypair();
    const auto s1 = rdcli::core::derive_shared_secret(a.priv, b.pub);
    const auto s2 = rdcli::core::derive_shared_secret(b.priv, a.pub);
    CHECK(s1 == s2);

    std::array<uint8_t, 32> key{};
    for (int i = 0; i < 32; i++) {
        key[i] = static_cast<uint8_t>(i);
    }
    rdcli::core::Encryptor enc(key);
    rdcli::core::Encryptor dec(key);
    const std::string plain = "hello secretbox";
    const std::string cipher = enc.encrypt(plain);
    CHECK(cipher != plain);
    const auto opened = dec.decrypt(cipher);
    CHECK(opened.has_value());
    CHECK_EQ(*opened, plain);

    std::string bad = cipher;
    bad[0] = static_cast<char>(bad[0] ^ 0xFF);
    CHECK(!dec.decrypt(bad).has_value());

    const auto digest = rdcli::core::sha256("abc");
    const uint8_t expected[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                                  0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                                  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                                  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    CHECK_EQ(std::memcmp(digest.data(), expected, 32), 0);

    const auto peer = rdcli::core::generate_keypair();
    const auto sym = rdcli::core::create_symmetric_key_msg(peer.pub);
    const auto opened_key = rdcli::core::decrypt_symmetric_key(sym.sym_sealed, sym.asym, peer.priv);
    CHECK(opened_key.has_value());
    CHECK(*opened_key == sym.key);
}

void test_verify_signed_id() {
    unsigned char ed_pk[32];
    unsigned char ed_sk[64];
    crypto_sign_keypair(ed_pk, ed_sk);

    hbb::IdPk idpk;
    idpk.set_id("123456789");
    idpk.set_pk(std::string(32, 'x'));
    const std::string msg = idpk.SerializeAsString();

    unsigned char sig[64];
    unsigned long long siglen = 0;
    crypto_sign_detached(sig, &siglen, reinterpret_cast<const unsigned char*>(msg.data()),
                         msg.size(), ed_sk);

    std::string blob(reinterpret_cast<char*>(sig), 64);
    blob += msg;

    const auto r = rdcli::core::verify_signed_id(blob, a32(ed_pk));
    CHECK(r.has_value());
    CHECK_EQ(r->id, std::string("123456789"));
    CHECK_EQ(r->pk.size(), static_cast<size_t>(32));

    unsigned char other_pk[32];
    unsigned char other_sk[64];
    crypto_sign_keypair(other_pk, other_sk);
    (void)other_sk;
    CHECK(!rdcli::core::verify_signed_id(blob, a32(other_pk)).has_value());
}

void test_secure() {
    {
        auto ms = std::make_unique<MemoryStream>();
        rdcli::core::SecureConn sc(std::move(ms));
        const std::string msg = "hello framed world";
        CHECK_EQ(sc.write(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()),
                 static_cast<int64_t>(msg.size()));
        uint8_t buf[128];
        const int64_t n = sc.read(buf, sizeof(buf));
        CHECK_EQ(n, static_cast<int64_t>(msg.size()));
        CHECK_EQ(std::string(reinterpret_cast<char*>(buf), n), msg);
    }

    {
        auto ms = std::make_unique<MemoryStream>();
        rdcli::core::SecureConn sc(std::move(ms));
        std::array<uint8_t, 32> key{};
        for (int i = 0; i < 32; i++) {
            key[i] = static_cast<uint8_t>(255 - i);
        }
        sc.set_key(key);
        CHECK(sc.is_secured());

        const std::string msg = "encrypted payload";
        CHECK_EQ(sc.write(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()),
                 static_cast<int64_t>(msg.size()));
        uint8_t buf[128];
        const int64_t n = sc.read(buf, sizeof(buf));
        CHECK_EQ(n, static_cast<int64_t>(msg.size()));
        CHECK_EQ(std::string(reinterpret_cast<char*>(buf), n), msg);
    }

    {
        auto ms = std::make_unique<MemoryStream>();
        rdcli::core::SecureConn sc(std::move(ms));
        const std::string msg = "a message";
        sc.write(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
        const auto got = sc.read_message();
        CHECK(got.has_value());
        CHECK_EQ(*got, msg);
    }
}

void test_config() {
#if !defined(_WIN32)
    const char* tmp = "/tmp/rdcli_test_config.toml";
    ::setenv("RDC_CONFIG", tmp, 1);
    std::remove(tmp);

    rdcli::config::Config cfg;
    std::string err;
    CHECK(cfg.load(&err));
    cfg.set_peers_password("123456789", "secret");
    cfg.peers["123456789"].name = "home-pc";
    cfg.add_tag("123456789", "work");
    cfg.add_tag("123456789", "prod");
    CHECK(cfg.save(&err));

    rdcli::config::Config cfg2;
    CHECK(cfg2.load(&err));
    CHECK_EQ(cfg2.password_for_peer("123456789"), std::string("secret"));
    CHECK_EQ(cfg2.peers["123456789"].name, std::string("home-pc"));
    CHECK_EQ(cfg2.tags_for("123456789").size(), static_cast<size_t>(2));

    // Regression: config.toml holds machine passwords and an access token, so
    // it must land owner-only (0600), not whatever the process umask allows.
    struct stat st {};
    CHECK(::stat(tmp, &st) == 0);
    CHECK_EQ(static_cast<int>(st.st_mode & 0777), 0600);

    // Regression: save() used to truncate and rewrite an existing
    // config.toml.tmp, so anyone holding it open (e.g. opened while an earlier
    // save left it world-readable) would read the new secrets through it.
    const std::string stale = std::string(tmp) + ".tmp";
    {
        std::FILE* f = std::fopen(stale.c_str(), "w");
        CHECK(f != nullptr);
        if (f) {
            std::fputs("stale", f);
            std::fclose(f);
        }
    }
    ::chmod(stale.c_str(), 0644);
    const int held = ::open(stale.c_str(), O_RDONLY);
    CHECK(held >= 0);
    cfg.set_peers_password("123456789", "secret2");
    CHECK(cfg.save(&err));
    char got[256] = {};
    const ssize_t rn = held >= 0 ? ::pread(held, got, sizeof(got) - 1, 0) : -1;
    if (held >= 0) {
        ::close(held);
    }
    CHECK_EQ(std::string(got, rn > 0 ? static_cast<size_t>(rn) : 0), std::string("stale"));
    CHECK(::stat(tmp, &st) == 0);
    CHECK_EQ(static_cast<int>(st.st_mode & 0777), 0600);
    rdcli::config::Config cfg3;
    CHECK(cfg3.load(&err));
    CHECK_EQ(cfg3.password_for_peer("123456789"), std::string("secret2"));

    std::remove(tmp);
#endif
}

// Conn::Close() relies on this: shutdown() must wake a read blocked on another
// thread, leaving the descriptor open until the stream is destroyed.
void test_shutdown_wakes_reader() {
#if !defined(_WIN32)
    const int ls = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(ls >= 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(::bind(ls, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0);
    CHECK(::listen(ls, 1) == 0);
    socklen_t len = sizeof(sa);
    CHECK(::getsockname(ls, reinterpret_cast<sockaddr*>(&sa), &len) == 0);

    auto s = rdcli::net::dial_tcp("127.0.0.1:" + std::to_string(ntohs(sa.sin_port)),
                                  std::chrono::seconds(2));
    CHECK(s != nullptr);
    const int peer = s ? ::accept(ls, nullptr, nullptr) : -1;
    if (s && peer >= 0) {
        std::atomic<bool> woke{false};
        std::atomic<int64_t> got{-2};
        std::thread reader([&] {
            uint8_t b[16];
            got = s->read(b, sizeof(b));
            woke = true;
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        s->shutdown();
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (!woke && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        CHECK(woke.load());
        if (woke) {
            reader.join();
            CHECK_EQ(got.load(), static_cast<int64_t>(0));
        } else {
            reader.detach();  // stuck in recv; the process exits after the report
            (void)s.release();  // the detached reader still uses it
        }
    }
    if (peer >= 0) {
        ::close(peer);
    }
    ::close(ls);
#endif
}

void test_hostport() {
    std::string host, port;

    CHECK(rdcli::net::split_hostport("example.com:21116", &host, &port));
    CHECK_EQ(host, std::string("example.com"));
    CHECK_EQ(port, std::string("21116"));

    CHECK(rdcli::net::split_hostport("[::1]:21116", &host, &port));
    CHECK_EQ(host, std::string("::1"));
    CHECK_EQ(port, std::string("21116"));

    // Regression: a bare IPv6 literal (no brackets) has more than one colon
    // and must be rejected, exactly like Go's net.SplitHostPort — otherwise
    // rfind(':') slices it into a bogus host/port pair.
    CHECK(!rdcli::net::split_hostport("::1", &host, &port));
    CHECK(!rdcli::net::split_hostport("fe80::1:2:3", &host, &port));

    CHECK_EQ(rdcli::net::normalize_hostport("example.com", "21116"),
            std::string("example.com:21116"));
    CHECK_EQ(rdcli::net::normalize_hostport("example.com:9999", "21116"),
            std::string("example.com:9999"));
    CHECK_EQ(rdcli::net::normalize_hostport("::1", "21116"), std::string("[::1]:21116"));

    uint16_t p = 0;
    CHECK(rdcli::net::parse_port("21116", &p));
    CHECK_EQ(p, static_cast<uint16_t>(21116));
    CHECK(rdcli::net::parse_port("65535", &p));
    CHECK_EQ(p, static_cast<uint16_t>(65535));

    // Regression: these used to reach std::stoul and throw std::invalid_argument
    // (or std::out_of_range), aborting the whole process on a malformed --server.
    CHECK(!rdcli::net::parse_port("", &p));
    CHECK(!rdcli::net::parse_port("notaport", &p));
    CHECK(!rdcli::net::parse_port("0", &p));
    CHECK(!rdcli::net::parse_port("65536", &p));
    CHECK(!rdcli::net::parse_port("999999999999999999999", &p));
    CHECK(!rdcli::net::parse_port("-1", &p));
}

void test_devices_local() {
    rdcli::config::Config cfg;
    cfg.set_peers_password("111111111", "pw");
    cfg.peers["111111111"].name = "alpha";
    cfg.add_tag("111111111", "prod");

    std::string err;
    auto src = rdcli::core::NewDeviceSource(&cfg, &err);
    CHECK(src != nullptr);
    std::vector<rdcli::core::Device> devs;
    CHECK(src->List(&devs, &err));
    CHECK_EQ(devs.size(), static_cast<size_t>(1));
    CHECK_EQ(devs[0].id, std::string("111111111"));
    CHECK_EQ(devs[0].source, std::string("local"));
    CHECK_EQ(devs[0].name, std::string("alpha"));

    auto tags = src->Tags("111111111");
    CHECK_EQ(tags.size(), static_cast<size_t>(1));
    CHECK_EQ(tags[0], std::string("prod"));
}

}  // namespace

int main() {
    if (sodium_init() < 0) {
        std::printf("sodium_init failed\n");
        return 1;
    }
    test_codec();
    test_addr_mangle();
    test_crypt();
    test_verify_signed_id();
    test_secure();
    test_config();
    test_shutdown_wakes_reader();
    test_hostport();
    test_devices_local();

    if (failures == 0) {
        std::printf("ALL TESTS PASSED\n");
        return 0;
    }
    std::printf("%d CHECK(S) FAILED\n", failures);
    return 1;
}
