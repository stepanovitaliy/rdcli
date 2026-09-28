#include "core/conn.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include <sodium.h>

#if defined(_WIN32)
#include <windows.h>
#undef RGB  // wingdi.h macro clashes with the protobuf message hbb::RGB
#endif

#include "core/addr_mangle.h"
#include "core/codec.h"
#include "core/nat.h"
#include "core/rendezvous.h"
#include "net/socket.h"

namespace rdcli::core {

namespace {

constexpr int kPunchMaxTry = 3;

#if defined(_WIN32)
constexpr const char* kPlatform = "Windows";
#elif defined(__APPLE__)
constexpr const char* kPlatform = "macOS";
#else
constexpr const char* kPlatform = "Linux";
#endif

std::array<uint8_t, 32> a32(const std::string& s) {
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), s.data(), std::min<size_t>(s.size(), out.size()));
    return out;
}

std::array<uint8_t, 32> a32(const uint8_t* p) {
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), p, out.size());
    return out;
}

std::string as_string(const std::array<uint8_t, 32>& a) {
    return std::string(reinterpret_cast<const char*>(a.data()), a.size());
}

std::chrono::milliseconds min_duration(std::chrono::milliseconds a,
                                       std::chrono::milliseconds b) {
    return a < b ? a : b;
}

std::string rendezvous_host(const std::string& server) {
    const std::string s = normalize_server_addr(server);
    std::string host, port;
    if (net::split_hostport(s, &host, &port)) {
        return host;
    }
    return s;
}

std::string normalize_relay(const std::string& server) {
    return net::normalize_hostport(server, "21117");
}

std::optional<std::string> base64_decode(const std::string& in) {
    std::string out(in.size(), '\0');
    size_t out_len = 0;
    if (sodium_base642bin(reinterpret_cast<unsigned char*>(out.data()), out.size(), in.data(),
                          in.size(), nullptr, &out_len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        return std::nullopt;
    }
    out.resize(out_len);
    return out;
}

std::optional<std::array<uint8_t, 32>> decode_rs_key(const std::string& key) {
    const std::string k = key.empty() ? std::string(kRsPubKey) : key;
    auto pk = base64_decode(k);
    if (!pk || pk->size() != 32) {
        return std::nullopt;
    }
    return a32(reinterpret_cast<const uint8_t*>(pk->data()));
}

std::string new_uuid() {
    std::array<uint8_t, 16> b{};
    randombytes_buf(b.data(), b.size());
    b[6] = static_cast<uint8_t>((b[6] & 0x0f) | 0x40);
    b[8] = static_cast<uint8_t>((b[8] & 0x3f) | 0x80);
    char buf[40];
    std::snprintf(buf, sizeof(buf),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
                  b[12], b[13], b[14], b[15]);
    return buf;
}

std::string random_peer_id() {
    std::array<uint8_t, 9> b{};
    randombytes_buf(b.data(), b.size());
    std::string out;
    out.reserve(9);
    for (uint8_t c : b) {
        out.push_back(static_cast<char>('0' + (c % 10)));
    }
    return out;
}

}  // namespace
namespace {

std::string machine_uuid() {
#if defined(_WIN32)
    // RustDesk (machine_uid crate) keys local secrets with MachineGuid.
    wchar_t buf[128];
    DWORD size = sizeof(buf);
    if (::RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
                       RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, buf, &size) != ERROR_SUCCESS) {
        return {};
    }
    std::string out;
    for (const wchar_t* p = buf; *p != L'\0'; p++) {
        out.push_back(static_cast<char>(*p));  // GUID text is ASCII
    }
    return out;
#elif defined(__APPLE__)
    FILE* f = ::popen("ioreg -rd1 -c IOPlatformExpertDevice", "r");
    if (f == nullptr) {
        return {};
    }
    std::string output;
    char buf[4096];
    while (std::fgets(buf, sizeof(buf), f) != nullptr) {
        output += buf;
    }
    ::pclose(f);
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        const auto pos = line.find("\"IOPlatformUUID\"");
        if (pos == std::string::npos) {
            continue;
        }
        const auto eq = line.find('=', pos);
        if (eq == std::string::npos) {
            continue;
        }
        std::string u = line.substr(eq + 1);
        const auto first = u.find_first_not_of(" \t\"");
        if (first != std::string::npos) {
            u.erase(0, first);
        }
        const auto end = u.find('"');
        if (end != std::string::npos) {
            u = u.substr(0, end);
        }
        if (!u.empty()) {
            return u;
        }
    }
    return {};
#else
    std::ifstream f("/etc/machine-id");
    if (!f.is_open()) {
        return {};
    }
    std::string id;
    std::getline(f, id);
    return id;
#endif
}

std::optional<std::string> decrypt_h1_blob(const std::string& b64, const std::string& machine_id) {
    if (machine_id.empty()) {
        return std::nullopt;
    }
    auto payload = base64_decode(b64);
    if (!payload) {
        return std::nullopt;
    }
    std::array<uint8_t, 32> key{};
    std::memcpy(key.data(), machine_id.data(), std::min<size_t>(machine_id.size(), key.size()));
    // Classic symmetric_crypt layout (Windows GUI): secretbox with an all-zero
    // nonce and no version byte, so the payload is just MAC(16) || h1(32).
    if (payload->size() == 16 + 32) {
        if (auto h1 = secretbox_open(*payload, std::array<uint8_t, 24>{}, key)) {
            return h1;
        }
    }
    if (payload->size() < 1 + 24 + 16 || (*payload)[0] != 1) {
        return std::nullopt;
    }
    std::array<uint8_t, 24> nonce{};
    std::memcpy(nonce.data(), payload->data() + 1, 24);
    return secretbox_open(payload->substr(25), nonce, key);
}

std::string h1_for_password(const std::string& password, const std::string& salt) {
    if (password.size() > 2 && password[0] == '0' && password[1] == '0') {
        auto h1 = decrypt_h1_blob(password.substr(2), machine_uuid());
        if (h1 && h1->size() == 32) {
            return *h1;
        }
    }
    return as_string(sha256(password + salt));
}

std::string hash_password(const std::string& password, const std::string& salt,
                          const std::string& challenge) {
    return as_string(sha256(h1_for_password(password, salt) + challenge));
}

bool is_ipv4_literal(const std::string& s) {
    int dots = 0;
    for (char c : s) {
        if (c == '.') {
            dots++;
        } else if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return dots == 3 && !s.empty();
}

bool is_ipv6_literal(const std::string& s) {
    if (s.find(':') == std::string::npos) {
        return false;
    }
    for (char c : s) {
        if (std::isxdigit(static_cast<unsigned char>(c)) || c == ':') {
            continue;
        }
        return false;
    }
    return true;
}

bool is_direct_ip(const std::string& peer) {
    std::string host, port;
    if (net::split_hostport(peer, &host, &port)) {
        if (!std::all_of(port.begin(), port.end(),
                         [](char c) { return std::isdigit(static_cast<unsigned char>(c)); })) {
            return false;
        }
        return is_ipv4_literal(host) || is_ipv6_literal(host);
    }
    return is_ipv4_literal(peer) || is_ipv6_literal(peer);
}

std::array<int, 3> parse_version(const std::string& v) {
    std::array<int, 3> out{0, 0, 0};
    const std::string main = v.substr(0, v.find('-'));
    std::istringstream iss(main);
    std::string part;
    for (int i = 0; i < 3 && std::getline(iss, part, '.'); i++) {
        out[i] = std::atoi(part.c_str());
    }
    return out;
}

}  // namespace



namespace {

std::optional<std::string> verify_signed_blob(const std::string& blob,
                                              const std::array<uint8_t, 32>& ed_pub) {
    if (blob.size() <= 64) {
        return std::nullopt;
    }
    const std::string sig = blob.substr(0, 64);
    const std::string msg = blob.substr(64);
    if (!verify_signature(sig, msg, ed_pub)) {
        return std::nullopt;
    }
    return msg;
}

bool write_rendezvous_secure(SecureConn* sc, const hbb::RendezvousMessage& msg) {
    const std::string data = msg.SerializeAsString();
    return sc->write(reinterpret_cast<const uint8_t*>(data.data()), data.size()) ==
           static_cast<int64_t>(data.size());
}

std::optional<hbb::RendezvousMessage> read_rendezvous_secure(SecureConn* sc) {
    auto raw = sc->read_message();
    if (!raw) {
        return std::nullopt;
    }
    hbb::RendezvousMessage msg;
    if (!msg.ParseFromString(*raw)) {
        return std::nullopt;
    }
    return msg;
}

std::unique_ptr<SecureConn> secure_tcp(std::unique_ptr<net::Stream> conn,
                                       const std::string& server_key, std::string* err) {
    auto rs_pk = decode_rs_key(server_key);
    if (!rs_pk) {
        *err = "hbb: invalid server public key";
        return nullptr;
    }
    auto msg = read_rendezvous_message(conn.get());
    if (!msg) {
        *err = "hbb: read key exchange";
        return nullptr;
    }
    if (!msg->has_key_exchange() || msg->key_exchange().keys_size() != 1) {
        *err = "hbb: expected key exchange from rendezvous";
        return nullptr;
    }
    auto pk = verify_signed_blob(msg->key_exchange().keys(0), *rs_pk);
    if (!pk || pk->size() != 32) {
        *err = "hbb: invalid key exchange key";
        return nullptr;
    }
    auto sym = create_symmetric_key_msg(a32(reinterpret_cast<const uint8_t*>(pk->data())));
    hbb::RendezvousMessage resp;
    resp.mutable_key_exchange()->add_keys(as_string(sym.asym));
    resp.mutable_key_exchange()->add_keys(sym.sym_sealed);
    if (!write_rendezvous_message(conn.get(), resp)) {
        *err = "hbb: send key exchange response";
        return nullptr;
    }
    auto sc = std::make_unique<SecureConn>(std::move(conn));
    sc->set_key(sym.key);
    return sc;
}

struct PunchResult {
    net::Endpoint peer_addr;
    std::string signed_id_pk;
    std::string relay_server;
    hbb::NatType nat_type = hbb::UNKNOWN_NAT;
    bool is_local = false;
    std::string uuid;
    net::Endpoint local_addr;
};

std::chrono::milliseconds connect_timeout(const PunchResult& pr,
                                          std::chrono::milliseconds timeout) {
    if (pr.is_local || pr.nat_type == hbb::SYMMETRIC) {
        return min_duration(std::chrono::milliseconds(3000), timeout);
    }
    return min_duration(std::chrono::milliseconds(12000), timeout);
}

}  // namespace


namespace {

std::optional<PunchResult> punch(const DialOpts& opts, std::chrono::milliseconds timeout,
                                std::string* err) {
    PunchResult res;
    if (opts.force_relay) {
        return res;
    }

    const std::string addr = normalize_server_addr(opts.server);
    std::string last_err;

    hbb::NatType nat_type = hbb::UNKNOWN_NAT;
    if (auto nt = test_nat_type(opts.server, min_duration(timeout, std::chrono::seconds(1)))) {
        nat_type = *nt;
    }

    for (int i = 0; i < kPunchMaxTry; i++) {
        auto conn = net::dial_tcp(addr, timeout);
        if (!conn) {
            last_err = "hbb: connect rendezvous";
            continue;
        }
        if (timeout.count() > 0) {
            conn->set_timeout(timeout);
        }
        res.local_addr = conn->local_addr();

        hbb::RendezvousMessage req;
        auto* ph = req.mutable_punch_hole_request();
        ph->set_id(opts.peer_id);
        ph->set_nat_type(nat_type);
        ph->set_licence_key(opts.key);
        ph->set_token(opts.token);
        ph->set_conn_type(opts.conn_type);
        ph->set_force_relay(opts.force_relay);
        ph->set_version(kVersion);

        std::unique_ptr<SecureConn> sc;
        net::Stream* raw = conn.get();
        if (!opts.token.empty()) {
            sc = secure_tcp(std::move(conn), opts.key, err);
            if (!sc) {
                last_err = *err;
                continue;
            }
            raw = nullptr;
        }

        bool ok = sc ? write_rendezvous_secure(sc.get(), req)
                     : write_rendezvous_message(raw, req);
        if (!ok) {
            last_err = "hbb: send punch request";
            continue;
        }

        for (int j = 0; j < 5; j++) {
            std::optional<hbb::RendezvousMessage> msg =
                sc ? read_rendezvous_secure(sc.get()) : read_rendezvous_message(raw);
            if (!msg) {
                last_err = "hbb: read punch response";
                break;
            }
            switch (msg->union_case()) {
            case hbb::RendezvousMessage::kPunchHoleResponse: {
                const auto& phr = msg->punch_hole_response();
                if (!phr.socket_addr().empty()) {
                    uint8_t ip[16];
                    size_t ip_len = 0;
                    uint16_t port = 0;
                    if (decode_addr(phr.socket_addr(), ip, &ip_len, &port)) {
                        res.peer_addr.ip.assign(reinterpret_cast<char*>(ip), ip_len);
                        res.peer_addr.port = port;
                    }
                    res.signed_id_pk = phr.pk();
                    res.relay_server = phr.relay_server();
                    if (phr.has_nat_type()) {
                        res.nat_type = phr.nat_type();
                    }
                    res.is_local = phr.has_is_local() && phr.is_local();
                    return res;
                }
                if (!phr.other_failure().empty()) {
                    *err = phr.other_failure();
                    return std::nullopt;
                }
                switch (phr.failure()) {
                case hbb::PunchHoleResponse_Failure_ID_NOT_EXIST:
                    *err = "id does not exist";
                    return std::nullopt;
                case hbb::PunchHoleResponse_Failure_OFFLINE:
                    *err = "remote desktop is offline";
                    return std::nullopt;
                case hbb::PunchHoleResponse_Failure_LICENSE_MISMATCH:
                    *err = "key mismatch";
                    return std::nullopt;
                case hbb::PunchHoleResponse_Failure_LICENSE_OVERUSE:
                    *err = "key overuse";
                    return std::nullopt;
                default:
                    break;
                }
                last_err = "punch hole failed";
                break;
            }
            case hbb::RendezvousMessage::kRelayResponse: {
                const auto& rr = msg->relay_response();
                res.relay_server = rr.relay_server();
                res.signed_id_pk = rr.pk();
                res.uuid = rr.uuid();
                if (!rr.refuse_reason().empty()) {
                    *err = rr.refuse_reason();
                    return std::nullopt;
                }
                return res;
            }
            case hbb::RendezvousMessage::kKeyExchange:
                continue;
            default:
                last_err = "hbb: unexpected rendezvous message";
                break;
            }
        }
    }
    if (last_err.empty()) {
        last_err = "no response from rendezvous server";
    }
    *err = last_err;
    return std::nullopt;
}

}  // namespace


namespace {

struct RelayTarget {
    std::string relay_server;
    std::string uuid;
    std::string pk;
};

std::optional<RelayTarget> request_relay_via_rendezvous(const DialOpts& opts,
                                                        const std::string& want_relay,
                                                        std::chrono::milliseconds timeout,
                                                        std::string* err) {
    const std::string addr = normalize_server_addr(opts.server);
    auto conn = net::dial_tcp(addr, timeout);
    if (!conn) {
        *err = "hbb: connect rendezvous";
        return std::nullopt;
    }
    if (timeout.count() > 0) {
        conn->set_timeout(timeout);
    }
    const std::string uuid = new_uuid();
    hbb::RendezvousMessage req;
    auto* rr = req.mutable_request_relay();
    rr->set_id(opts.peer_id);
    rr->set_uuid(uuid);
    rr->set_relay_server(want_relay);
    rr->set_licence_key(opts.key);
    rr->set_token(opts.token);
    rr->set_conn_type(hbb::DEFAULT_CONN);

    std::unique_ptr<SecureConn> sc;
    net::Stream* raw = conn.get();
    if (!opts.token.empty()) {
        sc = secure_tcp(std::move(conn), opts.key, err);
        if (!sc) {
            return std::nullopt;
        }
        raw = nullptr;
    }

    bool ok = sc ? write_rendezvous_secure(sc.get(), req)
                 : write_rendezvous_message(raw, req);
    if (!ok) {
        *err = "hbb: send relay request";
        return std::nullopt;
    }
    for (int i = 0; i < 12; i++) {
        auto msg = sc ? read_rendezvous_secure(sc.get()) : read_rendezvous_message(raw);
        if (!msg) {
            break;
        }
        if (!msg->has_relay_response()) {
            continue;
        }
        const auto& resp = msg->relay_response();
        if (!resp.refuse_reason().empty()) {
            *err = resp.refuse_reason();
            return std::nullopt;
        }
        RelayTarget t;
        t.relay_server = resp.relay_server().empty() ? want_relay : resp.relay_server();
        t.uuid = resp.uuid().empty() ? uuid : resp.uuid();
        t.pk = resp.pk();
        return t;
    }
    *err = "timeout waiting for relay response";
    return std::nullopt;
}

std::unique_ptr<SecureConn> connect_relay(const std::string& relay_server,
                                          const DialOpts& opts, const std::string& uuid,
                                          std::chrono::milliseconds timeout, std::string* err) {
    const std::string addr = normalize_relay(relay_server);
    auto conn = net::dial_tcp(addr, timeout);
    if (!conn) {
        *err = "hbb: connect relay server";
        return nullptr;
    }
    if (timeout.count() > 0) {
        conn->set_timeout(timeout);
    }
    hbb::RendezvousMessage req;
    auto* rr = req.mutable_request_relay();
    rr->set_id(opts.peer_id);
    rr->set_uuid(uuid);
    rr->set_licence_key(opts.key);
    rr->set_conn_type(opts.conn_type);
    if (!write_rendezvous_message(conn.get(), req)) {
        *err = "hbb: send relay request";
        return nullptr;
    }
    return std::make_unique<SecureConn>(std::move(conn));
}

}  // namespace


Conn::~Conn() { Close(); }

std::unique_ptr<Conn> Conn::Connect(const DialOpts& opts, std::string* err) {
    std::chrono::milliseconds timeout = opts.timeout;
    if (timeout.count() <= 0) {
        timeout = std::chrono::milliseconds(10000);
    }

    if (is_direct_ip(opts.peer_id)) {
        if (!opts.yes) {
            *err = "insecure direct connection to " + opts.peer_id + " requires --yes";
            return nullptr;
        }
        std::string addr = opts.peer_id;
        std::string host, port;
        if (!net::split_hostport(addr, &host, &port)) {
            addr = net::normalize_hostport(addr, "21116");
        }
        auto conn = net::dial_tcp(addr, timeout);
        if (!conn) {
            *err = "hbb: direct connect";
            return nullptr;
        }
        if (timeout.count() > 0) {
            conn->set_timeout(timeout);
        }
        auto c = std::make_unique<Conn>();
        c->sc_ = std::make_unique<SecureConn>(std::move(conn));
        c->opts_ = opts;
        c->peer_id_ = opts.peer_id;
        c->direct_ = true;
        if (!c->secure_handshake({}, opts.key, err)) {
            return nullptr;
        }
        return c;
    }

    auto pr = punch(opts, timeout, err);
    if (!pr) {
        return nullptr;
    }

    std::unique_ptr<SecureConn> sc;
    if (!opts.force_relay && pr->peer_addr.valid()) {
        const auto ct = connect_timeout(*pr, timeout);
        auto conn = dial_punch(pr->local_addr, pr->peer_addr, ct);
        if (conn) {
            // The TCP dial can succeed against a NAT/firewall that never
            // forwards to the peer; bound the handshake (login clears the
            // timeout) and fall back to relay if it doesn't complete.
            conn->set_timeout(ct);
            auto c = std::make_unique<Conn>();
            c->sc_ = std::make_unique<SecureConn>(std::move(conn));
            c->opts_ = opts;
            c->peer_id_ = opts.peer_id;
            c->direct_ = true;
            std::string herr;
            if (c->secure_handshake(pr->signed_id_pk, opts.key, &herr)) {
                return c;
            }
            if (std::getenv("RDC_DEBUG") != nullptr) {
                std::fprintf(stderr, "hbb debug: direct punch failed: %s\n", herr.c_str());
            }
        }
    }

    std::string relay_server = pr->relay_server;
    std::string uuid = pr->uuid;
    std::string signed_id_pk = pr->signed_id_pk;
    if (uuid.empty()) {
        std::string want_relay = relay_server;
        if (want_relay.empty()) {
            want_relay = rendezvous_host(opts.server);
        }
        if (std::getenv("RDC_DEBUG") != nullptr) {
            std::fprintf(stderr, "hbb debug: requesting relay via rendezvous (relay=%s)\n",
                         want_relay.c_str());
        }
        auto t = request_relay_via_rendezvous(opts, want_relay, timeout, err);
        if (!t) {
            if (std::getenv("RDC_DEBUG") != nullptr) {
                std::fprintf(stderr, "hbb debug: relay request failed: %s\n", err->c_str());
            }
            return nullptr;
        }
        if (!t->relay_server.empty()) {
            relay_server = t->relay_server;
        }
        uuid = t->uuid;
        if (!t->pk.empty()) {
            signed_id_pk = t->pk;
        }
    }
    if (relay_server.empty()) {
        relay_server = rendezvous_host(opts.server);
    }
    if (std::getenv("RDC_DEBUG") != nullptr) {
        std::fprintf(stderr, "hbb debug: relay connect server=%s uuid=%s signedPkLen=%zu\n",
                     normalize_relay(relay_server).c_str(), uuid.c_str(), signed_id_pk.size());
    }
    sc = connect_relay(relay_server, opts, uuid, timeout, err);
    if (!sc) {
        return nullptr;
    }
    pr->signed_id_pk = signed_id_pk;

    auto c = std::make_unique<Conn>();
    c->sc_ = std::move(sc);
    c->opts_ = opts;
    c->peer_id_ = opts.peer_id;
    if (!c->secure_handshake(pr->signed_id_pk, opts.key, err)) {
        return nullptr;
    }
    return c;
}

bool Conn::secure_handshake(const std::string& signed_id_pk, const std::string& key,
                            std::string* err) {
    auto rs_pk = decode_rs_key(key);
    if (!rs_pk) {
        *err = "hbb: invalid server public key";
        return false;
    }

    std::array<uint8_t, 32> peer_sign_pk{};
    if (!signed_id_pk.empty()) {
        if (auto sid = verify_signed_id(signed_id_pk, *rs_pk)) {
            peer_sign_pk = sid->pk;
        }
    }

    if (peer_sign_pk == std::array<uint8_t, 32>{}) {
        return send_message(hbb::Message{});
    }

    auto raw = sc_->read_message();
    if (!raw) {
        *err = "hbb: read signed id";
        return false;
    }
    hbb::Message msg;
    if (!msg.ParseFromString(*raw)) {
        *err = "hbb: parse message";
        return false;
    }
    if (!msg.has_signed_id()) {
        pending_ = std::move(msg);
        return send_message(hbb::Message{});
    }
    auto sid = verify_signed_id(msg.signed_id().id(), peer_sign_pk);
    if (!sid || sid->id != peer_id_) {
        return send_message(hbb::Message{});
    }

    auto sym = create_symmetric_key_msg(sid->pk);
    hbb::Message out;
    out.mutable_public_key()->set_asymmetric_value(as_string(sym.asym));
    out.mutable_public_key()->set_symmetric_value(sym.sym_sealed);
    if (!send_message(out)) {
        *err = "hbb: send public key";
        return false;
    }
    sc_->set_key(sym.key);
    return true;
}

bool Conn::send_message(const hbb::Message& msg) {
    const std::string data = msg.SerializeAsString();
    return sc_->write(reinterpret_cast<const uint8_t*>(data.data()), data.size()) ==
           static_cast<int64_t>(data.size());
}

bool Conn::Send(const hbb::Message& msg) { return send_message(msg); }

std::optional<hbb::Message> Conn::Recv() {
    if (pending_) {
        hbb::Message m = std::move(*pending_);
        pending_.reset();
        return m;
    }
    auto raw = sc_->read_message();
    if (!raw) {
        return std::nullopt;
    }
    hbb::Message msg;
    if (!msg.ParseFromString(*raw)) {
        return std::nullopt;
    }
    if (std::getenv("RDC_DEBUG") != nullptr) {
        std::fprintf(stderr, "hbb debug: recv msg union=%d\n", static_cast<int>(msg.union_case()));
    }
    return msg;
}


std::optional<hbb::PeerInfo> Conn::Login(LoginKind kind, const LoginSpec& spec,
                                         std::string* err) {
    while (true) {
        auto msg = Recv();
        if (!msg) {
            *err = "hbb: recv during login";
            return std::nullopt;
        }
        switch (msg->union_case()) {
        case hbb::Message::kHash: {
            const auto& hash = msg->hash();
            hbb::LoginRequest lr;
            lr.set_username(peer_id_);
            lr.set_my_id(random_peer_id());
            lr.set_my_name("rdcli");
            lr.set_my_platform(kPlatform);
            lr.set_version(kVersion);
            if (!opts_.password.empty()) {
                lr.set_password(hash_password(opts_.password, hash.salt(), hash.challenge()));
            }
            switch (kind) {
            case LoginKind::FileTransfer:
                lr.mutable_file_transfer()->set_dir(spec.dir);
                break;
            case LoginKind::Tunnel:
                lr.mutable_port_forward()->set_host(spec.host);
                lr.mutable_port_forward()->set_port(spec.port);
                break;
            case LoginKind::Terminal:
                lr.mutable_terminal();
                break;
            default:
                break;
            }
            hbb::Message out;
            *out.mutable_login_request() = lr;
            if (!send_message(out)) {
                *err = "hbb: send login request";
                return std::nullopt;
            }
            break;
        }
        case hbb::Message::kLoginResponse: {
            const auto& lr = msg->login_response();
            if (!lr.error().empty()) {
                *err = lr.error();
                return std::nullopt;
            }
            if (!lr.has_peer_info()) {
                *err = "empty peer info in login response";
                return std::nullopt;
            }
            peer_info_ = lr.peer_info();
            has_peer_info_ = true;
            sc_->underlying()->set_timeout(std::chrono::milliseconds(0));
            return peer_info_;
        }
        case hbb::Message::kTestDelay: {
            hbb::Message out;
            *out.mutable_test_delay() = msg->test_delay();
            send_message(out);
            break;
        }
        case hbb::Message::kMisc: {
            if (!msg->misc().close_reason().empty()) {
                *err = "peer closed: " + msg->misc().close_reason();
                return std::nullopt;
            }
            break;
        }
        default:
            break;
        }
    }
}

void Conn::SetRaw() {
    raw_ = true;
    sc_->set_raw();
}

int64_t Conn::ReadRaw(uint8_t* p, size_t n) { return sc_->read(p, n); }

int64_t Conn::WriteRaw(const uint8_t* p, size_t n) { return sc_->write(p, n); }

void Conn::Close() {
    if (sc_ && has_peer_info_ && !raw_ && !close_sent_) {
        // The official client sends Misc{close_reason} before hanging up so
        // the peer's connection window drops the tab immediately. Without it
        // the peer learns of the disconnect only from the socket dropping —
        // which, over a relay, can be delayed or missed, leaving a stray tab.
        // Best-effort: a send failure here just means we're already gone.
        close_sent_ = true;
        hbb::Message msg;
        msg.mutable_misc()->set_close_reason("client exit");
        send_message(msg);
    }
    // Shut down, don't close: another thread may still be inside Recv() or
    // Send(). It now sees EOF / an error, while the descriptor stays valid
    // until sc_ is destroyed with the Conn, so it can't be reused under it.
    Shutdown();
}

void Conn::Shutdown() {
    if (sc_) {
        sc_->shutdown();
    }
}

bool version_at_least(const std::string& v, const std::string& min) {
    const auto a = parse_version(v);
    const auto b = parse_version(min);
    for (int i = 0; i < 3; i++) {
        if (a[i] != b[i]) {
            return a[i] > b[i];
        }
    }
    return true;
}

}  // namespace rdcli::core

