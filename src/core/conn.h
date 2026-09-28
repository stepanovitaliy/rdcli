#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>

#include "core/secure.h"
#include "net/stream.h"
#include "proto/message.pb.h"
#include "proto/rendezvous.pb.h"

namespace rdcli::core {

constexpr const char* kVersion = "1.4.1";
constexpr const char* kRsPubKey = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=";

enum class LoginKind {
    Default,
    FileTransfer,
    Tunnel,
    Terminal,
};

struct DialOpts {
    std::string server;
    std::string peer_id;
    std::string password;
    std::string key;
    std::string token;
    bool force_relay = false;
    bool yes = false;
    hbb::ConnType conn_type = hbb::DEFAULT_CONN;
    std::chrono::milliseconds timeout{10000};
};

struct LoginSpec {
    std::string host;
    int32_t port = 0;
    std::string dir;
};

// Established connection to a peer (hole punch, relay, or direct).
class Conn {
public:
    ~Conn();
    static std::unique_ptr<Conn> Connect(const DialOpts& opts, std::string* err);

    // Performs the peer login handshake; returns peer info on success.
    std::optional<hbb::PeerInfo> Login(LoginKind kind, const LoginSpec& spec, std::string* err);

    bool Send(const hbb::Message& msg);
    std::optional<hbb::Message> Recv();

    void SetRaw();
    int64_t ReadRaw(uint8_t* p, size_t n);
    int64_t WriteRaw(const uint8_t* p, size_t n);

    // Notifies the peer (once) and shuts the socket down, waking a Recv() or
    // Send() in flight on another thread. The descriptor itself is released
    // only when the Conn is destroyed.
    void Close();

    // Unblocks a Recv() in flight on another thread without closing the socket.
    void Shutdown();

    bool Direct() const { return direct_; }
    const hbb::PeerInfo& PeerInfo() const { return peer_info_; }
    bool HasPeerInfo() const { return has_peer_info_; }

    SecureConn* sc() { return sc_.get(); }

private:
    bool send_message(const hbb::Message& msg);
    bool secure_handshake(const std::string& signed_id_pk, const std::string& key,
                          std::string* err);

    std::unique_ptr<SecureConn> sc_;
    DialOpts opts_;
    std::string peer_id_;
    bool direct_ = false;
    hbb::PeerInfo peer_info_;
    bool has_peer_info_ = false;
    // Set by SetRaw(): once true, the stream carries a raw byte pipe (tunnel
    // passthrough) and Close() must not frame a protocol message into it.
    bool raw_ = false;
    // Close() can be called more than once (explicit call + destructor); only
    // the first call should try to notify the peer.
    bool close_sent_ = false;
    std::optional<hbb::Message> pending_;
};

// Compares dotted version strings ("1.4.1" vs "1.1.10").
bool version_at_least(const std::string& v, const std::string& min);

}  // namespace rdcli::core

