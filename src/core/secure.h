#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include "core/crypt.h"
#include "net/stream.h"

namespace rdcli::core {

enum class StreamMode {
    Framed,
    Encrypted,
    Raw,
};

// Framed stream that can be plaintext, secretbox-encrypted, or raw. Mirrors
// hbb_common tcp::FramedStream / SecureConn.
class SecureConn {
public:
    explicit SecureConn(std::unique_ptr<net::Stream> stream);
    ~SecureConn();

    SecureConn(const SecureConn&) = delete;
    SecureConn& operator=(const SecureConn&) = delete;

    void set_key(const std::array<uint8_t, 32>& key);
    void set_raw();
    bool is_secured() const;

    int64_t read(uint8_t* p, size_t n);
    int64_t write(const uint8_t* p, size_t n);
    std::optional<std::string> read_message();
    void close();

    // Unblocks a read in flight on another thread; see net::Stream::shutdown.
    void shutdown();

    net::Stream* underlying() const { return stream_.get(); }

private:
    bool decrypt_frame(const std::string& frame);
    int64_t write_all(const uint8_t* p, size_t n);

    std::unique_ptr<net::Stream> stream_;
    // write() is called from the terminal input thread and from whichever
    // thread answers TestDelay; encrypt() bumps a nonce counter and the framed
    // payload must reach the socket in one piece, so the pair is serialised.
    // Reads stay single-threaded by design and are not guarded.
    std::mutex write_mu_;
    StreamMode mode_ = StreamMode::Framed;
    std::unique_ptr<Encryptor> encryptor_;
    std::string read_buf_;
    std::string dec_buf_;
};

}  // namespace rdcli::core
