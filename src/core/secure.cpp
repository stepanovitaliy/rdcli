#include "core/secure.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include "core/codec.h"

namespace rdcli::core {

SecureConn::SecureConn(std::unique_ptr<net::Stream> stream) : stream_(std::move(stream)) {}

SecureConn::~SecureConn() { close(); }

void SecureConn::set_key(const std::array<uint8_t, 32>& key) {
    encryptor_ = std::make_unique<Encryptor>(key);
    mode_ = StreamMode::Encrypted;
}

void SecureConn::set_raw() {
    mode_ = StreamMode::Raw;
    encryptor_.reset();
    read_buf_.clear();
    dec_buf_.clear();
}

bool SecureConn::is_secured() const { return mode_ == StreamMode::Encrypted; }

bool SecureConn::decrypt_frame(const std::string& frame) {
    if (mode_ == StreamMode::Encrypted) {
        // hbb_common tcp.rs skips empty/1-byte frames without decrypting them
        // or advancing the nonce counter.
        if (frame.size() <= 1) {
            dec_buf_ = frame;
            return true;
        }
        auto plaintext = encryptor_->decrypt(frame);
        if (!plaintext) {
            return false;
        }
        dec_buf_ = std::move(*plaintext);
        return true;
    }
    dec_buf_ = frame;
    return true;
}

int64_t SecureConn::read(uint8_t* p, size_t n) {
    if (n == 0) {
        return 0;
    }

    while (true) {
        if (!dec_buf_.empty()) {
            const size_t c = std::min(n, dec_buf_.size());
            std::memcpy(p, dec_buf_.data(), c);
            dec_buf_.erase(0, c);
            return static_cast<int64_t>(c);
        }

        if (mode_ == StreamMode::Raw) {
            if (!read_buf_.empty()) {
                const size_t c = std::min(n, read_buf_.size());
                std::memcpy(p, read_buf_.data(), c);
                read_buf_.erase(0, c);
                return static_cast<int64_t>(c);
            }
            return stream_->read(p, n);
        }

        if (!read_buf_.empty()) {
            auto frame = decode_frame(read_buf_);
            if (frame) {
                if (!decrypt_frame(*frame)) {
                    return -1;
                }
                continue;
            }
        }

        uint8_t buf[4096];
        const int64_t rn = stream_->read(buf, sizeof(buf));
        if (rn > 0) {
            read_buf_.append(reinterpret_cast<const char*>(buf), rn);
            continue;
        }
        if (rn < 0 || rn == 0) {
            // On error or EOF, try to flush a pending frame before surfacing it.
            if (!read_buf_.empty()) {
                auto frame = decode_frame(read_buf_);
                if (frame) {
                    if (!decrypt_frame(*frame)) {
                        return -1;
                    }
                    continue;
                }
            }
            return rn;
        }
    }
}

int64_t SecureConn::write_all(const uint8_t* p, size_t n) {
    size_t written = 0;
    while (written < n) {
        const int64_t w = stream_->write(p + written, n - written);
        if (w <= 0) {
            return -1;
        }
        written += static_cast<size_t>(w);
    }
    return static_cast<int64_t>(written);
}

int64_t SecureConn::write(const uint8_t* p, size_t n) {
    std::lock_guard<std::mutex> lk(write_mu_);
    switch (mode_) {
    case StreamMode::Raw:
        return write_all(p, n);
    case StreamMode::Encrypted: {
        std::string plain(reinterpret_cast<const char*>(p), n);
        std::string encrypted = encryptor_->encrypt(plain);
        std::string framed = encode(encrypted);
        if (write_all(reinterpret_cast<const uint8_t*>(framed.data()), framed.size()) < 0) {
            return -1;
        }
        return static_cast<int64_t>(n);
    }
    default: {
        std::string framed = encode(std::string(reinterpret_cast<const char*>(p), n));
        if (write_all(reinterpret_cast<const uint8_t*>(framed.data()), framed.size()) < 0) {
            return -1;
        }
        return static_cast<int64_t>(n);
    }
    }
}

std::optional<std::string> SecureConn::read_message() {
    uint8_t tmp[4096];
    while (true) {
        auto frame = decode_frame(read_buf_);
        if (frame) {
            if (mode_ == StreamMode::Encrypted && frame->size() > 1) {
                auto plain = encryptor_->decrypt(*frame);
                if (!plain) {
                    return std::nullopt;
                }
                return std::string(std::move(*plain));
            }
            return frame;
        }
        const int64_t n = stream_->read(tmp, sizeof(tmp));
        if (n > 0) {
            read_buf_.append(reinterpret_cast<const char*>(tmp), n);
        }
        if (n <= 0) {
            return std::nullopt;
        }
    }
}

void SecureConn::close() {
    if (stream_) {
        stream_->close();
    }
}

void SecureConn::shutdown() {
    if (stream_) {
        stream_->shutdown();
    }
}

}  // namespace rdcli::core
