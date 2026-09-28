#include "core/terminal.h"

#include <algorithm>
#include <cstring>
#include <optional>
#include <string>

#include <zstd.h>

#include "proto/message.pb.h"

namespace rdcli::core {

namespace {

std::optional<std::string> zstd_decompress(const std::string& data) {
    unsigned long long sz = ZSTD_getFrameContentSize(data.data(), data.size());
    if (sz == ZSTD_CONTENTSIZE_ERROR) {
        return std::nullopt;
    }
    if (sz == ZSTD_CONTENTSIZE_UNKNOWN) {
        sz = 16 * 1024 * 1024;
    }
    std::string out(static_cast<size_t>(sz), '\0');
    const size_t n = ZSTD_decompress(out.data(), out.size(), data.data(), data.size());
    if (ZSTD_isError(n)) {
        return std::nullopt;
    }
    out.resize(n);
    return out;
}

std::string decompress_terminal_data(const hbb::TerminalData& td) {
    std::string data = td.data();
    if (td.compressed()) {
        if (auto d = zstd_decompress(data)) {
            data = std::move(*d);
        }
    }
    return data;
}

bool terminal_supported(const hbb::PeerInfo& pi) {
    if (pi.has_features() && pi.features().terminal()) {
        return true;
    }
    return version_at_least(pi.version(), "1.4.1");
}

}  // namespace

TerminalSession::~TerminalSession() { Close(); }

std::unique_ptr<TerminalSession> TerminalSession::Open(const DialOpts& opts, uint32_t rows,
                                                       uint32_t cols, std::string* err) {
    DialOpts o = opts;
    o.conn_type = hbb::TERMINAL;
    auto c = Conn::Connect(o, err);
    if (!c) {
        return nullptr;
    }
    auto pi = c->Login(LoginKind::Terminal, LoginSpec{}, err);
    if (!pi) {
        return nullptr;
    }
    if (!terminal_supported(*pi)) {
        *err = "remote terminal is not supported by the remote side (peer version " +
               pi->version() + ", need 1.4.1 or higher)";
        return nullptr;
    }

    hbb::Message open_msg;
    auto* ta = open_msg.mutable_terminal_action();
    auto* open = ta->mutable_open();
    open->set_terminal_id(0);
    open->set_rows(rows);
    open->set_cols(cols);
    if (!c->Send(open_msg)) {
        *err = "send open terminal";
        return nullptr;
    }

    auto ts = std::unique_ptr<TerminalSession>(new TerminalSession());
    ts->conn_ = std::move(c);
    ts->term_id_ = 0;
    ts->rows_ = rows;
    ts->cols_ = cols;

    while (true) {
        auto msg = ts->conn_->Recv();
        if (!msg) {
            *err = "recv open terminal response";
            return nullptr;
        }
        if (msg->has_terminal_response()) {
            const auto& tr = msg->terminal_response();
            switch (tr.union_case()) {
            case hbb::TerminalResponse::kOpened: {
                const auto& opened = tr.opened();
                if (!opened.success()) {
                    *err = opened.message().empty() ? "failed to open terminal"
                                                    : opened.message();
                    return nullptr;
                }
                ts->term_id_ = opened.terminal_id();
                return ts;
            }
            case hbb::TerminalResponse::kError:
                *err = "terminal error: " + tr.error().message();
                return nullptr;
            case hbb::TerminalResponse::kClosed:
                *err = "terminal closed";
                return nullptr;
            case hbb::TerminalResponse::kData:
                ts->buf_ += decompress_terminal_data(tr.data());
                break;
            default:
                break;
            }
        } else if (msg->has_test_delay()) {
            hbb::Message resp;
            *resp.mutable_test_delay() = msg->test_delay();
            ts->conn_->Send(resp);
        }
    }
}


int64_t TerminalSession::Read(uint8_t* p, size_t n) {
    if (n == 0) {
        return 0;
    }
    while (true) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!buf_.empty()) {
                const size_t c = std::min(n, buf_.size());
                std::memcpy(p, buf_.data(), c);
                buf_.erase(0, c);
                return static_cast<int64_t>(c);
            }
            if (closed_) {
                return err_.empty() ? 0 : -1;
            }
        }

        auto msg = conn_->Recv();
        if (!msg) {
            std::lock_guard<std::mutex> lk(mu_);
            closed_ = true;
            if (err_.empty()) {
                err_ = "connection closed";
            }
            if (!buf_.empty()) {
                const size_t c = std::min(n, buf_.size());
                std::memcpy(p, buf_.data(), c);
                buf_.erase(0, c);
                return static_cast<int64_t>(c);
            }
            return -1;
        }

        if (msg->has_terminal_response()) {
            const auto& tr = msg->terminal_response();
            switch (tr.union_case()) {
            case hbb::TerminalResponse::kData: {
                std::lock_guard<std::mutex> lk(mu_);
                buf_ += decompress_terminal_data(tr.data());
                break;
            }
            case hbb::TerminalResponse::kClosed: {
                std::lock_guard<std::mutex> lk(mu_);
                closed_ = true;
                err_.clear();
                break;
            }
            case hbb::TerminalResponse::kError: {
                std::lock_guard<std::mutex> lk(mu_);
                closed_ = true;
                err_ = tr.error().message().empty() ? "terminal error"
                                                    : tr.error().message();
                break;
            }
            default:
                break;
            }
        } else if (msg->has_test_delay()) {
            hbb::Message resp;
            *resp.mutable_test_delay() = msg->test_delay();
            conn_->Send(resp);
        }
    }
}

int64_t TerminalSession::Write(const uint8_t* p, size_t n) {
    if (n == 0) {
        return 0;
    }
    int32_t term_id;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (closed_) {
            return -1;
        }
        term_id = term_id_;
    }
    hbb::Message msg;
    auto* ta = msg.mutable_terminal_action();
    auto* data = ta->mutable_data();
    data->set_terminal_id(term_id);
    data->set_data(std::string(reinterpret_cast<const char*>(p), n));
    if (!conn_->Send(msg)) {
        return -1;
    }
    return static_cast<int64_t>(n);
}

bool TerminalSession::Resize(uint32_t rows, uint32_t cols) {
    int32_t term_id;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (closed_) {
            return false;
        }
        rows_ = rows;
        cols_ = cols;
        term_id = term_id_;
    }
    hbb::Message msg;
    auto* ta = msg.mutable_terminal_action();
    auto* resize = ta->mutable_resize();
    resize->set_terminal_id(term_id);
    resize->set_rows(rows);
    resize->set_cols(cols);
    return conn_->Send(msg);
}

void TerminalSession::Shutdown() {
    // Only wakes a blocked Read(); the session is marked closed by Read()
    // itself once the torn-down socket reports EOF.
    conn_->Shutdown();
}

void TerminalSession::Close() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (closed_) {
            return;
        }
        closed_ = true;
    }
    hbb::Message msg;
    auto* ta = msg.mutable_terminal_action();
    ta->mutable_close()->set_terminal_id(term_id_);
    conn_->Send(msg);
    conn_->Close();
}

}  // namespace rdcli::core
