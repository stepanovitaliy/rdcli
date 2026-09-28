#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "core/conn.h"

namespace rdcli::core {

// Interactive or one-shot remote terminal session.
class TerminalSession {
public:
    static std::unique_ptr<TerminalSession> Open(const DialOpts& opts, uint32_t rows,
                                                 uint32_t cols, std::string* err);
    ~TerminalSession();

    int64_t Read(uint8_t* p, size_t n);
    int64_t Write(const uint8_t* p, size_t n);
    bool Resize(uint32_t rows, uint32_t cols);
    void Close();

    // Unblocks a Read() in flight on another thread so it can be joined.
    void Shutdown();

private:
    std::unique_ptr<Conn> conn_;
    int32_t term_id_ = 0;
    uint32_t rows_ = 0;
    uint32_t cols_ = 0;

    std::mutex mu_;
    std::string buf_;
    bool closed_ = false;
    std::string err_;
};

}  // namespace rdcli::core
