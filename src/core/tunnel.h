#pragma once

#include <memory>
#include <string>

#include "core/conn.h"
#include "net/stream.h"

namespace rdcli::core {

// A single port-forward session: logs in as a port-forward connection, then
// pipes raw bytes bidirectionally.
class Tunnel {
public:
    static std::unique_ptr<Tunnel> Open(const DialOpts& opts, const std::string& host,
                                        int32_t port, std::string* err);
    ~Tunnel();

    // Pipes raw bytes bidirectionally between the peer and `local`.
    void Pipe(net::Stream* local);

    void Close();

private:
    std::unique_ptr<Conn> conn_;
};

}  // namespace rdcli::core
