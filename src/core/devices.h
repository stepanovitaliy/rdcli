#pragma once

#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "config/config.h"

namespace rdcli::core {

struct Device {
    std::string id;
    std::string name;
    std::string platform;
    std::vector<std::string> tags;
    bool online = false;
    std::string last_seen;
    std::string source;
};

class DeviceSource {
public:
    virtual ~DeviceSource() = default;
    virtual bool List(std::vector<Device>* out, std::string* err) = 0;
    virtual std::vector<std::string> Tags(const std::string& id) = 0;
    virtual bool AddTag(const std::string& id, const std::string& tag, std::string* err) = 0;
    virtual bool RemoveTag(const std::string& id, const std::string& tag, std::string* err) = 0;
};

// Local config source, or the Pro address-book API when api_server is set.
std::unique_ptr<DeviceSource> NewDeviceSource(config::Config* cfg, std::string* err);

// Batch online check over the rendezvous server.
std::map<std::string, bool> BatchOnline(const std::string& server,
                                        const std::vector<std::string>& ids,
                                        std::chrono::milliseconds timeout);

}  // namespace rdcli::core
