#pragma once

#include <map>
#include <string>
#include <vector>

namespace rdcli::config {

struct Peer {
    std::string name;
    std::string password;
};

struct Config {
    std::string server;
    std::string key;
    std::string access_token;
    std::string api_server;
    std::string api_username;
    std::string api_password;
    std::map<std::string, Peer> peers;
    std::map<std::string, std::vector<std::string>> tags;

    bool load(std::string* err);
    bool save(std::string* err);

    std::string password_for_peer(const std::string& id) const;
    std::vector<std::string> tags_for(const std::string& id) const;
    void add_tag(const std::string& id, const std::string& tag);
    void remove_tag(const std::string& id, const std::string& tag);
    void set_peers_password(const std::string& id, const std::string& pw);
    void set_access_token(const std::string& token);
};

// Config file path (~/.config/rdcli/config.toml or $RDC_CONFIG).
std::string path();
std::string home_dir();

std::string gui_access_token();
std::string gui_access_token_path();
std::string gui_user_info(const std::string& gui_path);

}  // namespace rdcli::config
