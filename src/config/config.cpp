#include "config/config.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace rdcli::config {

namespace fs = std::filesystem;

namespace {

std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) {
        return {};
    }
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string unquote(const std::string& s) {
    std::string v = trim(s);
    if (v.size() >= 2 && v.front() == '"' && v.back() == '"') {
        std::string inner = v.substr(1, v.size() - 2);
        std::string out;
        for (size_t i = 0; i < inner.size(); i++) {
            if (inner[i] == '\\' && i + 1 < inner.size()) {
                i++;
                switch (inner[i]) {
                case '"':
                    out.push_back('"');
                    break;
                case '\\':
                    out.push_back('\\');
                    break;
                case 'n':
                    out.push_back('\n');
                    break;
                case 't':
                    out.push_back('\t');
                    break;
                default:
                    out.push_back(inner[i]);
                }
                continue;
            }
            out.push_back(inner[i]);
        }
        return out;
    }
    return v;
}

std::string quote(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            out.push_back(c);
        }
    }
    out += "\"";
    return out;
}

int find_closing_quote(const std::string& s) {
    for (size_t i = 1; i < s.size(); i++) {
        if (s[i] == '\\') {
            i++;
            continue;
        }
        if (s[i] == '"') {
            return static_cast<int>(i);
        }
    }
    return -1;
}

std::string parse_string(const std::string& value) {
    std::string v = trim(value);
    if (!v.empty() && v.front() == '"') {
        const int end = find_closing_quote(v);
        if (end >= 0) {
            return unquote(v.substr(0, end + 1));
        }
    }
    const auto hash = v.find('#');
    if (hash != std::string::npos) {
        v = trim(v.substr(0, hash));
    }
    return unquote(v);
}

bool parse_string_array(const std::string& value, std::vector<std::string>* out,
                        std::string* err) {
    std::string v = trim(value);
    if (v.empty() || v.front() != '[') {
        *err = "expected array";
        return false;
    }
    const auto end = v.find_last_of(']');
    if (end == std::string::npos) {
        *err = "unclosed array";
        return false;
    }
    std::string inner = v.substr(1, end - 1);
    const auto hash = inner.find('#');
    if (hash != std::string::npos) {
        inner = inner.substr(0, hash);
    }
    std::istringstream iss(inner);
    std::string part;
    while (std::getline(iss, part, ',')) {
        part = trim(part);
        if (part.empty()) {
            continue;
        }
        out->push_back(unquote(part));
    }
    return true;
}

std::string parse_local_access_token(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        return {};
    }
    std::string line;
    bool in_options = false;
    while (std::getline(f, line)) {
        line = trim(line);
        if (!line.empty() && line.front() == '[') {
            in_options = trim(line.substr(1, line.size() - 2)) == "options";
            continue;
        }
        if (!in_options) {
            continue;
        }
        if (line.rfind("access_token", 0) == 0) {
            const auto eq = line.find('=');
            if (eq != std::string::npos) {
                std::string v = trim(line.substr(eq + 1));
                v.erase(std::remove(v.begin(), v.end(), '\''), v.end());
                v.erase(std::remove(v.begin(), v.end(), '"'), v.end());
                return v;
            }
        }
    }
    return {};
}

std::vector<std::string> gui_token_candidates() {
    const std::string home = home_dir();
    if (home.empty()) {
        return {};
    }
    return {
        (fs::path(home) / "Library" / "Preferences" / "com.carriez.RustDesk" / "RustDesk_local.toml")
            .string(),
        (fs::path(home) / ".config" / "rustdesk" / "RustDesk_local.toml").string(),
        (fs::path(home) / ".local" / "share" / "rustdesk" / "RustDesk_local.toml").string(),
        (fs::path(home) / "AppData" / "Roaming" / "RustDesk" / "RustDesk_local.toml").string(),
        (fs::path(home) / "AppData" / "Roaming" / "RustDesk" / "config" / "RustDesk_local.toml")
            .string(),
    };
}

}  // namespace

std::string home_dir() {
#if defined(_WIN32)
    const char* h = std::getenv("USERPROFILE");
#else
    const char* h = std::getenv("HOME");
#endif
    return h ? std::string(h) : std::string();
}

std::string path() {
    if (const char* p = std::getenv("RDC_CONFIG")) {
        if (*p != '\0') {
            return p;
        }
    }
    const std::string home = home_dir();
    if (home.empty()) {
        return "config.toml";
    }
    return (fs::path(home) / ".config" / "rdcli" / "config.toml").string();
}

bool Config::load(std::string* err) {
    const std::string p = path();
    std::ifstream f(p);
    if (!f.is_open()) {
        return true;
    }
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string data = ss.str();

    std::string section;
    std::istringstream iss(data);
    std::string line;
    while (std::getline(iss, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }
        if (line[0] == '[') {
            std::string header = trim(line.substr(1, line.size() - 2));
            if (header == "tags") {
                section = "tags";
            } else if (header.rfind("peers.", 0) == 0) {
                section = "peer:" + unquote(trim(header.substr(6)));
            } else {
                section.clear();
            }
            continue;
        }
        const auto eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        const std::string key = trim(line.substr(0, eq));
        const std::string value = trim(line.substr(eq + 1));
        if (section == "tags") {
            std::vector<std::string> parsed_tags;
            if (!parse_string_array(value, &parsed_tags, err)) {
                return false;
            }
            std::sort(parsed_tags.begin(), parsed_tags.end());
            tags[unquote(key)] = parsed_tags;
        } else if (section.rfind("peer:", 0) == 0) {
            const std::string id = section.substr(5);
            Peer& p = peers[id];
            if (key == "password") {
                p.password = parse_string(value);
            } else if (key == "name") {
                p.name = parse_string(value);
            }
        } else {
            if (key == "server") {
                server = parse_string(value);
            } else if (key == "key") {
                this->key = parse_string(value);
            } else if (key == "access_token") {
                access_token = parse_string(value);
            } else if (key == "api_server") {
                api_server = parse_string(value);
            } else if (key == "api_username") {
                api_username = parse_string(value);
            } else if (key == "api_password") {
                api_password = parse_string(value);
            }
        }
    }
    return true;
}

bool Config::save(std::string* err) {
    std::string out;
    out += "server = " + quote(server) + "\n";
    out += "key = " + quote(key) + "\n";
    out += "access_token = " + quote(access_token) + "\n";
    out += "api_server = " + quote(api_server) + "\n";
    out += "api_username = " + quote(api_username) + "\n";
    out += "api_password = " + quote(api_password) + "\n";

    std::vector<std::string> peer_ids;
    for (const auto& kv : peers) {
        peer_ids.push_back(kv.first);
    }
    std::sort(peer_ids.begin(), peer_ids.end());
    for (const auto& id : peer_ids) {
        const Peer& p = peers.at(id);
        out += "\n[peers." + quote(id) + "]\n";
        out += "password = " + quote(p.password) + "\n";
        if (!p.name.empty()) {
            out += "name = " + quote(p.name) + "\n";
        }
    }

    std::vector<std::string> tag_ids;
    for (const auto& kv : tags) {
        if (!kv.second.empty()) {
            tag_ids.push_back(kv.first);
        }
    }
    std::sort(tag_ids.begin(), tag_ids.end());
    if (!tag_ids.empty()) {
        out += "\n[tags]\n";
        for (const auto& id : tag_ids) {
            out += quote(id) + " = [";
            const auto& ts = tags.at(id);
            for (size_t i = 0; i < ts.size(); i++) {
                if (i > 0) {
                    out += ", ";
                }
                out += quote(ts[i]);
            }
            out += "]\n";
        }
    }

    const std::string p = path();
    std::error_code ec;
    fs::create_directories(fs::path(p).parent_path(), ec);

    // Write through a temporary file: an interrupted save must not truncate a
    // config that holds machine passwords, and the file must stay owner-only.
    const std::string tmp = p + ".tmp";
    // Never write into an existing tmp: a stale one from an interrupted save
    // may be world-readable, or held open by someone who opened it while it
    // was. Start from a fresh file that is owner-only from creation.
    fs::remove(tmp, ec);
#if defined(_WIN32)
    {
        std::ofstream f(tmp, std::ios::trunc | std::ios::binary);
        if (!f.is_open()) {
            *err = "config: write " + tmp;
            return false;
        }
        f << out;
        f.flush();
        if (!f) {
            *err = "config: write " + tmp;
            fs::remove(tmp, ec);
            return false;
        }
    }
#else
    {
        const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) {
            *err = "config: write " + tmp + ": " + std::strerror(errno);
            return false;
        }
        size_t off = 0;
        while (off < out.size()) {
            const ssize_t w = ::write(fd, out.data() + off, out.size() - off);
            if (w < 0 && errno == EINTR) {
                continue;
            }
            if (w <= 0) {
                *err = "config: write " + tmp + ": " + std::strerror(errno);
                ::close(fd);
                fs::remove(tmp, ec);
                return false;
            }
            off += static_cast<size_t>(w);
        }
        if (::close(fd) != 0) {
            *err = "config: write " + tmp + ": " + std::strerror(errno);
            fs::remove(tmp, ec);
            return false;
        }
    }
#endif
    // Still set explicitly: the umask can strip bits from the 0600 above, and
    // the result must be exactly owner read/write.
    fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace, ec);
    if (ec) {
        *err = "config: chmod " + tmp + ": " + ec.message();
        fs::remove(tmp, ec);
        return false;
    }
    fs::rename(tmp, p, ec);
    if (ec) {
        *err = "config: rename " + tmp + ": " + ec.message();
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}


std::string Config::password_for_peer(const std::string& id) const {
    const auto it = peers.find(id);
    return it == peers.end() ? std::string() : it->second.password;
}

std::vector<std::string> Config::tags_for(const std::string& id) const {
    const auto it = tags.find(id);
    return it == tags.end() ? std::vector<std::string>() : it->second;
}

void Config::add_tag(const std::string& id, const std::string& tag) {
    auto& ts = tags[id];
    for (const auto& t : ts) {
        if (t == tag) {
            return;
        }
    }
    ts.push_back(tag);
    std::sort(ts.begin(), ts.end());
}

void Config::remove_tag(const std::string& id, const std::string& tag) {
    auto& ts = tags[id];
    ts.erase(std::remove(ts.begin(), ts.end(), tag), ts.end());
    if (ts.empty()) {
        tags.erase(id);
    }
}

void Config::set_peers_password(const std::string& id, const std::string& pw) {
    peers[id].password = pw;
}

void Config::set_access_token(const std::string& token) { access_token = token; }

std::string gui_access_token() {
    for (const auto& p : gui_token_candidates()) {
        const std::string tok = parse_local_access_token(p);
        if (!tok.empty()) {
            return tok;
        }
    }
    return {};
}

std::string gui_access_token_path() {
    for (const auto& p : gui_token_candidates()) {
        if (!parse_local_access_token(p).empty()) {
            return p;
        }
    }
    return {};
}

std::string gui_user_info(const std::string& gui_path) {
    if (gui_path.empty()) {
        return {};
    }
    std::ifstream f(gui_path);
    if (!f.is_open()) {
        return {};
    }
    std::string line;
    bool in_options = false;
    while (std::getline(f, line)) {
        line = trim(line);
        if (!line.empty() && line.front() == '[') {
            in_options = trim(line.substr(1, line.size() - 2)) == "options";
            continue;
        }
        if (!in_options) {
            continue;
        }
        if (line.rfind("user_info", 0) == 0) {
            const auto eq = line.find('=');
            if (eq != std::string::npos) {
                std::string v = trim(line.substr(eq + 1));
                v.erase(std::remove(v.begin(), v.end(), '\''), v.end());
                v.erase(std::remove(v.begin(), v.end(), '"'), v.end());
                return v;
            }
        }
    }
    return {};
}

}  // namespace rdcli::config

