#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <exception>
#include <stdexcept>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if !defined(_WIN32)
#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>
#else
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h>
#include <windows.h>
#undef RGB  // wingdi.h macro clashes with the protobuf message hbb::RGB
#endif

#include <sodium.h>

#include "config/config.h"
#include "core/conn.h"
#include "core/devices.h"
#include "core/file_transfer.h"
#include "core/rendezvous.h"
#include "core/terminal.h"
#include "core/tunnel.h"
#include "net/socket.h"
#include "net/stream.h"

using rdcli::config::Config;
using rdcli::core::DialOpts;

namespace {

constexpr const char* kVersion = "0.1.0";
constexpr int kOneShotMinWaitMs = 1000;

struct Flags {
    std::string password;
    std::string server;
    std::string key;
    std::string token;
    std::string connect_ref;
    bool relay = false;
    bool yes = false;
    bool json = false;
    int timeout_sec = 10;
    int idle_ms = 300;
};

// Parses a Go-style duration ("300ms", "5s", "2m") or a bare seconds count.
bool parse_duration_ms(const std::string& v, int* out) {
    size_t i = 0;
    long long num = 0;
    bool any = false;
    while (i < v.size() && std::isdigit(static_cast<unsigned char>(v[i]))) {
        num = num * 10 + (v[i] - '0');
        any = true;
        i++;
    }
    if (!any || num < 0 || num > 3600000) {
        return false;
    }
    const std::string unit = v.substr(i);
    if (unit == "ms") {
        *out = static_cast<int>(num);
    } else if (unit == "s" || unit.empty()) {
        *out = static_cast<int>(num * 1000);
    } else if (unit == "m") {
        *out = static_cast<int>(num * 60000);
    } else {
        return false;
    }
    return true;
}

int usage_error(const std::string& msg) {
    std::fprintf(stderr, "rdcli: %s\n", msg.c_str());
    return 2;
}

int runtime_error(const std::string& msg) {
    std::fprintf(stderr, "%s\n", msg.c_str());
    return 1;
}

std::string to_lower(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

bool parse_args(int argc, char** argv, Flags* flags, std::vector<std::string>* pos) {
    for (int i = 1; i < argc; i++) {
        const std::string a = argv[i];
        const std::string next = (i + 1 < argc) ? argv[i + 1] : std::string();
        bool consumed = false;
        if (a == "--password" || a == "-p") {
            flags->password = next;
            i++;
            consumed = true;
        } else if (a.rfind("--password=", 0) == 0) {
            flags->password = a.substr(11);
            consumed = true;
        } else if (a == "--server") {
            flags->server = next;
            i++;
            consumed = true;
        } else if (a.rfind("--server=", 0) == 0) {
            flags->server = a.substr(9);
            consumed = true;
        } else if (a == "--key") {
            flags->key = next;
            i++;
            consumed = true;
        } else if (a.rfind("--key=", 0) == 0) {
            flags->key = a.substr(6);
            consumed = true;
        } else if (a == "--token") {
            flags->token = next;
            i++;
            consumed = true;
        } else if (a.rfind("--token=", 0) == 0) {
            flags->token = a.substr(8);
            consumed = true;
        } else if (a == "--connect" || a == "-c") {
            flags->connect_ref = next;
            i++;
            consumed = true;
        } else if (a.rfind("--connect=", 0) == 0) {
            flags->connect_ref = a.substr(10);
            consumed = true;
        } else if (a == "--relay") {
            flags->relay = true;
            consumed = true;
        } else if (a == "--yes") {
            flags->yes = true;
            consumed = true;
        } else if (a == "--json") {
            flags->json = true;
            consumed = true;
        } else if (a == "--timeout") {
            flags->timeout_sec = std::atoi(next.c_str());
            i++;
            consumed = true;
        } else if (a.rfind("--timeout=", 0) == 0) {
            flags->timeout_sec = std::atoi(a.substr(10).c_str());
            consumed = true;
        } else if (a == "--idle") {
            if (!parse_duration_ms(next, &flags->idle_ms)) {
                return false;
            }
            i++;
            consumed = true;
        } else if (a.rfind("--idle=", 0) == 0) {
            if (!parse_duration_ms(a.substr(7), &flags->idle_ms)) {
                return false;
            }
            consumed = true;
        }
        if (!consumed) {
            pos->push_back(a);
        }
    }
    return true;
}

bool resolve_ref(Config& cfg, const std::string& ref, std::string* id, std::string* pw) {
    if (cfg.peers.count(ref)) {
        *id = ref;
        *pw = cfg.peers[ref].password;
        return true;
    }
    const std::string lref = to_lower(ref);
    for (const auto& kv : cfg.peers) {
        if (to_lower(kv.second.name).find(lref) != std::string::npos) {
            *id = kv.first;
            *pw = kv.second.password;
            return true;
        }
    }
    for (const auto& kv : cfg.tags) {
        for (const auto& t : kv.second) {
            if (to_lower(t) == lref) {
                *id = kv.first;
                auto it = cfg.peers.find(kv.first);
                *pw = it == cfg.peers.end() ? std::string() : it->second.password;
                return true;
            }
        }
    }
    *id = ref;
    *pw = cfg.password_for_peer(ref);
    return true;
}

bool resolve_target(const Flags& flags, const std::vector<std::string>& args, Config* cfg,
                    std::string* id, std::string* pw, std::vector<std::string>* rest);
std::string get_password(const Flags& flags);

}  // namespace

namespace {

std::string get_server(const Flags& flags, Config& cfg) {
    if (!flags.server.empty()) {
        return flags.server;
    }
    if (const char* e = std::getenv("RDC_SERVER")) {
        return e;
    }
    if (!cfg.server.empty()) {
        return cfg.server;
    }
    return rdcli::core::kDefaultRendezvousServer;
}

std::string get_key(const Flags& flags, Config& cfg) {
    if (!flags.key.empty()) {
        return flags.key;
    }
    if (const char* e = std::getenv("RDC_KEY")) {
        return e;
    }
    return cfg.key;
}

std::string get_token(const Flags& flags, Config& cfg) {
    if (!flags.token.empty()) {
        return flags.token;
    }
    if (const char* e = std::getenv("RDC_TOKEN")) {
        return e;
    }
    if (!cfg.access_token.empty()) {
        return cfg.access_token;
    }
    return rdcli::config::gui_access_token();
}

std::string get_password(const Flags& flags) {
    if (!flags.password.empty()) {
        return flags.password;
    }
    if (const char* e = std::getenv("RDC_PASSWORD")) {
        return e;
    }
    return {};
}

DialOpts make_dial_opts(const Flags& flags, Config& cfg, const std::string& peer_id,
                        const std::string& password, hbb::ConnType ct) {
    DialOpts o;
    o.server = get_server(flags, cfg);
    o.peer_id = peer_id;
    o.password = password.empty() ? get_password(flags) : password;
    o.key = get_key(flags, cfg);
    o.token = get_token(flags, cfg);
    o.force_relay = flags.relay;
    o.yes = flags.yes;
    o.conn_type = ct;
    o.timeout = std::chrono::seconds(flags.timeout_sec);
    return o;
}

std::string json_escape(const std::string& s) {
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
        case '\r':
            out += "\\r";
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

void print_aligned(const std::vector<std::vector<std::string>>& rows) {
    if (rows.empty()) {
        return;
    }
    std::vector<size_t> widths(rows[0].size(), 0);
    for (const auto& r : rows) {
        for (size_t i = 0; i < r.size() && i < widths.size(); i++) {
            widths[i] = std::max(widths[i], r[i].size());
        }
    }
    for (const auto& r : rows) {
        for (size_t i = 0; i < r.size(); i++) {
            if (i > 0) {
                std::printf("  ");
            }
            std::printf("%s", r[i].c_str());
            if (i < widths.size()) {
                std::printf("%*s", static_cast<int>(widths[i] - r[i].size()), "");
            }
        }
        std::printf("\n");
    }
}

std::string human_size(uint64_t n) {
    constexpr uint64_t unit = 1024;
    if (n < unit) {
        return std::to_string(n) + " B";
    }
    uint64_t div = unit;
    int exp = 0;
    for (uint64_t m = n / unit; m >= unit; m /= unit) {
        div *= unit;
        exp++;
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.1f %ciB", static_cast<double>(n) / div, "KMGTPE"[exp]);
    return buf;
}

std::string human_time(uint64_t sec) {
    if (sec == 0) {
        return {};
    }
    const std::time_t t = static_cast<std::time_t>(sec);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tm);
    return buf;
}

}  // namespace

namespace {

int cmd_version() {
    std::printf("rdcli %s\n", kVersion);
    return 0;
}

int cmd_ping(const Flags& flags, const std::vector<std::string>& args) {
    Config cfg;
    std::string cerr;
    cfg.load(&cerr);
    std::string id, pw;
    std::string ref = args.empty() ? std::string() : args[0];
    if (ref.empty() && !flags.connect_ref.empty()) {
        ref = flags.connect_ref;
    }
    if (ref.empty()) {
        return usage_error("usage: rdcli ping <id>");
    }
    resolve_ref(cfg, ref, &id, &pw);
    const auto start = std::chrono::steady_clock::now();
    const auto online = rdcli::core::check_online(get_server(flags, cfg), id,
                                                  std::chrono::seconds(flags.timeout_sec));
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - start)
                        .count();
    if (!online) {
        return runtime_error("ping failed");
    }
    if (flags.json) {
        std::printf("{\"version\":1,\"id\":%s,\"online\":%s,\"latency_ms\":%lld}\n",
                    json_escape(id).c_str(), *online ? "true" : "false",
                    static_cast<long long>(ms));
    } else if (*online) {
        std::printf("online (%lldms)\n", static_cast<long long>(ms));
    } else {
        std::printf("offline (%lldms)\n", static_cast<long long>(ms));
    }
    return *online ? 0 : 1;
}

int cmd_connect(const Flags& flags, const std::vector<std::string>& args, bool disconnect) {
    if (args.size() != 1) {
        return usage_error(disconnect ? "usage: rdcli disconnect <id|name|tag>"
                                      : "usage: rdcli connect <id|name|tag>");
    }
    Config cfg;
    std::string cerr;
    cfg.load(&cerr);
    std::string id, pw;
    resolve_ref(cfg, args[0], &id, &pw);
    if (!disconnect) {
        // --password/-p wins over RDC_PASSWORD, which wins over whatever is
        // already stored for this peer.
        const std::string given = get_password(flags);
        if (!given.empty()) {
            pw = given;
        }
        cfg.set_peers_password(id, pw);
    } else {
        cfg.set_peers_password(id, "");
    }
    if (!cfg.save(&cerr)) {
        return runtime_error(cerr);
    }
    std::printf("%s %s\n", disconnect ? "disconnected from" : "connected to", id.c_str());
    return 0;
}

std::string mask_token(const std::string& tok) {
    if (tok.size() <= 8) {
        return "****";
    }
    return tok.substr(0, 4) + "..." + tok.substr(tok.size() - 4);
}

std::string or_dash(const std::string& s) { return s.empty() ? "-" : s; }

int cmd_auth(const Flags& flags, const std::vector<std::string>& args) {
    Config cfg;
    std::string cerr;
    cfg.load(&cerr);
    const std::string gui_path = rdcli::config::gui_access_token_path();
    const std::string gui_tok = rdcli::config::gui_access_token();

    if (args.empty()) {
        return usage_error("usage: rdcli auth <status|import-gui|logout|set>");
    }
    const std::string& sub = args[0];

    if (sub == "status") {
        std::string source;
        std::string tok = cfg.access_token;
        if (!tok.empty()) {
            source = "config";
        } else if (!gui_tok.empty()) {
            tok = gui_tok;
            source = "gui";
        }
        if (flags.json) {
            std::printf(
                "{\"version\":1,\"logged_in\":%s,\"token\":%s,\"source\":%s,\"gui_config\":%s,"
                "\"rdc_config\":%s,\"server\":%s,\"user_info\":%s,\"password_set\":%s}\n",
                tok.empty() ? "false" : "true", json_escape(tok).c_str(),
                json_escape(source).c_str(), json_escape(gui_path).c_str(),
                json_escape(rdcli::config::path()).c_str(),
                json_escape(get_server(flags, cfg)).c_str(),
                json_escape(rdcli::config::gui_user_info(gui_path)).c_str(),
                cfg.peers.empty() ? "false" : "true");
        } else {
            if (!tok.empty()) {
                std::printf("logged in (%s)\n", source.c_str());
                std::printf("token:    %s\n", mask_token(tok).c_str());
            } else {
                std::printf("not logged in\n");
            }
            std::printf("source:   %s\n", or_dash(source).c_str());
            std::printf("gui cfg:  %s\n", or_dash(gui_path).c_str());
            std::printf("rdc cfg:  %s\n", rdcli::config::path().c_str());
            const std::string ui = rdcli::config::gui_user_info(gui_path);
            if (!ui.empty()) {
                std::printf("user:     %s\n", ui.c_str());
            }
            if (!cfg.peers.empty()) {
                std::printf("saved passwords: %zu peer(s)\n", cfg.peers.size());
            }
        }
        return 0;
    }
    if (sub == "import-gui") {
        if (gui_tok.empty()) {
            return runtime_error("auth: no token found in RustDesk desktop app config");
        }
        cfg.set_access_token(gui_tok);
        if (!cfg.save(&cerr)) {
            return runtime_error("auth: " + cerr);
        }
        std::printf("imported token from %s\n", gui_path.c_str());
        return 0;
    }
    if (sub == "logout") {
        if (cfg.access_token.empty()) {
            std::printf("no token stored\n");
            return 0;
        }
        cfg.set_access_token("");
        if (!cfg.save(&cerr)) {
            return runtime_error("auth: " + cerr);
        }
        std::printf("logged out\n");
        return 0;
    }
    if (sub == "set") {
        if (args.size() != 2) {
            return usage_error("usage: rdcli auth set <token>");
        }
        cfg.set_access_token(args[1]);
        if (!cfg.save(&cerr)) {
            return runtime_error(cerr);
        }
        std::printf("token saved\n");
        return 0;
    }
    return usage_error("unknown auth subcommand: " + sub);
}

}  // namespace

namespace {

int cmd_devices(const Flags& flags, const std::vector<std::string>& args) {
    Config cfg;
    std::string cerr;
    cfg.load(&cerr);
    std::string query;
    std::string tag_filter;
    bool online_only = false;

    if (!args.empty() && args[0] == "search") {
        if (args.size() != 2) {
            return usage_error("usage: rdcli devices search <query> [--json]");
        }
        query = args[1];
    } else {
        for (size_t i = 0; i < args.size(); i++) {
            if (args[i] == "--tag" && i + 1 < args.size()) {
                tag_filter = args[++i];
            } else if (args[i] == "--online") {
                online_only = true;
            }
        }
    }

    std::string err;
    auto src = rdcli::core::NewDeviceSource(&cfg, &err);
    if (!src) {
        return runtime_error("address book: " + err);
    }
    std::vector<rdcli::core::Device> devs;
    if (!src->List(&devs, &err)) {
        return runtime_error(err);
    }
    for (auto& d : devs) {
        if (d.name.empty()) {
            auto it = cfg.peers.find(d.id);
            if (it != cfg.peers.end()) {
                d.name = it->second.name;
            }
        }
    }
    std::vector<std::string> ids;
    for (const auto& d : devs) {
        ids.push_back(d.id);
    }
    auto online = rdcli::core::BatchOnline(get_server(flags, cfg), ids,
                                           std::chrono::seconds(flags.timeout_sec));

    std::vector<rdcli::core::Device> out;
    const std::string q = to_lower(query);
    for (auto& d : devs) {
        if (!query.empty()) {
            bool match = to_lower(d.id).find(q) != std::string::npos ||
                         to_lower(d.name).find(q) != std::string::npos;
            for (const auto& t : d.tags) {
                match = match || to_lower(t).find(q) != std::string::npos;
            }
            if (!match) {
                continue;
            }
        }
        if (!tag_filter.empty() &&
            std::find(d.tags.begin(), d.tags.end(), tag_filter) == d.tags.end()) {
            continue;
        }
        d.online = online[d.id];
        if (online_only && !d.online) {
            continue;
        }
        out.push_back(std::move(d));
    }

    if (flags.json) {
        std::printf("{\"version\":1,\"devices\":[");
        for (size_t i = 0; i < out.size(); i++) {
            const auto& d = out[i];
            if (i > 0) {
                std::printf(",");
            }
            std::string tags = "[";
            for (size_t j = 0; j < d.tags.size(); j++) {
                if (j > 0) {
                    tags += ",";
                }
                tags += json_escape(d.tags[j]);
            }
            tags += "]";
            std::printf(
                "{\"id\":%s,\"name\":%s,\"tags\":%s,\"online\":%s,\"platform\":%s,"
                "\"last_seen\":%s,\"source\":%s}",
                json_escape(d.id).c_str(), json_escape(d.name).c_str(), tags.c_str(),
                d.online ? "true" : "false", json_escape(d.platform).c_str(),
                json_escape(d.last_seen).c_str(), json_escape(d.source).c_str());
        }
        std::printf("]}\n");
        return 0;
    }

    std::vector<std::vector<std::string>> rows = {
        {"ID", "NAME", "TAGS", "ONLINE", "PLATFORM", "LAST_SEEN"}};
    for (const auto& d : out) {
        std::string tags;
        for (size_t i = 0; i < d.tags.size(); i++) {
            if (i > 0) {
                tags += ",";
            }
            tags += d.tags[i];
        }
        rows.push_back({d.id, d.name, tags, d.online ? "yes" : "no", d.platform, d.last_seen});
    }
    print_aligned(rows);
    return 0;
}

}  // namespace

namespace {

int cmd_tag(const Flags& flags, const std::vector<std::string>& args) {
    if (args.empty()) {
        return usage_error("usage: rdcli tag <add|rm|ls> ...");
    }
    Config cfg;
    std::string cerr;
    cfg.load(&cerr);
    std::string err;
    auto src = rdcli::core::NewDeviceSource(&cfg, &err);

    const std::string& sub = args[0];
    if (sub == "add" || sub == "rm") {
        if (args.size() != 3) {
            return usage_error("usage: rdcli tag " + sub + " <id> <tag>");
        }
        if (!src) {
            return runtime_error("tag: " + err);
        }
        std::string id, pw;
        resolve_ref(cfg, args[1], &id, &pw);
        bool ok = sub == "add" ? src->AddTag(id, args[2], &err) : src->RemoveTag(id, args[2], &err);
        if (!ok) {
            return runtime_error("tag " + sub + ": " + err);
        }
        std::printf("%s tag %s %s\n", sub == "add" ? "added" : "removed", args[2].c_str(),
                    id.c_str());
        return 0;
    }
    if (sub == "ls") {
        if (!src) {
            return runtime_error("tag: " + err);
        }
        if (args.size() == 2) {
            std::string id, pw;
            resolve_ref(cfg, args[1], &id, &pw);
            auto tags = src->Tags(id);
            std::sort(tags.begin(), tags.end());
            if (flags.json) {
                std::printf("{\"version\":1,\"tags\":{%s:[", json_escape(id).c_str());
                for (size_t i = 0; i < tags.size(); i++) {
                    if (i > 0) {
                        std::printf(",");
                    }
                    std::printf("%s", json_escape(tags[i]).c_str());
                }
                std::printf("]}}\n");
            } else {
                for (size_t i = 0; i < tags.size(); i++) {
                    if (i > 0) {
                        std::printf(",");
                    }
                    std::printf("%s", tags[i].c_str());
                }
                std::printf("\n");
            }
            return 0;
        }
        std::vector<rdcli::core::Device> devs;
        if (!src->List(&devs, &err)) {
            return runtime_error("tag ls: " + err);
        }
        std::map<std::string, std::vector<std::string>> all;
        for (const auto& d : devs) {
            auto tags = src->Tags(d.id);
            std::sort(tags.begin(), tags.end());
            if (!tags.empty()) {
                all[d.id] = tags;
            }
        }
        if (flags.json) {
            std::printf("{\"version\":1,\"tags\":{");
            bool first = true;
            for (const auto& kv : all) {
                if (!first) {
                    std::printf(",");
                }
                first = false;
                std::printf("%s:[", json_escape(kv.first).c_str());
                for (size_t i = 0; i < kv.second.size(); i++) {
                    if (i > 0) {
                        std::printf(",");
                    }
                    std::printf("%s", json_escape(kv.second[i]).c_str());
                }
                std::printf("]");
            }
            std::printf("}}\n");
        } else {
            for (const auto& kv : all) {
                std::printf("%s:", kv.first.c_str());
                for (size_t i = 0; i < kv.second.size(); i++) {
                    if (i > 0) {
                        std::printf(",");
                    }
                    std::printf("%s", kv.second[i].c_str());
                }
                std::printf("\n");
            }
        }
        return 0;
    }
    return usage_error("unknown tag subcommand: " + sub);
}

}  // namespace

namespace {

// Set by stop_stdin() to stop the stdin reader thread so it can be joined.
std::atomic<bool> g_stdin_stop{false};

#if !defined(_WIN32)
static termios g_saved_termios;
static bool g_raw_mode = false;
static volatile sig_atomic_t g_sigwinch = 0;

void sigwinch_handler(int) { g_sigwinch = 1; }

bool enter_raw() {
    if (::tcgetattr(STDIN_FILENO, &g_saved_termios) != 0) {
        return false;
    }
    termios raw = g_saved_termios;
    ::cfmakeraw(&raw);
    if (::tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) {
        return false;
    }
    g_raw_mode = true;
    return true;
}

void leave_raw() {
    if (g_raw_mode) {
        ::tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
        g_raw_mode = false;
    }
}

int64_t read_stdin(uint8_t* buf, size_t n) {
    // stdin has no shutdown(), so wait in slices and re-check the stop flag:
    // an input thread that cannot be woken cannot be joined.
    while (!g_stdin_stop.load()) {
        pollfd pfd{};
        pfd.fd = STDIN_FILENO;
        pfd.events = POLLIN;
        const int pr = ::poll(&pfd, 1, 200);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (pr == 0) {
            continue;
        }
        return ::read(STDIN_FILENO, buf, n);
    }
    return 0;
}
#else
static volatile int g_sigwinch = 0;
void sigwinch_handler(int) { g_sigwinch = 1; }
bool enter_raw() { return false; }
void leave_raw() {}

// Waiting on the stdin handle can't keep the read from blocking: a console
// handle is signalled by any input record (focus, mouse, key-up) and, in line
// mode, _read then waits for Enter; a pipe handle is no readiness signal at
// all. So the reading thread publishes itself here and stop_stdin() cancels
// its read outright. Non-null only while a read is in flight.
std::mutex g_stdin_mu;
HANDLE g_stdin_reader = nullptr;

int64_t read_stdin(uint8_t* buf, size_t n) {
    // CancelSynchronousIo needs THREAD_TERMINATE on the target thread.
    const HANDLE self = ::OpenThread(THREAD_TERMINATE, FALSE, ::GetCurrentThreadId());
    if (self == nullptr) {
        return -1;
    }
    {
        std::lock_guard<std::mutex> lk(g_stdin_mu);
        if (g_stdin_stop.load()) {
            ::CloseHandle(self);
            return 0;
        }
        g_stdin_reader = self;
    }
    const int r = ::_read(::_fileno(stdin), buf, static_cast<unsigned>(n));
    {
        std::lock_guard<std::mutex> lk(g_stdin_mu);
        g_stdin_reader = nullptr;
    }
    ::CloseHandle(self);
    // A cancelled read fails; once stopping was requested that is just EOF.
    return g_stdin_stop.load() ? 0 : r;
}
#endif

// Stops the stdin reader so its thread can be joined.
void stop_stdin() {
    g_stdin_stop = true;
#if defined(_WIN32)
    // Retry until the reader has left _read: a cancel issued just before it
    // enters the read finds nothing to cancel.
    while (true) {
        {
            std::lock_guard<std::mutex> lk(g_stdin_mu);
            if (g_stdin_reader == nullptr) {
                break;
            }
            ::CancelSynchronousIo(g_stdin_reader);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
#endif
}

void term_size(uint32_t* rows, uint32_t* cols) {
#if !defined(_WIN32)
    struct winsize ws {};
    if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        *cols = ws.ws_col;
        *rows = ws.ws_row;
        return;
    }
#endif
    *cols = 80;
    *rows = 24;
}

int run_sh_oneshot(const DialOpts& opts, uint32_t rows, uint32_t cols,
                   const std::string& command, int idle_ms) {
    std::string err;
    auto ts = rdcli::core::TerminalSession::Open(opts, rows, cols, &err);
    if (!ts) {
        return runtime_error(err);
    }
    if (ts->Write(reinterpret_cast<const uint8_t*>(command.c_str()), command.size()) < 0) {
        return 1;
    }
    // Submit with a carriage return, not "\n": on a Windows ConPTY the Enter
    // key is CR (0x0D), and PSReadLine treats a bare LF as a soft line-break
    // (it drops to a ">>" continuation prompt and never runs the command).
    // Unix PTYs in canonical mode map CR->NL via ICRNL, so CR submits there too.
    if (ts->Write(reinterpret_cast<const uint8_t*>("\r"), 1) < 0) {
        return 1;
    }

    std::atomic<bool> done{false};
    std::atomic<bool> had_output{false};
    std::atomic<long long> last_output{0};
    std::string err_out;
    std::thread reader([&] {
        uint8_t buf[4096];
        while (true) {
            const int64_t n = ts->Read(buf, sizeof(buf));
            if (n > 0) {
                std::fwrite(buf, 1, static_cast<size_t>(n), stdout);
                std::fflush(stdout);
                had_output = true;
                last_output = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::steady_clock::now().time_since_epoch())
                                  .count();
            }
            if (n <= 0) {
                break;
            }
        }
        done = true;
    });

    const auto start = std::chrono::steady_clock::now();
    while (!done) {
        if (had_output) {
            const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now().time_since_epoch())
                                 .count();
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - start)
                                     .count();
            if (now - last_output >= idle_ms && elapsed >= kOneShotMinWaitMs) {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    // Close() notifies the peer (Misc{close_reason}) and then shuts the socket
    // down, which wakes the reader's recv with EOF — a prior separate
    // Shutdown() call would kill the write side first and make that
    // notification fail silently. The descriptor is released only when `ts`
    // is destroyed, so join before returning: nothing may still be touching
    // `ts` (or its socket) by then.
    ts->Close();
    reader.join();
    return 0;
}

int run_sh_interactive(const DialOpts& opts, uint32_t rows, uint32_t cols) {
    std::string err;
    auto ts = rdcli::core::TerminalSession::Open(opts, rows, cols, &err);
    if (!ts) {
        return runtime_error(err);
    }
    const bool raw = enter_raw();
#if !defined(_WIN32)
    ::signal(SIGWINCH, sigwinch_handler);
#endif

    std::thread writer([&] {
        uint8_t buf[1024];
        while (true) {
            const int64_t n = read_stdin(buf, sizeof(buf));
            if (n <= 0) {
                break;
            }
            if (ts->Write(buf, static_cast<size_t>(n)) < 0) {
                break;
            }
        }
    });

    uint8_t buf[4096];
    while (true) {
        if (g_sigwinch) {
            g_sigwinch = 0;
            uint32_t r, c;
            term_size(&r, &c);
            ts->Resize(r, c);
        }
        const int64_t n = ts->Read(buf, sizeof(buf));
        if (n > 0) {
            std::fwrite(buf, 1, static_cast<size_t>(n), stdout);
            std::fflush(stdout);
        }
        if (n <= 0) {
            break;
        }
    }
    ts->Close();
    stop_stdin();
    writer.join();
    if (raw) {
        leave_raw();
    }
    return 0;
}

int cmd_sh(const Flags& flags, const std::vector<std::string>& args) {
    Config cfg;
    std::string cerr;
    cfg.load(&cerr);
    std::string id, pw;
    std::vector<std::string> rest;
    if (!resolve_target(flags, args, &cfg, &id, &pw, &rest)) {
        return usage_error("usage: rdcli sh [<ref>] [command]");
    }
    auto opts = make_dial_opts(flags, cfg, id, pw, hbb::TERMINAL);
    uint32_t rows, cols;
    term_size(&rows, &cols);
    if (rest.empty()) {
        return run_sh_interactive(opts, rows, cols);
    }
    std::string command;
    for (const auto& r : rest) {
        if (!command.empty()) {
            command += " ";
        }
        command += r;
    }
    return run_sh_oneshot(opts, rows, cols, command, flags.idle_ms > 0 ? flags.idle_ms : 300);
}

}  // namespace

namespace {

// Resolves the target peer for a command that takes [ref] then sub-args.
bool resolve_target(const Flags& flags, const std::vector<std::string>& args, Config* cfg,
                    std::string* id, std::string* pw, std::vector<std::string>* rest) {
    std::string ref;
    if (!flags.connect_ref.empty()) {
        ref = flags.connect_ref;
        *rest = args;
    } else {
        if (args.empty()) {
            return false;
        }
        ref = args[0];
        *rest = std::vector<std::string>(args.begin() + 1, args.end());
    }
    resolve_ref(*cfg, ref, id, pw);
    // An explicit --password/-p overrides whatever the config remembers.
    if (const std::string given = get_password(flags); !given.empty()) {
        *pw = given;
    }
    return true;
}

std::string ls_type_name(hbb::FileType t) {
    switch (t) {
    case hbb::Dir:
    case hbb::DirLink:
    case hbb::DirDrive:
        return "dir";
    default:
        return "file";
    }
}

int cmd_ls(const Flags& flags, const std::vector<std::string>& args) {
    Config cfg;
    std::string cerr;
    cfg.load(&cerr);
    std::string id, pw;
    std::vector<std::string> rest;
    if (!resolve_target(flags, args, &cfg, &id, &pw, &rest)) {
        return usage_error("usage: rdcli ls [<ref>] [remote_path]");
    }
    std::string remote_path = ".";
    if (!rest.empty()) {
        remote_path = rest[0];
    }
    auto opts = make_dial_opts(flags, cfg, id, pw, hbb::FILE_TRANSFER);
    std::string err;
    auto ft = rdcli::core::FileTransfer::Open(opts, remote_path, &err);
    if (!ft) {
        return runtime_error("ls: " + err);
    }
    auto dir = ft->ReadDir(remote_path, &err);
    if (!dir) {
        return runtime_error("ls: " + err);
    }
    std::vector<hbb::FileEntry> entries;
    for (const auto& e : dir->entries()) {
        entries.push_back(e);
    }
    std::sort(entries.begin(), entries.end(), [](const hbb::FileEntry& a, const hbb::FileEntry& b) {
        if (a.entry_type() != b.entry_type()) {
            return ls_type_name(a.entry_type()) == "dir";
        }
        return a.name() < b.name();
    });

    if (flags.json) {
        std::printf("{\"version\":1,\"path\":%s,\"entries\":[", json_escape(dir->path()).c_str());
        for (size_t i = 0; i < entries.size(); i++) {
            const auto& e = entries[i];
            if (i > 0) {
                std::printf(",");
            }
            std::printf("{\"name\":%s,\"type\":%s,\"size\":%llu,\"modified_time\":%llu,"
                        "\"is_hidden\":%s}",
                        json_escape(e.name()).c_str(), json_escape(ls_type_name(e.entry_type())).c_str(),
                        static_cast<unsigned long long>(e.size()),
                        static_cast<unsigned long long>(e.modified_time()),
                        e.is_hidden() ? "true" : "false");
        }
        std::printf("]}\n");
        return 0;
    }

    std::vector<std::vector<std::string>> rows = {{"NAME", "TYPE", "SIZE", "MODIFIED"}};
    for (const auto& e : entries) {
        rows.push_back({e.name(), ls_type_name(e.entry_type()), human_size(e.size()),
                        human_time(e.modified_time())});
    }
    print_aligned(rows);
    return 0;
}

bool is_remote_path(const std::string& p) {
    if (!p.empty() && p[0] == '/') {
        return true;
    }
    return p.size() >= 2 && p[1] == ':' &&
           ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z'));
}

int cmd_cp(const Flags& flags, const std::vector<std::string>& args) {
    Config cfg;
    std::string cerr;
    cfg.load(&cerr);
    std::string id, pw;
    std::vector<std::string> rest;
    if (!resolve_target(flags, args, &cfg, &id, &pw, &rest)) {
        return usage_error("usage: rdcli cp [<ref>] <src> <dst>");
    }
    bool recursive = false;
    std::string direction;
    std::vector<std::string> files;
    for (size_t i = 0; i < rest.size(); i++) {
        if (rest[i] == "-r") {
            recursive = true;
        } else if (rest[i] == "-d" && i + 1 < rest.size()) {
            direction = rest[++i];
        } else {
            files.push_back(rest[i]);
        }
    }
    if (files.size() != 2) {
        return usage_error("usage: rdcli cp [<ref>] <src> <dst>");
    }
    const std::string& src = files[0];
    const std::string& dst = files[1];

    bool up;
    const std::string d = to_lower(direction);
    if (d.empty()) {
        up = is_remote_path(dst);
    } else if (d == "up" || d == "to-remote") {
        up = true;
    } else if (d == "down" || d == "to-local") {
        up = false;
    } else {
        return usage_error("invalid direction \"" + direction + "\" (want up or down)");
    }

    if (up) {
        // Fail on a bad local source before spending a connection attempt on it.
        std::error_code ec;
        if (!std::filesystem::exists(src, ec) || ec) {
            return runtime_error("cp: " + src + ": no such file or directory");
        }
        if (std::filesystem::is_directory(src, ec) && !recursive) {
            return runtime_error("cp: " + src + " is a directory (use -r)");
        }
    }

    const std::string remote_dir = up ? dst : src;
    auto opts = make_dial_opts(flags, cfg, id, pw, hbb::FILE_TRANSFER);
    std::string err;
    auto ft = rdcli::core::FileTransfer::Open(opts, remote_dir, &err);
    if (!ft) {
        return runtime_error("cp: " + err);
    }

    rdcli::core::FileTransfer::ProgressFunc progress =
        [](int files_done, int files_total, int64_t done_bytes, int64_t total_bytes) {
            if (files_total == 0) {
                return;
            }
            int pct = 0;
            if (total_bytes > 0) {
                pct = static_cast<int>(static_cast<double>(done_bytes) / total_bytes * 100);
            }
            if (pct > 100) {
                pct = 100;
            }
            std::fprintf(stderr, "\r%d/%d files %d%%", files_done, files_total, pct);
        };

    const auto start = std::chrono::steady_clock::now();
    bool ok = up ? ft->Send(src, dst, recursive, progress, &err)
                 : ft->Receive(src, dst, progress, &err);
    if (!ok) {
        std::fprintf(stderr, "\rcp: %s\n", err.c_str());
        return 1;
    }
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - start)
                        .count();
    std::fprintf(stderr, "\rcopied in %lldms\n", static_cast<long long>(ms));
    return 0;
}

}  // namespace

namespace {

class StdioStream : public rdcli::net::Stream {
public:
    int64_t read(uint8_t* buf, size_t n) override {
        // Goes through read_stdin so Tunnel::Pipe can wake and join this
        // direction when the remote end hangs up.
        return read_stdin(buf, n);
    }
    int64_t write(const uint8_t* buf, size_t n) override {
        const size_t w = std::fwrite(buf, 1, n, stdout);
        std::fflush(stdout);
        return w == n ? static_cast<int64_t>(w) : -1;
    }
    void close() override {}
    void shutdown() override { stop_stdin(); }
    bool set_timeout(std::chrono::milliseconds) override { return true; }
    rdcli::net::Endpoint local_addr() const override { return {}; }
};

bool parse_forward_spec(const std::string& s, int* lport, std::string* host, int32_t* rport) {
    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= s.size()) {
        const size_t c = s.find(':', start);
        if (c == std::string::npos) {
            parts.push_back(s.substr(start));
            break;
        }
        parts.push_back(s.substr(start, c - start));
        start = c + 1;
    }
    if (parts.size() != 3) {
        return false;
    }
    *lport = std::atoi(parts[0].c_str());
    *rport = std::atoi(parts[2].c_str());
    *host = parts[1];
    return *lport >= 0 && *lport <= 65535 && *rport >= 1 && *rport <= 65535;
}

int cmd_tunnel(const Flags& flags, const std::vector<std::string>& args) {
    Config cfg;
    std::string cerr;
    cfg.load(&cerr);
    std::string id, pw;
    std::vector<std::string> rest;
    if (!resolve_target(flags, args, &cfg, &id, &pw, &rest)) {
        return usage_error("usage: rdcli tunnel <id> -L lport:rhost:rport [--once]");
    }
    bool once = false;
    std::string spec_str;
    for (size_t i = 0; i < rest.size(); i++) {
        if (rest[i] == "--once") {
            once = true;
        } else if ((rest[i] == "-L" || rest[i] == "--listen") && i + 1 < rest.size()) {
            spec_str = rest[++i];
        }
    }
    if (spec_str.empty()) {
        return usage_error("missing -L lport:rhost:rport");
    }
    int lport;
    std::string host;
    int32_t rport;
    if (!parse_forward_spec(spec_str, &lport, &host, &rport)) {
        return usage_error("invalid -L spec \"" + spec_str + "\", want lport:rhost:rport");
    }

    auto opts = make_dial_opts(flags, cfg, id, pw, hbb::PORT_FORWARD);
    if (once) {
        std::string err;
        auto t = rdcli::core::Tunnel::Open(opts, host, rport, &err);
        if (!t) {
            return runtime_error("tunnel: " + err);
        }
        StdioStream io;
        t->Pipe(&io);
        return 0;
    }

    auto listener = rdcli::net::listen_loopback(static_cast<uint16_t>(lport));
    if (!listener) {
        return runtime_error("tunnel: bind 127.0.0.1:" + std::to_string(lport));
    }
    std::fprintf(stderr, "listening on 127.0.0.1:%d, forwarding to %s:%d\n", lport, host.c_str(),
                 rport);

    while (auto local = listener->accept()) {
        std::thread([local = std::shared_ptr<rdcli::net::Stream>(std::move(local)), opts, host,
                     rport] {
            std::string err;
            auto t = rdcli::core::Tunnel::Open(opts, host, rport, &err);
            if (!t) {
                std::fprintf(stderr, "tunnel: %s\n", err.c_str());
                return;
            }
            t->Pipe(local.get());
        }).detach();
    }
    return 0;
}

}  // namespace
namespace {

std::string detect_peers_dir() {
    const std::string home = rdcli::config::home_dir();
    if (home.empty()) {
        return {};
    }
    const std::vector<std::string> candidates = {
        (std::filesystem::path(home) / "Library" / "Preferences" / "com.carriez.RustDesk" /
         "peers")
            .string(),
        (std::filesystem::path(home) / ".local" / "share" / "rustdesk" / "peers").string(),
        (std::filesystem::path(home) / ".config" / "rustdesk" / "peers").string(),
        (std::filesystem::path(home) / "AppData" / "Roaming" / "RustDesk" / "config" / "peers")
            .string(),
    };
    for (const auto& p : candidates) {
        std::error_code ec;
        if (std::filesystem::is_directory(p, ec)) {
            return p;
        }
    }
    return {};
}

bool parse_peer_file(const std::string& path, std::string* id, std::string* password,
                     std::string* name, std::string* platform, std::string* hostname) {
    *id = std::filesystem::path(path).filename().string();
    if (id->size() > 5 && id->substr(id->size() - 5) == ".toml") {
        *id = id->substr(0, id->size() - 5);
    }
    std::ifstream f(path);
    if (!f.is_open()) {
        return false;
    }
    std::string line;
    std::string section;
    std::vector<uint8_t> pwd;
    bool in_array = false;
    auto trim = [](const std::string& s) {
        const auto b = s.find_first_not_of(" \t\r\n");
        const auto e = s.find_last_not_of(" \t\r\n");
        return b == std::string::npos ? std::string() : s.substr(b, e - b + 1);
    };
    while (std::getline(f, line)) {
        const std::string s = trim(line);
        if (s.empty() || s[0] == '#') {
            continue;
        }
        if (in_array) {
            std::string sub = s;
            const auto br = s.find(']');
            if (br != std::string::npos) {
                sub = s.substr(0, br);
                in_array = false;
            }
            std::istringstream iss(sub);
            std::string part;
            while (std::getline(iss, part, ',')) {
                const int v = std::atoi(part.c_str());
                if (v >= 0 && v <= 255) {
                    pwd.push_back(static_cast<uint8_t>(v));
                }
            }
            continue;
        }
        if (!s.empty() && s[0] == '[' && s.back() == ']') {
            section = s.substr(1, s.size() - 2);
            continue;
        }
        const auto eq = s.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        const std::string key = trim(s.substr(0, eq));
        std::string val = trim(s.substr(eq + 1));
        const auto h = val.find('#');
        if (h != std::string::npos) {
            val = trim(val.substr(0, h));
        }
        if (key.rfind("password", 0) == 0 && section.empty()) {
            const auto br = val.find('[');
            if (br != std::string::npos) {
                std::string arr = val.substr(br + 1);
                const auto close = arr.find(']');
                if (close == std::string::npos) {
                    in_array = true;
                } else {
                    arr = arr.substr(0, close);
                }
                std::istringstream iss(arr);
                std::string part;
                while (std::getline(iss, part, ',')) {
                    const int v = std::atoi(part.c_str());
                    if (v >= 0 && v <= 255) {
                        pwd.push_back(static_cast<uint8_t>(v));
                    }
                }
            }
        } else if (section == "info" && key == "platform") {
            *platform = val;
        } else if (section == "info" && key == "hostname") {
            *hostname = val;
        }
    }
    password->assign(reinterpret_cast<const char*>(pwd.data()), pwd.size());
    if (!hostname->empty()) {
        *name = *hostname;
    }
    return true;
}

int cmd_import_gui(const Flags& flags, const std::vector<std::string>& args) {
    (void)flags;
    if (!args.empty()) {
        return usage_error("usage: rdcli import-gui");
    }
    const std::string dir = detect_peers_dir();
    if (dir.empty()) {
        return runtime_error("import-gui: no RustDesk peers directory found");
    }
    Config cfg;
    std::string cerr;
    cfg.load(&cerr);

    std::error_code ec;
    int imported = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec || entry.is_directory()) {
            continue;
        }
        const std::string name = entry.path().filename().string();
        if (name.size() < 5 || name.substr(name.size() - 5) != ".toml") {
            continue;
        }
        std::string id, password, pname, platform, hostname;
        if (!parse_peer_file(entry.path().string(), &id, &password, &pname, &platform,
                             &hostname) ||
            id.empty()) {
            continue;
        }
        cfg.set_peers_password(id, password);
        if (!pname.empty()) {
            cfg.peers[id].name = pname;
        }
        if (!platform.empty()) {
            cfg.add_tag(id, to_lower(platform));
        } else if (!hostname.empty()) {
            cfg.add_tag(id, to_lower(hostname));
        }
        imported++;
    }
    if (!cfg.save(&cerr)) {
        return runtime_error("import-gui: " + cerr);
    }
    std::printf("imported %d peers\n", imported);
    return 0;
}

void print_usage(std::FILE* out) {
    std::fprintf(out,
                 "rdcli — headless RustDesk client CLI\n\n"
                 "usage: rdcli <command> [args] [flags]\n\n"
                 "commands:\n"
                 "  version                 print version\n"
                 "  ping <id>               check if peer is online\n"
                 "  connect <ref>           save machine password\n"
                 "  disconnect <ref>        forget saved password\n"
                 "  auth <sub>              manage login token\n"
                 "  devices [search <q>]    list machines\n"
                 "  tag add|rm|ls           tag management\n"
                 "  ls [<ref>] [path]       remote directory listing\n"
                 "  cp [<ref>] <src> <dst>  copy files (-r recursive)\n"
                 "  sh [<ref>] [command]    remote shell\n"
                 "  tunnel [<ref>] -L ...   TCP tunnel (--once for pipe mode)\n"
                 "  import-gui              import peers from RustDesk\n\n"
                 "flags: --password/-p --server --key --token -c --relay --yes --json --timeout\n"
                 "       --idle <dur>  one-shot sh idle timeout, e.g. 300ms or 5s\n");
}

}  // namespace


namespace {

int run(int argc, char** argv) {
    Flags flags;
    std::vector<std::string> args;
    if (!parse_args(argc, argv, &flags, &args)) {
        return usage_error("invalid flag value");
    }
    if (args.empty()) {
        print_usage(stderr);
        return 2;
    }

    const std::string& cmd = args[0];
    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        print_usage(stdout);
        return 0;
    }
    const std::vector<std::string> rest(args.begin() + 1, args.end());

    if (cmd == "version") {
        return cmd_version();
    }
    if (cmd == "ping") {
        return cmd_ping(flags, rest);
    }
    if (cmd == "connect") {
        return cmd_connect(flags, rest, false);
    }
    if (cmd == "disconnect") {
        return cmd_connect(flags, rest, true);
    }
    if (cmd == "auth") {
        return cmd_auth(flags, rest);
    }
    if (cmd == "devices") {
        return cmd_devices(flags, rest);
    }
    if (cmd == "tag") {
        return cmd_tag(flags, rest);
    }
    if (cmd == "ls") {
        return cmd_ls(flags, rest);
    }
    if (cmd == "cp") {
        return cmd_cp(flags, rest);
    }
    if (cmd == "sh") {
        return cmd_sh(flags, rest);
    }
    if (cmd == "tunnel") {
        return cmd_tunnel(flags, rest);
    }
    if (cmd == "import-gui") {
        return cmd_import_gui(flags, rest);
    }
    return usage_error("unknown command: " + cmd);
}

}  // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
#if !defined(_WIN32)
    // A peer that hangs up mid-transfer must surface as a write error, not as
    // SIGPIPE killing the process without a word.
    ::signal(SIGPIPE, SIG_IGN);
#endif
    try {
        return run(argc, argv);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "rdcli: %s\n", e.what());
        return 1;
    } catch (...) {
        std::fprintf(stderr, "rdcli: unknown fatal error\n");
        return 1;
    }
}

