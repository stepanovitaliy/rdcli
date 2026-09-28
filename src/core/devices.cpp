#include "core/devices.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <string>
#include <vector>

#include <curl/curl.h>

#include "core/rendezvous.h"

namespace rdcli::core {

namespace {

struct Json {
    enum Type { Null, Bool, Num, Str, Arr, Obj };
    Type type = Null;
    bool b = false;
    double num = 0;
    std::string str;
    std::vector<Json> arr;
    std::vector<std::pair<std::string, Json>> obj;

    const Json* find(const std::string& key) const {
        for (const auto& kv : obj) {
            if (kv.first == key) {
                return &kv.second;
            }
        }
        return nullptr;
    }
};

class JsonParser {
public:
    explicit JsonParser(const std::string& s) : s_(s) {}
    bool parse(Json* out) {
        skip_ws();
        if (!parse_value(out)) {
            return false;
        }
        skip_ws();
        return pos_ == s_.size();
    }

private:
    const std::string& s_;
    size_t pos_ = 0;

    void skip_ws() {
        while (pos_ < s_.size() && (s_[pos_] == ' ' || s_[pos_] == '\t' || s_[pos_] == '\n' ||
                                    s_[pos_] == '\r')) {
            pos_++;
        }
    }
    bool parse_value(Json* out) {
        if (pos_ >= s_.size()) {
            return false;
        }
        const char c = s_[pos_];
        if (c == '{') {
            return parse_object(out);
        }
        if (c == '[') {
            return parse_array(out);
        }
        if (c == '"') {
            out->type = Json::Str;
            return parse_string(&out->str);
        }
        if (c == 't' || c == 'f') {
            out->type = Json::Bool;
            if (s_.compare(pos_, 4, "true") == 0) {
                out->b = true;
                pos_ += 4;
            } else if (s_.compare(pos_, 5, "false") == 0) {
                out->b = false;
                pos_ += 5;
            } else {
                return false;
            }
            return true;
        }
        if (c == 'n') {
            if (s_.compare(pos_, 4, "null") == 0) {
                out->type = Json::Null;
                pos_ += 4;
                return true;
            }
            return false;
        }
        out->type = Json::Num;
        return parse_number(out);
    }
    bool parse_object(Json* out) {
        out->type = Json::Obj;
        pos_++;
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == '}') {
            pos_++;
            return true;
        }
        while (true) {
            skip_ws();
            std::string key;
            if (!parse_string(&key)) {
                return false;
            }
            skip_ws();
            if (pos_ >= s_.size() || s_[pos_] != ':') {
                return false;
            }
            pos_++;
            skip_ws();
            Json val;
            if (!parse_value(&val)) {
                return false;
            }
            out->obj.emplace_back(std::move(key), std::move(val));
            skip_ws();
            if (pos_ < s_.size() && s_[pos_] == ',') {
                pos_++;
                continue;
            }
            if (pos_ < s_.size() && s_[pos_] == '}') {
                pos_++;
                return true;
            }
            return false;
        }
    }
    bool parse_array(Json* out) {
        out->type = Json::Arr;
        pos_++;
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == ']') {
            pos_++;
            return true;
        }
        while (true) {
            skip_ws();
            Json val;
            if (!parse_value(&val)) {
                return false;
            }
            out->arr.push_back(std::move(val));
            skip_ws();
            if (pos_ < s_.size() && s_[pos_] == ',') {
                pos_++;
                continue;
            }
            if (pos_ < s_.size() && s_[pos_] == ']') {
                pos_++;
                return true;
            }
            return false;
        }
    }
    bool parse_string(std::string* out) {
        if (pos_ >= s_.size() || s_[pos_] != '"') {
            return false;
        }
        pos_++;
        while (pos_ < s_.size()) {
            const char c = s_[pos_];
            if (c == '"') {
                pos_++;
                return true;
            }
            if (c == '\\' && pos_ + 1 < s_.size()) {
                pos_++;
                switch (s_[pos_]) {
                case 'n':
                    out->push_back('\n');
                    break;
                case 't':
                    out->push_back('\t');
                    break;
                case '"':
                    out->push_back('"');
                    break;
                case '\\':
                    out->push_back('\\');
                    break;
                case 'r':
                    out->push_back('\r');
                    break;
                default:
                    out->push_back(s_[pos_]);
                }
                pos_++;
                continue;
            }
            out->push_back(c);
            pos_++;
        }
        return false;
    }
    bool parse_number(Json* out) {
        const size_t start = pos_;
        while (pos_ < s_.size() &&
               (std::isdigit(static_cast<unsigned char>(s_[pos_])) || s_[pos_] == '-' ||
                s_[pos_] == '.' || s_[pos_] == 'e' || s_[pos_] == 'E' || s_[pos_] == '+')) {
            pos_++;
        }
        if (pos_ == start) {
            return false;
        }
        out->num = std::strtod(s_.substr(start, pos_ - start).c_str(), nullptr);
        return true;
    }
};

size_t write_cb(void* data, size_t size, size_t nmemb, void* userp) {
    const size_t total = size * nmemb;
    auto* s = static_cast<std::string*>(userp);
    s->append(static_cast<const char*>(data), total);
    return total;
}

}  // namespace

namespace {

struct HttpResponse {
    long status = 0;
    std::string body;
};

bool http_req(const std::string& method, const std::string& url, const std::string& body,
              const std::vector<std::string>& headers, HttpResponse* out, std::string* err) {
    CURL* c = curl_easy_init();
    if (!c) {
        *err = "curl init";
        return false;
    }
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    curl_slist* hs = nullptr;
    for (const auto& h : headers) {
        hs = curl_slist_append(hs, h.c_str());
    }
    if (hs) {
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, hs);
    }
    if (!body.empty()) {
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.c_str());
    }
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &out->body);
    const CURLcode res = curl_easy_perform(c);
    if (res != CURLE_OK) {
        *err = std::string("http: ") + curl_easy_strerror(res);
        curl_slist_free_all(hs);
        curl_easy_cleanup(c);
        return false;
    }
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &out->status);
    curl_slist_free_all(hs);
    curl_easy_cleanup(c);
    return true;
}

struct ApiEntry {
    std::string id;
    std::string name;
    std::string platform;
    std::vector<std::string> tags;
};

class LocalSource : public DeviceSource {
public:
    explicit LocalSource(config::Config* cfg) : cfg_(cfg) {}

    bool List(std::vector<Device>* out, std::string* err) override {
        std::map<std::string, bool> id_map;
        for (const auto& kv : cfg_->tags) {
            id_map[kv.first] = true;
        }
        for (const auto& kv : cfg_->peers) {
            id_map[kv.first] = true;
        }
        std::vector<std::string> ids;
        for (const auto& kv : id_map) {
            ids.push_back(kv.first);
        }
        std::sort(ids.begin(), ids.end());
        for (const auto& id : ids) {
            Device d;
            d.id = id;
            d.source = "local";
            auto it = cfg_->peers.find(id);
            if (it != cfg_->peers.end()) {
                d.name = it->second.name;
            }
            d.tags = cfg_->tags_for(id);
            std::sort(d.tags.begin(), d.tags.end());
            out->push_back(std::move(d));
        }
        (void)err;
        return true;
    }

    std::vector<std::string> Tags(const std::string& id) override { return cfg_->tags_for(id); }

    bool AddTag(const std::string& id, const std::string& tag, std::string* err) override {
        cfg_->add_tag(id, tag);
        return cfg_->save(err);
    }

    bool RemoveTag(const std::string& id, const std::string& tag, std::string* err) override {
        cfg_->remove_tag(id, tag);
        return cfg_->save(err);
    }

private:
    config::Config* cfg_;
};

}  // namespace



namespace {

class ApiSource : public DeviceSource {
public:
    ApiSource(std::string base, std::string token, std::vector<ApiEntry> entries)
        : base_(std::move(base)), token_(std::move(token)) {
        for (auto& e : entries) {
            if (!e.id.empty()) {
                entries_[e.id] = std::move(e);
            }
        }
    }

    bool List(std::vector<Device>* out, std::string* err) override {
        std::vector<std::string> ids;
        for (const auto& kv : entries_) {
            ids.push_back(kv.first);
        }
        std::sort(ids.begin(), ids.end());
        for (const auto& id : ids) {
            const auto& e = entries_[id];
            Device d;
            d.id = id;
            d.name = e.name;
            d.platform = e.platform;
            d.tags = e.tags;
            std::sort(d.tags.begin(), d.tags.end());
            d.source = "api";
            out->push_back(std::move(d));
        }
        (void)err;
        return true;
    }

    std::vector<std::string> Tags(const std::string& id) override {
        const auto it = entries_.find(id);
        return it == entries_.end() ? std::vector<std::string>() : it->second.tags;
    }

    bool AddTag(const std::string& id, const std::string& tag, std::string* err) override {
        return set_tag(id, tag, true, err);
    }

    bool RemoveTag(const std::string& id, const std::string& tag, std::string* err) override {
        return set_tag(id, tag, false, err);
    }

private:
    bool set_tag(const std::string& id, const std::string& tag, bool add, std::string* err) {
        auto it = entries_.find(id);
        if (it == entries_.end()) {
            *err = "unknown device";
            return false;
        }
        std::vector<std::string> tags = it->second.tags;
        tags.erase(std::remove(tags.begin(), tags.end(), tag), tags.end());
        if (add) {
            tags.push_back(tag);
            std::sort(tags.begin(), tags.end());
        }
        return put_ab(id, tags, err);
    }

    bool put_ab(const std::string& id, const std::vector<std::string>& tags, std::string* err) {
        std::vector<std::string> ids;
        for (const auto& kv : entries_) {
            ids.push_back(kv.first);
        }
        std::sort(ids.begin(), ids.end());
        std::string body = "[";
        bool first = true;
        for (const auto& k : ids) {
            ApiEntry e = entries_[k];
            if (k == id) {
                e.tags = tags;
            }
            if (!first) {
                body += ",";
            }
            first = false;
            body += json_entry(e);
        }
        body += "]";

        HttpResponse resp;
        if (!http_req("PUT", base_ + "/api/ab", body,
                      {"Content-Type: application/json", "Authorization: Bearer " + token_},
                      &resp, err)) {
            return false;
        }
        if (resp.status < 200 || resp.status >= 300) {
            *err = "tag management not supported by this api server";
            return false;
        }
        return true;
    }

    static std::string json_str(const std::string& s) {
        std::string out = "\"";
        for (char c : s) {
            if (c == '"' || c == '\\') {
                out.push_back('\\');
            }
            out.push_back(c);
        }
        out += "\"";
        return out;
    }

    static std::string json_entry(const ApiEntry& e) {
        std::string out = "{\"id\":" + json_str(e.id) + ",\"name\":" + json_str(e.name) +
                          ",\"platform\":" + json_str(e.platform) + ",\"tags\":[";
        for (size_t i = 0; i < e.tags.size(); i++) {
            if (i > 0) {
                out += ",";
            }
            out += json_str(e.tags[i]);
        }
        out += "]}";
        return out;
    }

    std::string base_;
    std::string token_;
    std::map<std::string, ApiEntry> entries_;
};

}  // namespace


namespace {

std::string api_login(const std::string& base, const std::string& username,
                      const std::string& password, std::string* err) {
    const std::string body =
        "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
    HttpResponse resp;
    if (!http_req("POST", base + "/api/login", body, {"Content-Type: application/json"}, &resp,
                  err)) {
        return {};
    }
    if (resp.status < 200 || resp.status >= 300) {
        *err = "api login failed: status " + std::to_string(resp.status);
        return {};
    }
    Json j;
    JsonParser p(resp.body);
    if (!p.parse(&j)) {
        *err = "decode login response";
        return {};
    }
    if (const Json* tok = j.find("access_token")) {
        if (tok->type == Json::Str) {
            return tok->str;
        }
    }
    *err = "api login response missing access_token";
    return {};
}

std::vector<ApiEntry> api_get_ab(const std::string& base, const std::string& token,
                                 std::string* err) {
    HttpResponse resp;
    if (!http_req("GET", base + "/api/ab", "", {"Authorization: Bearer " + token}, &resp, err)) {
        return {};
    }
    if (resp.status < 200 || resp.status >= 300) {
        *err = "address book failed: status " + std::to_string(resp.status);
        return {};
    }
    Json j;
    JsonParser p(resp.body);
    if (!p.parse(&j)) {
        *err = "decode address book";
        return {};
    }
    const Json* arr = &j;
    if (j.type == Json::Obj) {
        if (const Json* d = j.find("data")) {
            arr = d;
        }
    }
    if (arr->type != Json::Arr) {
        *err = "decode address book";
        return {};
    }
    std::vector<ApiEntry> entries;
    for (const auto& e : arr->arr) {
        ApiEntry entry;
        if (const Json* id = e.find("id")) {
            entry.id = id->str;
        }
        if (const Json* name = e.find("name")) {
            entry.name = name->str;
        }
        if (const Json* platform = e.find("platform")) {
            entry.platform = platform->str;
        }
        if (const Json* tags = e.find("tags")) {
            for (const auto& t : tags->arr) {
                entry.tags.push_back(t.str);
            }
        }
        if (!entry.id.empty()) {
            entries.push_back(std::move(entry));
        }
    }
    return entries;
}

}  // namespace

std::unique_ptr<DeviceSource> NewDeviceSource(config::Config* cfg, std::string* err) {
    if (cfg && !cfg->api_server.empty()) {
        std::string base = cfg->api_server;
        while (!base.empty() && base.back() == '/') {
            base.pop_back();
        }
        const std::string token = api_login(base, cfg->api_username, cfg->api_password, err);
        if (token.empty()) {
            return nullptr;
        }
        auto entries = api_get_ab(base, token, err);
        if (err && !err->empty()) {
            return nullptr;
        }
        return std::make_unique<ApiSource>(std::move(base), token, std::move(entries));
    }
    return std::make_unique<LocalSource>(cfg);
}

std::map<std::string, bool> BatchOnline(const std::string& server,
                                        const std::vector<std::string>& ids,
                                        std::chrono::milliseconds timeout) {
    auto res = query_online(server, ids, timeout);
    std::map<std::string, bool> m;
    if (!res) {
        for (const auto& id : ids) {
            m[id] = false;
        }
        return m;
    }
    return res->online;
}

}  // namespace rdcli::core
