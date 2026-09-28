#include "core/file_transfer.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include <zstd.h>

#include <sys/stat.h>
#if defined(_WIN32)
#include <sys/utime.h>
#else
#include <sys/time.h>
#endif

#include "proto/message.pb.h"

namespace rdcli::core {

namespace fs = std::filesystem;

namespace {

constexpr size_t kFileBlockSize = 64 * 1024;

std::optional<std::string> zstd_compress(const std::string& data) {
    const size_t bound = ZSTD_compressBound(data.size());
    std::string out(bound, '\0');
    const size_t n = ZSTD_compress(out.data(), out.size(), data.data(), data.size(), 3);
    if (ZSTD_isError(n)) {
        return std::nullopt;
    }
    out.resize(n);
    return out;
}

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

std::string lower_ext(const std::string& path) {
    const std::string ext = fs::path(path).extension().string();
    std::string out;
    out.reserve(ext.size());
    for (char c : ext) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

bool is_compressed_name(const std::string& path) {
    const std::string ext = lower_ext(path);
    return ext == ".xz" || ext == ".gz" || ext == ".zip" || ext == ".7z" || ext == ".rar" ||
           ext == ".bz2" || ext == ".tgz" || ext == ".png" || ext == ".jpg";
}

uint64_t file_modified_unix(const fs::path& p) {
#if defined(_WIN32)
    struct _stat64 st {};
    if (::_stat64(p.string().c_str(), &st) != 0) {
        return 0;
    }
    return static_cast<uint64_t>(st.st_mtime);
#else
    struct stat st {};
    if (::stat(p.c_str(), &st) != 0) {
        return 0;
    }
    return static_cast<uint64_t>(st.st_mtime);
#endif
}

void set_file_mtime(const fs::path& p, uint64_t unix_sec) {
#if defined(_WIN32)
    struct _utimbuf t {};
    t.actime = static_cast<time_t>(unix_sec);
    t.modtime = static_cast<time_t>(unix_sec);
    ::_utime(p.string().c_str(), &t);
#else
    struct timeval tv[2];
    tv[0].tv_sec = static_cast<time_t>(unix_sec);
    tv[0].tv_usec = 0;
    tv[1].tv_sec = static_cast<time_t>(unix_sec);
    tv[1].tv_usec = 0;
    ::utimes(p.c_str(), tv);
#endif
}

}  // namespace


FileTransfer::~FileTransfer() {
    if (conn_) {
        conn_->Close();
    }
}

std::unique_ptr<FileTransfer> FileTransfer::Open(const DialOpts& opts, const std::string& dir,
                                                 std::string* err) {
    DialOpts o = opts;
    o.conn_type = hbb::FILE_TRANSFER;
    auto c = Conn::Connect(o, err);
    if (!c) {
        return nullptr;
    }
    LoginSpec spec;
    spec.dir = dir;
    auto pi = c->Login(LoginKind::FileTransfer, spec, err);
    if (!pi) {
        return nullptr;
    }
    auto ft = std::unique_ptr<FileTransfer>(new FileTransfer());
    ft->conn_ = std::move(c);
    ft->overwrite_enabled_ = version_at_least(pi->version(), "1.1.10");
    ft->next_id_ = 1;
    return ft;
}

int32_t FileTransfer::next_job_id() { return next_id_++; }

bool FileTransfer::send_action(const hbb::FileAction& a) {
    hbb::Message msg;
    *msg.mutable_file_action() = a;
    return conn_->Send(msg);
}

bool FileTransfer::send_block(const hbb::FileTransferBlock& b) {
    hbb::Message msg;
    msg.mutable_file_response()->mutable_block()->CopyFrom(b);
    return conn_->Send(msg);
}

bool FileTransfer::send_done(int32_t id, int32_t file_num) {
    hbb::Message msg;
    auto* done = msg.mutable_file_response()->mutable_done();
    done->set_id(id);
    done->set_file_num(file_num);
    return conn_->Send(msg);
}

std::optional<hbb::FileDirectory> FileTransfer::ReadDir(const std::string& path,
                                                        std::string* err) {
    hbb::FileAction a;
    a.mutable_read_dir()->set_path(path);
    if (!send_action(a)) {
        *err = "hbb: send read_dir";
        return std::nullopt;
    }
    while (true) {
        auto msg = conn_->Recv();
        if (!msg) {
            *err = "hbb: recv read_dir";
            return std::nullopt;
        }
        if (!msg->has_file_response()) {
            continue;
        }
        const auto& fr = msg->file_response();
        switch (fr.union_case()) {
        case hbb::FileResponse::kDir:
            return fr.dir();
        case hbb::FileResponse::kError:
            *err = fr.error().error();
            return std::nullopt;
        default:
            *err = "unexpected file response";
            return std::nullopt;
        }
    }
}

bool FileTransfer::CreateDir(const std::string& path, std::string* err) {
    const int32_t id = next_job_id();
    hbb::FileAction a;
    auto* c = a.mutable_create();
    c->set_id(id);
    c->set_path(path);
    if (!send_action(a)) {
        *err = "hbb: send create dir";
        return false;
    }
    while (true) {
        auto msg = conn_->Recv();
        if (!msg) {
            *err = "hbb: recv create dir";
            return false;
        }
        if (!msg->has_file_response()) {
            continue;
        }
        const auto& fr = msg->file_response();
        switch (fr.union_case()) {
        case hbb::FileResponse::kDone:
            return true;
        case hbb::FileResponse::kError:
            *err = fr.error().error();
            return false;
        default:
            break;
        }
    }
}

std::optional<std::vector<hbb::FileEntry>> FileTransfer::ReadAllFiles(const std::string& path,
                                                                      std::string* err) {
    const int32_t id = next_job_id();
    hbb::FileAction a;
    auto* af = a.mutable_all_files();
    af->set_id(id);
    af->set_path(path);
    if (!send_action(a)) {
        *err = "hbb: send all files";
        return std::nullopt;
    }
    std::vector<hbb::FileEntry> entries;
    while (true) {
        auto msg = conn_->Recv();
        if (!msg) {
            *err = "hbb: recv all files";
            return std::nullopt;
        }
        if (!msg->has_file_response()) {
            continue;
        }
        const auto& fr = msg->file_response();
        switch (fr.union_case()) {
        case hbb::FileResponse::kDir:
            for (const auto& e : fr.dir().entries()) {
                entries.push_back(e);
            }
            break;
        case hbb::FileResponse::kDone:
            return entries;
        case hbb::FileResponse::kError:
            *err = fr.error().error();
            return std::nullopt;
        default:
            break;
        }
    }
}

std::vector<FileTransfer::Job> FileTransfer::build_send_jobs(const std::string& local_path,
                                                             const std::string& remote_dir,
                                                             bool recursive, std::string* err) {
    std::error_code ec;
    const fs::path lp(local_path);
    const auto fi = fs::status(lp, ec);
    if (ec) {
        *err = "stat " + local_path + ": " + ec.message();
        return {};
    }
    // fs::status reports a missing path as file_type::not_found without
    // setting ec, so absence has to be checked explicitly.
    if (!fs::exists(fi)) {
        *err = local_path + ": no such file or directory";
        return {};
    }

    if (!fs::is_directory(fi)) {
        const uintmax_t sz = fs::file_size(lp, ec);
        if (ec) {
            *err = "stat " + local_path + ": " + ec.message();
            return {};
        }
        hbb::FileEntry e;
        e.set_name(lp.filename().string());
        e.set_entry_type(hbb::File);
        e.set_size(sz);
        e.set_modified_time(file_modified_unix(lp));
        Job j;
        j.local_path = lp.parent_path().string();
        j.remote_path = remote_dir;
        j.files.push_back(std::move(e));
        return {std::move(j)};
    }
    if (!recursive) {
        *err = local_path + " is a directory (use -r to copy recursively)";
        return {};
    }

    std::vector<Job> jobs;
    fs::recursive_directory_iterator it(lp, fs::directory_options::skip_permission_denied, ec);
    fs::recursive_directory_iterator end;
    for (; !ec && it != end; it.increment(ec)) {
        if (!it->is_directory(ec)) {
            continue;
        }
        const fs::path p = it->path();
        const fs::path rel = fs::relative(p, lp, ec);
        std::string remote = remote_dir;
        if (!rel.empty() && rel.string() != ".") {
            remote = (fs::path(remote_dir) / rel).string();
        }

        std::vector<fs::path> names;
        fs::directory_iterator dit(p, ec);
        fs::directory_iterator dend;
        for (; !ec && dit != dend; dit.increment(ec)) {
            if (!dit->is_directory(ec)) {
                names.push_back(dit->path());
            }
        }
        std::sort(names.begin(), names.end());

        std::vector<hbb::FileEntry> entries;
        for (const auto& np : names) {
            const std::string name = np.filename().string();
            if (!name.empty() && name[0] == '.') {
                continue;
            }
            hbb::FileEntry e;
            e.set_name(name);
            e.set_entry_type(hbb::File);
            e.set_size(fs::file_size(np, ec));
            e.set_modified_time(file_modified_unix(np));
            entries.push_back(std::move(e));
        }
        Job j;
        j.local_path = p.string();
        j.remote_path = remote;
        j.files = std::move(entries);
        jobs.push_back(std::move(j));
    }
    if (ec) {
        *err = "walk " + local_path;
        return {};
    }
    return jobs;
}

bool FileTransfer::ensure_remote_dirs(const std::string& remote_dir,
                                      const std::vector<Job>& jobs, std::string* err) {
    std::vector<std::string> seen;
    std::vector<std::string> dirs;
    for (const auto& j : jobs) {
        std::string p = j.remote_path;
        while (true) {
            if (std::find(seen.begin(), seen.end(), p) == seen.end()) {
                seen.push_back(p);
                dirs.push_back(p);
            }
            if (p == remote_dir) {
                break;
            }
            const std::string parent = fs::path(p).parent_path().string();
            if (parent == p || parent.size() < remote_dir.size()) {
                break;
            }
            p = parent;
        }
    }
    std::sort(dirs.begin(), dirs.end(), [](const std::string& a, const std::string& b) {
        const auto da = std::count(a.begin(), a.end(), '/');
        const auto db = std::count(b.begin(), b.end(), '/');
        if (da != db) {
            return da < db;
        }
        return a < b;
    });
    for (const auto& d : dirs) {
        std::string ce;
        if (!CreateDir(d, &ce) && ce.find("exists") == std::string::npos) {
            *err = "create remote dir " + d + ": " + ce;
            return false;
        }
    }
    return true;
}

bool FileTransfer::Send(const std::string& local_path, const std::string& remote_dir,
                        bool recursive, const ProgressFunc& progress, std::string* err) {
    auto jobs = build_send_jobs(local_path, remote_dir, recursive, err);
    if (!err->empty() && jobs.empty()) {
        return false;
    }
    if (jobs.empty()) {
        return true;
    }
    if (!ensure_remote_dirs(remote_dir, jobs, err)) {
        return false;
    }

    int total_files = 0;
    int64_t total_bytes = 0;
    for (const auto& j : jobs) {
        total_files += static_cast<int>(j.files.size());
        for (const auto& f : j.files) {
            total_bytes += static_cast<int64_t>(f.size());
        }
    }
    int files_done = 0;
    int64_t done_bytes = 0;
    if (progress) {
        progress(files_done, total_files, done_bytes, total_bytes);
    }

    for (const auto& j : jobs) {
        if (j.files.empty()) {
            continue;
        }
        if (!send_job(j, progress, &files_done, total_files, &done_bytes, total_bytes, err)) {
            return false;
        }
        if (progress) {
            progress(files_done, total_files, done_bytes, total_bytes);
        }
    }
    return true;
}


namespace {

bool parse_digest(const std::string& data, uint64_t* size, uint64_t* modified) {
    const auto parse_num = [&](const std::string& key, uint64_t* out) -> bool {
        const auto pos = data.find("\"" + key + "\"");
        if (pos == std::string::npos) {
            return false;
        }
        const auto colon = data.find(':', pos);
        if (colon == std::string::npos) {
            return false;
        }
        size_t i = colon + 1;
        while (i < data.size() && (data[i] == ' ' || data[i] == '\t')) {
            i++;
        }
        uint64_t v = 0;
        bool any = false;
        while (i < data.size() && data[i] >= '0' && data[i] <= '9') {
            v = v * 10 + static_cast<uint64_t>(data[i] - '0');
            any = true;
            i++;
        }
        if (!any) {
            return false;
        }
        *out = v;
        return true;
    };
    return parse_num("size", size) && parse_num("modified", modified);
}

void overwrite_decision(const std::string& dst, const hbb::FileTransferDigest& d, bool* skip,
                        uint32_t* offset) {
    *skip = false;
    *offset = 0;
    std::error_code ec;
    if (fs::is_regular_file(dst, ec)) {
        const uint64_t sz = fs::file_size(dst, ec);
        if (!ec && sz == d.file_size() && file_modified_unix(dst) == d.last_modified()) {
            *skip = true;
            return;
        }
    }
    if (d.is_resume()) {
        std::ifstream f(dst + ".digest");
        if (f.is_open()) {
            std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            uint64_t size = 0;
            uint64_t modified = 0;
            if (parse_digest(data, &size, &modified) && size == d.file_size() &&
                modified == d.last_modified()) {
                if (fs::is_regular_file(dst + ".download", ec) && !ec) {
                    const uint64_t sz = fs::file_size(dst + ".download", ec);
                    if (!ec && sz > 0) {
                        *offset = static_cast<uint32_t>(sz);
                    }
                }
            }
        }
    }
}

void finalize_download(const std::string& dst, const hbb::FileEntry& entry, std::string* err) {
    std::error_code ec;
    fs::remove(dst + ".digest", ec);
    fs::rename(dst + ".download", dst, ec);
    if (ec) {
        *err = "finalize " + dst;
        return;
    }
    if (entry.modified_time() > 0) {
        set_file_mtime(dst, entry.modified_time());
    }
}

}  // namespace

bool FileTransfer::Receive(const std::string& remote_path, const std::string& local_path,
                           const ProgressFunc& progress, std::string* err) {
    const int32_t id = next_job_id();
    hbb::FileAction a;
    auto* s = a.mutable_send();
    s->set_id(id);
    s->set_path(remote_path);
    s->set_file_num(0);
    s->set_file_type(hbb::FileTransferSendRequest_FileType_Generic);
    if (!send_action(a)) {
        *err = "hbb: send request";
        return false;
    }

    std::vector<hbb::FileEntry> files;
    std::ofstream cur;
    bool cur_open = false;
    int32_t cur_num = -1;
    std::vector<bool> skipped;
    std::vector<uint32_t> resume_offset;
    int files_done = 0;
    int64_t done_bytes = 0;
    int64_t total_bytes = 0;

    std::error_code ec;
    bool single_target = true;
    if (!local_path.empty() && (local_path.back() == '/' || local_path.back() == '\\')) {
        single_target = false;
    }
    if (fs::is_directory(local_path, ec)) {
        single_target = false;
    }

    auto dst_for = [&](int32_t num) {
        if (single_target && num == 0 && files.size() == 1) {
            return local_path;
        }
        if (num >= static_cast<int32_t>(files.size())) {
            return local_path;
        }
        return (fs::path(local_path) / files[num].name()).string();
    };
    auto report = [&]() {
        if (progress) {
            progress(files_done, static_cast<int>(files.size()), done_bytes, total_bytes);
        }
    };
    auto close_cur = [&]() {
        if (cur_open) {
            cur.close();
            cur_open = false;
        }
    };
    std::vector<bool> started;
    std::vector<bool> finished;
    // finish closes and renames a received (or counts a skipped) file once.
    auto finish = [&](int32_t n) -> bool {
        if (n < 0 || n >= static_cast<int32_t>(files.size()) || finished[n] ||
            !(started[n] || skipped[n])) {
            return true;
        }
        finished[n] = true;
        if (n == cur_num) {
            close_cur();
        }
        if (!skipped[n]) {
            finalize_download(dst_for(n), files[n], err);
            if (!err->empty()) {
                return false;
            }
        }
        files_done++;
        report();
        return true;
    };

    while (true) {
        auto msg = conn_->Recv();
        if (!msg) {
            close_cur();
            *err = "hbb: recv file";
            return false;
        }
        if (!msg->has_file_response()) {
            continue;
        }
        const auto& fr = msg->file_response();
        switch (fr.union_case()) {
        case hbb::FileResponse::kError:
            close_cur();
            *err = fr.error().error();
            return false;
        case hbb::FileResponse::kDir:
            // Ignore the login-time directory listing (id 0); only our job's
            // listing describes the files being sent.
            if (files.empty() && fr.dir().id() == id) {
                for (const auto& e : fr.dir().entries()) {
                    files.push_back(e);
                }
                skipped.assign(files.size(), false);
                resume_offset.assign(files.size(), 0);
                started.assign(files.size(), false);
                finished.assign(files.size(), false);
                for (const auto& f : files) {
                    total_bytes += static_cast<int64_t>(f.size());
                }
                report();
            }
            break;
        case hbb::FileResponse::kDigest: {
            const auto& d = fr.digest();
            if (d.id() != id || d.file_num() >= static_cast<int32_t>(files.size())) {
                break;
            }
            bool skip = false;
            uint32_t offset = 0;
            overwrite_decision(dst_for(d.file_num()), d, &skip, &offset);
            hbb::FileAction confirm;
            auto* sc = confirm.mutable_send_confirm();
            sc->set_id(id);
            sc->set_file_num(d.file_num());
            if (skip) {
                sc->set_skip(true);
                skipped[d.file_num()] = true;
            } else {
                sc->set_offset_blk(offset);
                resume_offset[d.file_num()] = offset;
            }
            if (!send_action(confirm)) {
                close_cur();
                *err = "hbb: send confirm";
                return false;
            }
            break;
        }
        case hbb::FileResponse::kBlock: {
            const auto& b = fr.block();
            if (b.id() != id) {
                break;
            }
            if (b.file_num() != cur_num) {
                if (!finish(cur_num)) {
                    return false;
                }
                close_cur();
                cur_num = b.file_num();
                if (cur_num < 0 || cur_num >= static_cast<int32_t>(files.size())) {
                    *err = "file number out of range";
                    return false;
                }
                started[cur_num] = true;
                const std::string dst = dst_for(cur_num);
                fs::create_directories(fs::path(dst).parent_path(), ec);
                const std::string dp = dst + ".download";
                // Append only when resuming; otherwise a stale .download from
                // an aborted earlier transfer would be silently prepended to
                // the new one.
                const uint32_t off = cur_num < static_cast<int32_t>(resume_offset.size())
                                         ? resume_offset[cur_num]
                                         : 0;
                cur.open(dp, std::ios::binary |
                                 (off > 0 ? std::ios::app : std::ios::trunc));
                if (!cur.is_open()) {
                    *err = "open " + dp;
                    return false;
                }
                cur_open = true;
            }
            std::string data = b.data();
            if (b.compressed()) {
                auto plain = zstd_decompress(data);
                if (!plain) {
                    close_cur();
                    *err = "decompress block";
                    return false;
                }
                data = std::move(*plain);
            }
            cur.write(data.data(), static_cast<std::streamsize>(data.size()));
            if (!cur) {
                close_cur();
                *err = "write download";
                return false;
            }
            done_bytes += static_cast<int64_t>(data.size());
            report();
            break;
        }
        case hbb::FileResponse::kDone: {
            const auto& d = fr.done();
            if (d.id() != id) {
                break;
            }
            // Older peers send a done per file (file_num = index); current
            // RustDesk sends a single done once the job has advanced past the
            // last file (file_num = files.size()).
            const int32_t n = d.file_num();
            const int32_t count = static_cast<int32_t>(files.size());
            if (!finish(n)) {
                return false;
            }
            if (n >= count || (n == count - 1 && (started[n] || skipped[n]))) {
                for (int32_t i = 0; i < count; i++) {
                    if (!finish(i)) {
                        return false;
                    }
                }
                close_cur();
                report();
                return true;
            }
            break;
        }
        default:
            break;
        }
    }
}



bool FileTransfer::send_job(const Job& j, const ProgressFunc& progress, int* files_done,
                            int files_total, int64_t* done_bytes, int64_t total_bytes,
                            std::string* err) {
    const int32_t id = next_job_id();
    int64_t total = 0;
    for (const auto& f : j.files) {
        total += static_cast<int64_t>(f.size());
    }
    hbb::FileAction a;
    auto* recv = a.mutable_receive();
    recv->set_id(id);
    recv->set_path(j.remote_path);
    for (const auto& f : j.files) {
        *recv->add_files() = f;
    }
    recv->set_file_num(0);
    recv->set_total_size(static_cast<uint64_t>(total));
    if (!send_action(a)) {
        *err = "hbb: send receive request";
        return false;
    }

    int64_t sent = 0;
    int file_idx = 0;
    while (file_idx < static_cast<int>(j.files.size())) {
        const auto& entry = j.files[file_idx];
        uint32_t offset = 0;
        if (overwrite_enabled_) {
            bool skip = false;
            if (!negotiate_upload(id, file_idx, entry, &skip, &offset, err)) {
                return false;
            }
            if (skip) {
                (*files_done)++;
                *done_bytes += static_cast<int64_t>(entry.size());
                if (progress) {
                    progress(*files_done, files_total, *done_bytes, total_bytes);
                }
                file_idx++;
                continue;
            }
        }
        const fs::path fp = fs::path(j.local_path) / entry.name();
        const int64_t n = stream_file(id, file_idx, fp.string(), offset, err);
        if (!err->empty()) {
            return false;
        }
        file_idx++;
        (*files_done)++;
        *done_bytes += n;
        sent += n;
        if (progress) {
            progress(*files_done, files_total, *done_bytes, total_bytes);
        }
    }
    if (!j.files.empty()) {
        if (!send_done(id, static_cast<int32_t>(j.files.size() - 1))) {
            *err = "hbb: send done";
            return false;
        }
    }
    return true;
}

// negotiate_upload runs overwrite detection for one file of an upload job.
// As the sender we announce the file with our digest; the peer replies with a
// SendConfirm (skip, or the offset to start at) or, when it already holds a
// different copy, with its own digest, which we confirm with an overwrite (or
// resume) offset.
bool FileTransfer::negotiate_upload(int32_t id, int file_idx, const hbb::FileEntry& entry,
                                    bool* skip, uint32_t* offset, std::string* err) {
    hbb::Message out;
    auto* dg = out.mutable_file_response()->mutable_digest();
    dg->set_id(id);
    dg->set_file_num(file_idx);
    dg->set_last_modified(entry.modified_time());
    dg->set_file_size(entry.size());
    dg->set_is_upload(true);
    if (!conn_->Send(out)) {
        *err = "hbb: send digest";
        return false;
    }
    while (true) {
        auto msg = conn_->Recv();
        if (!msg) {
            *err = "hbb: recv digest";
            return false;
        }
        if (msg->has_file_action()) {
            const auto& fa = msg->file_action();
            if (fa.has_send_confirm()) {
                const auto& sc = fa.send_confirm();
                if (sc.id() == id && sc.file_num() == file_idx) {
                    *skip = sc.skip();
                    *offset = sc.skip() ? 0 : sc.offset_blk();
                    return true;
                }
            }
            continue;
        }
        if (!msg->has_file_response()) {
            continue;
        }
        const auto& fr = msg->file_response();
        switch (fr.union_case()) {
        case hbb::FileResponse::kDigest: {
            const auto& d = fr.digest();
            if (d.id() != id || d.file_num() != file_idx) {
                break;
            }
            *offset = 0;
            if (d.is_identical() && d.is_resume() && d.transferred_size() > 0) {
                *offset = static_cast<uint32_t>(d.transferred_size());
            }
            hbb::FileAction confirm;
            auto* sc = confirm.mutable_send_confirm();
            sc->set_id(id);
            sc->set_file_num(file_idx);
            sc->set_offset_blk(*offset);
            if (!send_action(confirm)) {
                *err = "hbb: send confirm";
                return false;
            }
            return true;
        }
        case hbb::FileResponse::kError:
            *err = fr.error().error();
            return false;
        default:
            break;
        }
    }
}

int64_t FileTransfer::stream_file(int32_t id, int32_t file_num, const std::string& path,
                                  uint32_t offset, std::string* err) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        *err = "open " + path;
        return 0;
    }
    if (offset > 0) {
        f.seekg(offset, std::ios::beg);
    }
    std::string buf(kFileBlockSize, '\0');
    int64_t sent = 0;
    while (true) {
        f.read(buf.data(), kFileBlockSize);
        const std::streamsize n = f.gcount();
        if (n == 0) {
            break;
        }
        std::string data(buf.data(), static_cast<size_t>(n));
        bool compressed = false;
        if (!is_compressed_name(path)) {
            if (auto enc = zstd_compress(data)) {
                if (enc->size() < data.size()) {
                    data = std::move(*enc);
                    compressed = true;
                }
            }
        }
        hbb::FileTransferBlock b;
        b.set_id(id);
        b.set_file_num(file_num);
        b.set_data(data);
        b.set_compressed(compressed);
        if (!send_block(b)) {
            *err = "hbb: send block";
            return 0;
        }
        sent += n;
        if (f.eof()) {
            break;
        }
    }
    if (!send_done(id, file_num)) {
        *err = "hbb: send file done";
        return 0;
    }
    return sent;
}


std::optional<std::vector<hbb::FileEntry>> list_dir(const DialOpts& opts,
                                                    const std::string& remote_path,
                                                    std::string* err) {
    auto ft = FileTransfer::Open(opts, remote_path, err);
    if (!ft) {
        return std::nullopt;
    }
    auto dir = ft->ReadDir(remote_path, err);
    if (!dir) {
        return std::nullopt;
    }
    std::vector<hbb::FileEntry> out;
    for (const auto& e : dir->entries()) {
        out.push_back(e);
    }
    return out;
}

}  // namespace rdcli::core

