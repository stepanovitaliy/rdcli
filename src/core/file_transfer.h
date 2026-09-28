#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "core/conn.h"

namespace rdcli::core {

// File-transfer session with a peer (ls / cp).
class FileTransfer {
public:
    using ProgressFunc = std::function<void(int files_done, int files_total, int64_t done_bytes,
                                            int64_t total_bytes)>;

    static std::unique_ptr<FileTransfer> Open(const DialOpts& opts, const std::string& dir,
                                              std::string* err);
    ~FileTransfer();

    std::optional<hbb::FileDirectory> ReadDir(const std::string& path, std::string* err);
    bool CreateDir(const std::string& path, std::string* err);
    bool Send(const std::string& local_path, const std::string& remote_dir, bool recursive,
              const ProgressFunc& progress, std::string* err);
    bool Receive(const std::string& remote_path, const std::string& local_path,
                 const ProgressFunc& progress, std::string* err);
    std::optional<std::vector<hbb::FileEntry>> ReadAllFiles(const std::string& path,
                                                            std::string* err);

    Conn* conn() { return conn_.get(); }

private:
    struct Job {
        std::string local_path;
        std::string remote_path;
        std::vector<hbb::FileEntry> files;
    };

    int32_t next_job_id();
    bool send_action(const hbb::FileAction& a);
    bool send_block(const hbb::FileTransferBlock& b);
    bool send_done(int32_t id, int32_t file_num);

    std::vector<Job> build_send_jobs(const std::string& local_path, const std::string& remote_dir,
                                     bool recursive, std::string* err);
    bool ensure_remote_dirs(const std::string& remote_dir, const std::vector<Job>& jobs,
                            std::string* err);
    bool send_job(const Job& j, const ProgressFunc& progress, int* files_done, int files_total,
                  int64_t* done_bytes, int64_t total_bytes, std::string* err);
    bool negotiate_upload(int32_t id, int file_idx, const hbb::FileEntry& entry, bool* skip,
                          uint32_t* offset, std::string* err);
    int64_t stream_file(int32_t id, int32_t file_num, const std::string& path, uint32_t offset,
                        std::string* err);

    std::unique_ptr<Conn> conn_;
    bool overwrite_enabled_ = false;
    int32_t next_id_ = 1;
};

std::optional<std::vector<hbb::FileEntry>> list_dir(const DialOpts& opts,
                                                    const std::string& remote_path,
                                                    std::string* err);

}  // namespace rdcli::core
