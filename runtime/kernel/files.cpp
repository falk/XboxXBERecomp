#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <sys/stat.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#ifdef __SWITCH__
extern "C" {  // as switch.h includes them
#include <switch/runtime/devices/fs_dev.h>
#include <switch/services/fs.h>
}
#endif

#include "kernel/disc.h"
#include "kernel/kernel.h"
#include "kernel/exports.h"

namespace fs = std::filesystem;

namespace kernel {

void (*g_on_open)(const char* name) = nullptr;
const char* (*g_redirect_file)(const char* name) = nullptr;

namespace {

std::mutex g_links_lock;
std::map<std::string, std::string> g_links;    // upper case "\??\D:" -> "\Device\CdRom0"
std::map<std::string, fs::path> g_devices;     // upper case device -> host directory
constexpr char kCdRom[] = "\\DEVICE\\CDROM0";

std::string Upper(std::string s) {
    for (char& c : s) c = char(std::toupper(uint8_t(c)));
    return s;
}

std::string Normalize(std::string p) {
    std::replace(p.begin(), p.end(), '/', '\\');
    std::string out;
    for (char c : p) {
        if (c == '\\' && !out.empty() && out.back() == '\\') continue;
        out += c;
    }
    while (out.size() > 1 && out.back() == '\\') out.pop_back();
    return out;
}

enum class Kind { None, File, Dir };

// The disc's folder never changes (it is read only, as the disc): one listing per folder answers what is there without
// asking the file system again. On Horizon each lookup is a request to the fs service, and a mission load probes
// thousands of package names that are not on the disc (each about 45 paths over D:, T: and the package folders).
// On Horizon the hard disk's folder is listed the same way (the T: twins of those probes): only this program
// changes it, and every change it makes there forgets the hard disk's listings (ForgetHostListings).
struct Listing {
    std::unordered_map<std::string, std::pair<std::string, Kind>> by_upper;  // upper case name: the name, its kind
};
std::mutex g_listing_lock;
std::unordered_map<std::string, std::shared_ptr<const Listing>> g_listings;  // by folder path
std::string g_disc_root;                                                     // the disc's folder, "" for none
std::string g_hdd_root;                                                      // the hard disk's, "" when not listed

bool Under(const std::string& p, const std::string& root) {
    return !root.empty() && p.compare(0, root.size(), root) == 0 &&
           (p.size() == root.size() || p[root.size()] == '/' || p[root.size()] == '\\');
}

// the listed folder a path is in: the disc's, the hard disk's, else nullptr
const std::string* ListedRoot(const std::string& p) {
    if (Under(p, g_disc_root)) return &g_disc_root;
    if (Under(p, g_hdd_root)) return &g_hdd_root;
    return nullptr;
}

// after this program creates, removes or renames anything on the hard disk
void ForgetHostListings() {
    std::lock_guard<std::mutex> lock(g_listing_lock);
    for (auto it = g_listings.begin(); it != g_listings.end();)
        it = Under(it->first, g_disc_root) ? std::next(it) : g_listings.erase(it);
}

std::shared_ptr<const Listing> ListingOf(const fs::path& dir) {
    std::lock_guard<std::mutex> lock(g_listing_lock);
    auto it = g_listings.find(dir.string());
    if (it != g_listings.end()) return it->second;
    auto l = std::make_shared<Listing>();
    std::error_code ec;
    for (auto& e : fs::directory_iterator(dir, ec)) {
        std::error_code tec;
        Kind k = e.is_directory(tec) ? Kind::Dir : Kind::File;
        std::string name = e.path().filename().string();
        l->by_upper[Upper(name)] = {name, k};
    }
    return g_listings[dir.string()] = l;
}

// a path in a listed folder (root): what the listing of its folder says, the root itself a folder
Kind ListedKind(const fs::path& p, const std::string& root) {
    std::string s = p.string();
    while (s.size() > root.size() && (s.back() == '/' || s.back() == '\\')) s.pop_back();
    if (s.size() <= root.size()) return Kind::Dir;
    fs::path q = s;
    if (ListedKind(q.parent_path(), root) != Kind::Dir) return Kind::None;
    auto l = ListingOf(q.parent_path());
    auto e = l->by_upper.find(Upper(q.filename().string()));
    return e == l->by_upper.end() ? Kind::None : e->second.second;
}

// What a host path names. On Horizon stat by path opens the file (libnx fsdev_stat: entry type, open, size, close,
// time stamps), which the fs service refuses while any handle holds the file open for writing, and costs five fs
// requests; the entry type alone is one request and never opens the file.
Kind HostKind(const fs::path& p) {
    if (const std::string* root = ListedRoot(p.string())) return ListedKind(p, *root);
#ifdef __SWITCH__
    FsFileSystem* device = nullptr;
    char inner[FS_MAX_PATH] = {};
    FsDirEntryType type;
    if (fsdevTranslatePath(p.c_str(), &device, inner) == -1 || R_FAILED(fsFsGetEntryType(device, inner, &type)))
        return Kind::None;
    return type == FsDirEntryType_Dir ? Kind::Dir : Kind::File;
#else
    std::error_code ec;
    fs::file_status st = fs::status(p, ec);
    return st.type() == fs::file_type::directory ? Kind::Dir
           : fs::exists(st)                       ? Kind::File
                                                  : Kind::None;
#endif
}

// host lookup that ignores case on file systems that do not
fs::path MatchCase(const fs::path& dir, const std::vector<std::string>& parts) {
    fs::path cur = dir;
    for (auto& part : parts) {
        if (part.empty() || part == ".") continue;
        if (part == "..") {
            cur = cur.parent_path();
            continue;
        }
        fs::path direct = cur / part;
        std::error_code ec;
        if (const std::string* root = ListedRoot(cur.string())) {
            // a listed folder: its listing gives the name in the case it has
            fs::path next = direct;
            if (ListedKind(cur, *root) == Kind::Dir) {
                auto l = ListingOf(cur);
                auto e = l->by_upper.find(Upper(part));
                if (e != l->by_upper.end()) next = cur / e->second.first;
            }
            cur = next;
            continue;
        }
        if (HostKind(direct) != Kind::None) {
            cur = direct;
            continue;
        }
        bool found = false;
        std::string want = Upper(part);
        for (auto& e : fs::directory_iterator(cur, ec)) {
            if (Upper(e.path().filename().string()) == want) {
                cur = e.path();
                found = true;
                break;
            }
        }
        if (!found) cur = direct;
    }
    return cur;
}

// A host stream that every handle reading the same file shares: Horizon lets a process hold only so many files open,
// and past that every open fails, creates too. The sound engine of Chaos Theory opens each bank about 24 times and
// keeps the handles, several hundred files, and then the autosave (and the shader cache) could not create theirs.
// The handles keep positions of their own; the stream's lock keeps a seek and its transfer together.
// Horizon's fs service answers each request in about the time a 64 KB read takes, and newlib's own buffer cannot
// help (its seek within the buffer misreads sdmc:'s block size of 0): the file layer keeps its own. A shared read
// only stream caches 64 KB around the last small read; a file open for writing gathers consecutive small writes.
constexpr size_t kReadCache = 64 * 1024, kWriteGather = 256 * 1024, kSmallTransfer = 32 * 1024;
#ifdef __SWITCH__
constexpr bool kCacheReads = true;  // no other handle writes a file a stream reads: the fs service refuses that open
#else
constexpr bool kCacheReads = false;
#endif

std::atomic<uint64_t> g_transfers{0}, g_fs_requests{0};  // the title's reads and writes, the host's fs requests

struct Stream {
    FILE* fp = nullptr;
    std::mutex io;
    std::vector<uint8_t> cache;  // the file's bytes from cache_at, under io
    uint64_t cache_at = 0;
    ~Stream() {
        if (fp) std::fclose(fp);
    }
};

// the file objects alive, for the log when an open fails
struct File;
std::mutex g_files_lock;
std::unordered_set<File*> g_files;

struct File : Object {
    fs::path host;
    std::string xbox;
    FILE* fp = nullptr;
    const Disc::Entry* entry = nullptr;  // on the disc image instead of a host path
    bool dir = false;
    uint64_t pos = 0;
    std::vector<fs::directory_entry> entries;
    std::vector<const Disc::Entry*> disc_entries;
    size_t next = 0;
    bool listed = false;
    bool delete_on_close = false;
    bool writable = false;  // fp open for writing
    bool cdrom = false;     // a file of the disc's folder: read only, as the disc is
    std::mutex io;  // threads sharing a handle: seek and transfer stay together
    std::shared_ptr<Stream> stream;  // fp is this shared read only stream's (it closes the file)
    std::vector<uint8_t> gather;     // writes not on the host yet, from gather_at; under Io()
    uint64_t gather_at = 0;
    std::mutex& Io() { return stream ? stream->io : io; }
    // the gathered writes to the host, before anything that reads, sizes, renames or closes the file; under Io()
    bool FlushWrites() {
        if (gather.empty()) return true;
        bool ok = fseeko(fp, off_t(gather_at), SEEK_SET) == 0 &&
                  std::fwrite(gather.data(), 1, gather.size(), fp) == gather.size();
        g_fs_requests++;
        if (!ok) LOGE("files: %zu bytes of %s not written", gather.size(), host.string().c_str());
        gather.clear();
        return ok;
    }
    File() : Object(ObjType::File) {
        std::lock_guard<std::mutex> lock(g_files_lock);
        g_files.insert(this);
    }
    ~File() override {
        {
            std::lock_guard<std::mutex> lock(g_files_lock);
            g_files.erase(this);
        }
        if (fp && !stream) {
            FlushWrites();
            std::fclose(fp);
        }
        stream.reset();  // Horizon removes no file still open
        if (delete_on_close) {
            std::error_code ec;
            fs::remove(host, ec);
            ForgetHostListings();
        }
    }
};

struct Link : Object {
    std::string target;
    Link() : Object(ObjType::SymLink) {}
};

#ifdef _WIN32
uint64_t ToFileTime(fs::file_time_type t) {
    using namespace std::chrono;
    auto sys = time_point_cast<nanoseconds>(t - fs::file_time_type::clock::now() + system_clock::now());
    return uint64_t(sys.time_since_epoch().count() / 100 + 116444736000000000ll);
}
#endif

// a host file or folder as the information classes report it
struct HostInfo {
    bool ok = false;
    bool dir = false;
    uint64_t size = 0;
    uint64_t time = 0;  // FILETIME of the last write
};

// Of the open stream when there is one (pending writes flushed first), else by path. On Horizon stat by path opens
// the file (libnx fsdev_stat), which the fs service refuses while any handle holds the file open for writing; fstat
// asks the open handle.
HostInfo Describe(const fs::path& p, FILE* fp = nullptr) {
    HostInfo h;
    if (fp) std::fflush(fp);
#ifdef _WIN32
    std::error_code ec;
    h.dir = fs::is_directory(p, ec);
    auto t = fs::last_write_time(p, ec);
    h.ok = !ec;
    if (h.ok) h.time = ToFileTime(t);
    if (!h.dir) {
        uintmax_t size = fs::file_size(p, ec);
        if (!ec) h.size = size;
    }
#else
    struct stat st;
#ifdef __SWITCH__
    // a folder by its entry type (libnx gives folders no times); a file another handle holds for writing cannot be
    // stat'ed by path, it shows with no size or time
    if (!fp) {
        Kind kind = HostKind(p);
        h.ok = kind != Kind::None;
        h.dir = kind == Kind::Dir;
        h.time = 116444736000000000ll;  // 1970, as libnx's stat of a folder gives
        if (kind != Kind::File || stat(p.c_str(), &st) != 0) return h;
    } else if (fstat(fileno(fp), &st) != 0) {
        return h;
    }
#else
    if ((fp ? fstat(fileno(fp), &st) : stat(p.c_str(), &st)) != 0) return h;
#endif
    h.ok = true;
    h.dir = S_ISDIR(st.st_mode);
    h.size = h.dir ? 0 : uint64_t(st.st_size);
    h.time = uint64_t(int64_t(st.st_mtim.tv_sec) * 10000000 + st.st_mtim.tv_nsec / 100 + 116444736000000000ll);
#endif
    return h;
}

// access rights that write: FILE_WRITE_DATA, FILE_APPEND_DATA, MAXIMUM_ALLOWED, GENERIC_ALL, GENERIC_WRITE
constexpr uint32_t kWriteAccess = 0x2 | 0x4 | 0x02000000 | 0x10000000 | 0x40000000;

// Existing files open read only unless a write right is asked: Horizon's fs service refuses any other open of a file
// (and stat by path) while one handle holds it for writing. On Horizon the stream is unbuffered: newlib buffers
// 1 KB on sdmc: (st_blksize 0), one fs request each; the title's transfers go through whole.
FILE* OpenHost(const std::string& path, const char* mode) {
    FILE* fp = std::fopen(path.c_str(), mode);
#ifdef __SWITCH__
    if (fp) std::setvbuf(fp, nullptr, _IONBF, 0);
#endif
    return fp;
}

std::mutex g_streams_lock;
std::unordered_map<std::string, std::weak_ptr<Stream>> g_streams;  // by host path

// the stream other handles already read the file through, else one opened now
std::shared_ptr<Stream> SharedReader(const std::string& path) {
    std::lock_guard<std::mutex> lock(g_streams_lock);
    std::weak_ptr<Stream>& w = g_streams[path];
    if (auto s = w.lock()) return s;
    FILE* fp = OpenHost(path, "rb");
    if (!fp) return nullptr;
    auto s = std::make_shared<Stream>();
    s->fp = fp;
    w = s;
    return s;
}

void FillNetworkInfo(uint32_t out, uint64_t t, uint64_t size, bool dir) {
    for (int i = 0; i < 4; i++) W64(out + i * 8, t);
    W64(out + 0x20, (size + 0xFFF) & ~0xFFFull);
    W64(out + 0x28, size);
    W32(out + 0x30, dir ? 0x10 : 0x80);  // FILE_ATTRIBUTE_DIRECTORY or NORMAL
}

void FillNetworkInfo(uint32_t out, const fs::path& p, FILE* fp = nullptr) {
    HostInfo h = Describe(p, fp);
    FillNetworkInfo(out, h.time, h.size, h.dir);
}

void FillNetworkInfo(uint32_t out, const Disc::Entry& e) {
    FillNetworkInfo(out, MountedDisc()->Time(), e.dir ? 0 : e.size, e.dir);
}

bool WildMatch(const std::string& pat, const std::string& s) {
    size_t p = 0, i = 0, star = std::string::npos, mark = 0;
    while (i < s.size()) {
        if (p < pat.size() && (pat[p] == '?' || std::toupper(uint8_t(pat[p])) == std::toupper(uint8_t(s[i])))) {
            p++;
            i++;
        } else if (p < pat.size() && pat[p] == '*') {
            star = p++;
            mark = i;
        } else if (star != std::string::npos) {
            p = star + 1;
            i = ++mark;
        } else {
            return false;
        }
    }
    while (p < pat.size() && pat[p] == '*') p++;
    return p == pat.size();
}

// past 2 GB a long offset wraps on Windows
void Seek(FILE* fp, uint64_t pos) {
#ifdef _WIN32
    _fseeki64(fp, int64_t(pos), SEEK_SET);
#else
    fseeko(fp, off_t(pos), SEEK_SET);
#endif
}

void IoStatus(uint32_t iosb, uint32_t status, uint32_t info) {
    if (!iosb) return;
    W32(iosb, status);
    W32(iosb + 4, info);
}

std::shared_ptr<File> FileFromHandle(uint32_t h) {
    ObjectRef o = FromHandle(h);
    if (!o || o->type != ObjType::File) return nullptr;
    return std::static_pointer_cast<File>(o);
}

std::string ObjectName(uint32_t attrs, uint32_t* root = nullptr) {
    if (root) *root = R32(attrs);
    return ReadAnsiString(R32(attrs + 4));
}

void Complete(uint32_t event, uint32_t apc, uint32_t apc_ctx, uint32_t iosb) {
    if (event)
        if (ObjectRef e = FromHandle(event)) SetEvent(*e);
    if (apc && Current()) QueueApc(*Current(), apc, apc_ctx, iosb, 0);
}

}  // namespace

std::string ReadAnsiString(uint32_t str) {
    if (!str) return {};
    uint16_t len = R16(str);
    uint32_t buf = R32(str + 4);
    if (!buf) return {};
    return std::string(reinterpret_cast<const char*>(HostPtr(buf)), len);
}

std::string ReadCString(uint32_t va, size_t max) {
    std::string s;
    if (!va) return s;
    for (size_t i = 0; i < max; i++) {
        char c = char(G<uint8_t>(va + uint32_t(i)));
        if (!c) break;
        s += c;
    }
    return s;
}

void MountDefaults(const std::string& game_dir, const std::string& data_dir) {
    std::lock_guard<std::mutex> lock(g_links_lock);
    fs::path d = data_dir;
    g_devices[kCdRom] = game_dir;
    {
        // the disc's folder as Resolve spells its paths (no trailing separator)
        std::lock_guard<std::mutex> l(g_listing_lock);
        g_disc_root = MountedDisc() ? std::string() : fs::path(game_dir).string();
        while (g_disc_root.size() > 1 && (g_disc_root.back() == '/' || g_disc_root.back() == '\\')) g_disc_root.pop_back();
#ifdef __SWITCH__
        g_hdd_root = d.string();
        while (g_hdd_root.size() > 1 && (g_hdd_root.back() == '/' || g_hdd_root.back() == '\\')) g_hdd_root.pop_back();
        g_listings.clear();
#endif
    }
    g_devices["\\DEVICE\\HARDDISK0\\PARTITION1"] = d / "E";
    g_devices["\\DEVICE\\HARDDISK0\\PARTITION2"] = d / "C";
    g_devices["\\DEVICE\\HARDDISK0\\PARTITION3"] = d / "X";
    g_devices["\\DEVICE\\HARDDISK0\\PARTITION4"] = d / "Y";
    g_devices["\\DEVICE\\HARDDISK0\\PARTITION5"] = d / "Z";
    for (auto& [k, v] : g_devices) {
        std::error_code ec;
        fs::create_directories(v, ec);
    }
    g_links["\\??\\D:"] = "\\Device\\CdRom0";
    const Disc* disc = MountedDisc();
    LOGI("files: D: is %s, hard disk under %s", disc ? disc->Path().string().c_str() : game_dir.c_str(), data_dir.c_str());
}

bool CreateSymbolicLink(const std::string& link, const std::string& target) {
    std::lock_guard<std::mutex> lock(g_links_lock);
    g_links[Upper(Normalize(link))] = Normalize(target);
    LOGI("files: link %s -> %s", link.c_str(), target.c_str());
    return true;
}

bool DeleteSymbolicLink(const std::string& link) {
    std::lock_guard<std::mutex> lock(g_links_lock);
    return g_links.erase(Upper(Normalize(link))) != 0;
}

std::string QuerySymbolicLink(const std::string& link) {
    std::lock_guard<std::mutex> lock(g_links_lock);
    auto it = g_links.find(Upper(Normalize(link)));
    return it == g_links.end() ? std::string() : it->second;
}

namespace {

struct Target {
    std::string host;                    // empty on the disc image or unmapped
    bool disc = false;                   // on the mounted disc image
    const Disc::Entry* entry = nullptr;  // there: the file or folder, null when missing
    bool cdrom = false;                  // in the folder that holds the disc's files: read only, as the disc is
};

Target Resolve(const std::string& xbox_path, uint32_t root_handle) {
    std::string p = Normalize(xbox_path);
    if (root_handle) {
        if (auto f = FileFromHandle(root_handle)) p = Normalize(f->xbox + "\\" + p);
    }
    if (p.size() >= 2 && p[1] == ':') p = "\\??\\" + p;
    std::lock_guard<std::mutex> lock(g_links_lock);
    for (int depth = 0; depth < 8; depth++) {
        std::string up = Upper(p);
        bool changed = false;
        for (auto& [k, v] : g_links) {
            if (up.compare(0, k.size(), k) == 0 && (up.size() == k.size() || up[k.size()] == '\\')) {
                p = v + p.substr(k.size());
                changed = true;
                break;
            }
        }
        if (!changed) break;
    }
    std::string up = Upper(p);
    const std::pair<const std::string, fs::path>* best = nullptr;
    for (auto& e : g_devices)
        if (up.compare(0, e.first.size(), e.first) == 0 && (up.size() == e.first.size() || up[e.first.size()] == '\\'))
            if (!best || e.first.size() > best->first.size()) best = &e;
    if (!best) return {};
    std::vector<std::string> parts;
    std::string rest = p.substr(best->first.size());
    size_t s = 0;
    while (s < rest.size()) {
        size_t e = rest.find('\\', s);
        if (e == std::string::npos) e = rest.size();
        if (e > s) parts.push_back(rest.substr(s, e - s));
        s = e + 1;
    }
    // no Xbox name holds ':', and fs::path would take "D:" as a host drive
    for (auto& part : parts)
        if (part.find(':') != std::string::npos) return {};
    if (best->first == kCdRom)
        if (const Disc* disc = MountedDisc()) return {{}, true, disc->Find(parts)};
    Target t{MatchCase(best->second, parts).string()};
    t.cdrom = best->first == kCdRom;
    return t;
}

// a file the title asked for and did not find. One missing from the game disc is a warning, flushed to the log at
// once: the title's disc error screen that follows names no file. Each name once: an engine probing its package
// folders asks for the same ones on every load, a thousand names in a level's first load: past the first few they are
// info, written with the log's next flush rather than each flushing it on the loading thread
void LogMissing(const std::string& name) {
    const std::string u = Upper(name);
    if (u.rfind("D:\\", 0) == 0 || u.rfind("\\DEVICE\\CDROM", 0) == 0) {
        static std::mutex lock;
        static std::unordered_set<std::string> logged;
        std::lock_guard<std::mutex> hold(lock);
        if (!logged.insert(u).second) return;
        if (logged.size() <= 32) LOGW("missing on the disc: %s", name.c_str());
        else LOGI("missing on the disc: %s", name.c_str());
        return;
    }
    LOG_FIRST(200, "missing %s", name.c_str());
}

// the disc image is read only: nothing on it is created, replaced or written
uint32_t OpenOnDisc(const Disc::Entry* e, const std::string& name, uint32_t handle_out, uint32_t iosb, uint32_t disposition,
                    uint32_t options) {
    if (!e && (disposition == 1 || disposition == 4)) {  // FILE_OPEN or FILE_OVERWRITE need an existing file
        LogMissing(name);
        IoStatus(iosb, kObjectNameNotFound, 5);
        return kObjectNameNotFound;
    }
    if (!e || (disposition != 1 && disposition != 3)) {
        IoStatus(iosb, kAccessDenied, 0);
        return kAccessDenied;
    }
    if (e->dir && !(options & 1) && (options & 0x40)) {  // options 1 FILE_DIRECTORY_FILE, 0x40 FILE_NON_DIRECTORY_FILE
        IoStatus(iosb, kFileIsADirectory, 0);
        return kFileIsADirectory;
    }
    auto f = std::make_shared<File>();
    f->xbox = Normalize(name);
    f->entry = e;
    f->dir = e->dir;
    W32(handle_out, NewHandle(f));
    IoStatus(iosb, kSuccess, 1);
    LOG_FIRST(400, "open %s", name.c_str());
    return kSuccess;
}

}  // namespace

std::string ResolvePath(const std::string& xbox_path, uint32_t root_handle) { return Resolve(xbox_path, root_handle).host; }

bool ReadGameFile(const std::string& xbox_path, std::vector<uint8_t>& out) {
    Target t = Resolve(xbox_path, 0);
    if (t.disc) {
        if (!t.entry || t.entry->dir) return false;
        out.resize(t.entry->size);
        return MountedDisc()->Read(*t.entry, 0, out.data(), t.entry->size) == t.entry->size;
    }
    // whole, in one read: a buffered stream reads 1 KB per fs request on Horizon
    FILE* f = OpenHost(t.host, "rb");
    if (!f) return false;
    HostInfo h = Describe(t.host, f);
    out.resize(size_t(h.size));
    size_t got = h.ok ? std::fread(out.data(), 1, out.size(), f) : 0;
    std::fclose(f);
    out.resize(got);
    return h.ok;
}

// exports

KERNEL_EXPORT(190, NtCreateFile, 9) {
    uint32_t handle_out = a[0], access = a[1], attrs = a[2], iosb = a[3], disposition = a[7], options = a[8];
    const char* open_mode = access & kWriteAccess ? "r+b" : "rb";
    uint32_t root;
    std::string name = ObjectName(attrs, &root);
    // what may change the file: write or delete access, a disposition that creates or cuts it, delete on close
    constexpr uint32_t kDelete = 0x10000;
    bool changes = (access & (kWriteAccess | kDelete)) || (disposition != 1 && disposition != 3) || (options & 0x1000);
    // a title's redirect is for reading another file (a copy the title keeps on its hard disk read from the disc):
    // an open that writes stays at the name asked for, else it would write over the disc's own file
    if (g_redirect_file && !changes)
        if (const char* other = g_redirect_file(name.c_str())) name = other;
    Target t = Resolve(name, root);
    if (t.disc) return OpenOnDisc(t.entry, name, handle_out, iosb, disposition, options);
    // the disc's folder is the disc: nothing is created, cut or removed there (opened for writing, it reads)
    if (t.cdrom && ((disposition != 1 && disposition != 3) || (options & 0x1000) ||
                    (disposition == 3 && HostKind(t.host) == Kind::None))) {
        LOG_FIRST(16, "NtCreateFile: %s is on the disc, not written", name.c_str());
        IoStatus(iosb, kAccessDenied, 0);
        return kAccessDenied;
    }
    const std::string& host = t.host;
    if (host.empty()) {
        LOGW("NtCreateFile: no mapping for %s", name.c_str());
        IoStatus(iosb, kObjectPathNotFound, 0);
        return kObjectPathNotFound;
    }
    std::error_code ec;
    Kind kind = HostKind(host);
    bool exists = kind != Kind::None;
    bool is_dir = kind == Kind::Dir;
    bool want_dir = options & 1;
    uint32_t info = 1;  // FILE_OPENED
    if (want_dir || is_dir) {
        if (!exists) {
            if (disposition == 1 || disposition == 4) {
                IoStatus(iosb, kObjectNameNotFound, 5);
                return kObjectNameNotFound;
            }
            fs::create_directories(host, ec);
            ForgetHostListings();
            info = 2;
        } else if (disposition == 2) {
            IoStatus(iosb, kObjectNameCollision, 4);
            return kObjectNameCollision;
        }
        if (!want_dir && (options & 0x40)) {
            IoStatus(iosb, kFileIsADirectory, 0);
            return kFileIsADirectory;
        }
        auto f = std::make_shared<File>();
        f->host = host;
        f->xbox = Normalize(name);
        f->dir = true;
        W32(handle_out, NewHandle(f));
        IoStatus(iosb, kSuccess, info);
        return kSuccess;
    }
    const char* mode = nullptr;
    switch (disposition) {
        case 0:  // supersede
        case 5:  // overwrite if
            mode = "w+b";
            info = exists ? 3 : 2;
            break;
        case 1:  // open
            if (!exists) {
                LogMissing(name);
                IoStatus(iosb, kObjectNameNotFound, 5);
                return kObjectNameNotFound;
            }
            mode = open_mode;
            break;
        case 2:  // create
            if (exists) {
                IoStatus(iosb, kObjectNameCollision, 4);
                return kObjectNameCollision;
            }
            mode = "w+b";
            info = 2;
            break;
        case 3:  // open if
            mode = exists ? open_mode : "w+b";
            info = exists ? 1 : 2;
            break;
        case 4:  // overwrite
            if (!exists) {
                IoStatus(iosb, kObjectNameNotFound, 5);
                return kObjectNameNotFound;
            }
            mode = "w+b";
            info = 3;
            break;
        default:
            return kInvalidParameter;
    }
    // a file in a missing folder fails as on the console: XAPI probes saves with OPEN_ALWAYS
    if (!exists && HostKind(fs::path(host).parent_path()) != Kind::Dir) {
        IoStatus(iosb, kObjectPathNotFound, 0);
        return kObjectPathNotFound;
    }
    if (t.cdrom) mode = "rb";
    std::shared_ptr<Stream> stream;
    FILE* fp = nullptr;
    if (std::string(mode) != "rb") fp = OpenHost(host, mode);
    if (fp && !exists) ForgetHostListings();
    if (!fp && std::string(mode) == "r+b") mode = "rb";  // read only media
    if (std::string(mode) == "rb" && (stream = SharedReader(host))) fp = stream->fp;
    if (!fp) {
        int err = errno;
        std::lock_guard<std::mutex> lock(g_files_lock);
        LOGE("NtCreateFile: cannot open %s (%s): %s, %zu files open", host.c_str(), mode, std::strerror(err), g_files.size());
        // those held for writing first: Horizon refuses a second writer of a file
        int listed = 0;
        for (int pass = 0; pass < 2; pass++)
            for (File* o : g_files)
                if (o->fp && o->writable == (pass == 0) && listed++ < 48)
                    LOGE("  open: %s%s", o->host.string().c_str(), o->writable ? " (writing)" : "");
        IoStatus(iosb, kAccessDenied, 0);
        return kAccessDenied;
    }
    auto f = std::make_shared<File>();
    f->host = host;
    f->xbox = Normalize(name);
    f->fp = fp;
    f->stream = stream;
    f->writable = std::string(mode) != "rb";
    f->cdrom = t.cdrom;
    f->delete_on_close = options & 0x1000;  // FILE_DELETE_ON_CLOSE
    W32(handle_out, NewHandle(f));
    IoStatus(iosb, kSuccess, info);
    LOG_FIRST(400, "open %s (%s)", name.c_str(), mode);
    if (g_on_open) g_on_open(name.c_str());
    return kSuccess;
}

KERNEL_EXPORT(202, NtOpenFile, 6) {
    // same as create with FILE_OPEN
    uint32_t handle_out = a[0], access = a[1], attrs = a[2], iosb = a[3], options = a[5];
    uint32_t root;
    std::string name = ObjectName(attrs, &root);
    Target t = Resolve(name, root);
    if (t.disc) return OpenOnDisc(t.entry, name, handle_out, iosb, 1, options);
    const std::string& host = t.host;
    Kind kind = host.empty() ? Kind::None : HostKind(host);
    if (kind == Kind::None) {
        LogMissing(name);
        IoStatus(iosb, kObjectNameNotFound, 5);
        return host.empty() ? kObjectPathNotFound : kObjectNameNotFound;
    }
    auto f = std::make_shared<File>();
    f->host = host;
    f->xbox = Normalize(name);
    f->dir = kind == Kind::Dir;
    f->cdrom = t.cdrom;
    if (!f->dir) {
        f->writable = (access & kWriteAccess) && !t.cdrom;
        if (f->writable) f->fp = OpenHost(host, "r+b");
        if (!f->fp) {
            f->writable = false;
            if ((f->stream = SharedReader(host))) f->fp = f->stream->fp;
        }
        if (!f->fp) return kAccessDenied;
    }
    (void)options;
    W32(handle_out, NewHandle(f));
    IoStatus(iosb, kSuccess, 1);
    return kSuccess;
}

// I/O completes before the call returns: the status block is written, then the file object, the event and the
// APC are signalled (GetOverlappedResult without an event waits on the file handle)
static uint32_t Finish(File& f, uint32_t status, uint32_t n, uint32_t event, uint32_t apc, uint32_t apc_ctx, uint32_t iosb) {
    IoStatus(iosb, status, n);
    SetEvent(f);
    Complete(event, apc, apc_ctx, iosb);
    return status;
}

static uint64_t Offset(File& f, uint32_t off) {
    int64_t o = off ? int64_t(R64(off)) : -1;
    return o >= 0 ? uint64_t(o) : f.pos;
}

// a small read of a shared stream, from its cache (filled with the 64 KB from pos when it does not hold the bytes);
// caller holds the stream's lock
static size_t CachedRead(Stream& s, uint64_t pos, void* dst, size_t len) {
    if (pos < s.cache_at || pos + len > s.cache_at + s.cache.size()) {
        s.cache.resize(kReadCache);
        Seek(s.fp, pos);
        size_t got = std::fread(s.cache.data(), 1, kReadCache, s.fp);  // the heap: the fs service writes it directly
        g_fs_requests++;
        s.cache.resize(got);
        s.cache_at = pos;
    }
    size_t have = pos >= s.cache_at ? size_t(std::min<uint64_t>(len, s.cache_at + s.cache.size() - pos)) : 0;
    std::memcpy(dst, s.cache.data() + (pos - s.cache_at), have);
    return have;
}

// a write: gathered when small and following the gathered ones, else (and when the gather is full) to the host;
// caller holds the file's lock
static size_t Write(File& f, uint64_t pos, const void* src, size_t len) {
    if (len < kSmallTransfer) {
        if (!f.gather.empty() && (pos != f.gather_at + f.gather.size() || f.gather.size() + len > kWriteGather))
            if (!f.FlushWrites()) return 0;
        if (f.gather.empty()) f.gather_at = pos;
        const uint8_t* b = static_cast<const uint8_t*>(src);
        f.gather.insert(f.gather.end(), b, b + len);
        return len;
    }
    if (!f.FlushWrites()) return 0;
    Seek(f.fp, pos);
    g_fs_requests++;
    return mem::FileWrite(src, len, f.fp);
}

// pages is the FILE_SEGMENT_ELEMENT array for scatter and gather, 0 for one buffer
static uint32_t Transfer(const Args& a, bool write, uint32_t pages) {
    uint32_t h = a[0], event = a[1], apc = a[2], apc_ctx = a[3], iosb = a[4], buf = a[5], len = a[6], off = a[7];
    auto f = FileFromHandle(h);
    if (!f || (!f->fp && !f->entry)) return kInvalidHandle;
    if (write && (f->entry || !f->writable)) return kAccessDenied;  // the disc, or a handle without write access
    ResetEvent(*f);
    std::lock_guard<std::mutex> lock(f->Io());
    uint64_t pos = Offset(*f, off);
    g_transfers++;
    if (f->fp && !write && !f->FlushWrites()) return Finish(*f, 0xC0000185, 0, event, apc, apc_ctx, iosb);  // I/O error
    uint32_t n = 0;
    while (n < len) {
        uint32_t at = pages ? R32(pages + n / 0x1000 * 8) + n % 0x1000 : buf + n;
        uint32_t chunk = pages ? std::min(len - n, 0x1000 - n % 0x1000) : len;
        size_t done;
        if (f->entry) {
            done = MountedDisc()->Read(*f->entry, pos + n, HostPtr(at), chunk);
        } else if (write) {
            done = Write(*f, pos + n, HostPtr(at), chunk);
        } else if (kCacheReads && f->stream && chunk < kSmallTransfer) {
            done = CachedRead(*f->stream, pos + n, HostPtr(at), chunk);
        } else {
            Seek(f->fp, pos + n);
            done = mem::FileRead(HostPtr(at), chunk, f->fp);
            g_fs_requests++;
        }
        n += uint32_t(done);
        if (done < chunk) break;
    }
    if ((g_transfers & 0xFFF) == 0)
        LOGI("files: %llu transfers, %llu fs requests", (unsigned long long)g_transfers.load(),
             (unsigned long long)g_fs_requests.load());
    f->pos = pos + n;
    if (write && n < len) return Finish(*f, 0xC000007F, n, event, apc, apc_ctx, iosb);  // disk full
    if (!write && len && !n) return Finish(*f, kEndOfFile, 0, event, apc, apc_ctx, iosb);
    return Finish(*f, kSuccess, n, event, apc, apc_ctx, iosb);
}

KERNEL_EXPORT(219, NtReadFile, 8) { return Transfer(a, false, 0); }
KERNEL_EXPORT(236, NtWriteFile, 8) { return Transfer(a, true, 0); }
// the buffer argument is an array of one page per element
KERNEL_EXPORT(220, NtReadFileScatter, 8) { return Transfer(a, false, a[5]); }
KERNEL_EXPORT(237, NtWriteFileGather, 8) { return Transfer(a, true, a[5]); }

KERNEL_EXPORT(211, NtQueryInformationFile, 5) {
    uint32_t h = a[0], iosb = a[1], out = a[2], len = a[3], cls = a[4];
    auto f = FileFromHandle(h);
    if (!f) return kInvalidHandle;
    HostInfo host;
    if (!f->entry) {
        std::lock_guard<std::mutex> lock(f->Io());  // the flush moves a shared stream's position
        f->FlushWrites();
        host = Describe(f->host, f->fp);
    }
    uint64_t size = f->dir ? 0 : f->entry ? f->entry->size : host.size;
    std::memset(HostPtr(out), 0, len);
    switch (cls) {
        case 4: {  // FileBasicInformation
            uint64_t t = f->entry ? MountedDisc()->Time() : host.time;
            for (int i = 0; i < 4; i++) W64(out + i * 8, t);
            W32(out + 0x20, f->dir ? 0x10 : 0x80);
            IoStatus(iosb, kSuccess, 0x28);
            return kSuccess;
        }
        case 5:  // FileStandardInformation
            W64(out, (size + 0xFFF) & ~0xFFFull);
            W64(out + 8, size);
            W32(out + 0x10, 1);  // NumberOfLinks
            G<uint8_t>(out + 0x15) = f->dir;  // Directory, after DeletePending
            IoStatus(iosb, kSuccess, 0x18);
            return kSuccess;
        case 14:  // FilePositionInformation
            W64(out, f->pos);
            IoStatus(iosb, kSuccess, 8);
            return kSuccess;
        case 34:  // FileNetworkOpenInformation
            if (f->entry) FillNetworkInfo(out, *f->entry);
            else FillNetworkInfo(out, host.time, size, f->dir);
            IoStatus(iosb, kSuccess, 0x38);
            return kSuccess;
        case 22:  // FileModeInformation
        case 16:
            IoStatus(iosb, kSuccess, 4);
            return kSuccess;
        default:
            LOG_FIRST(8, "NtQueryInformationFile: class %u", cls);
            return kInvalidParameter;
    }
}

KERNEL_EXPORT(226, NtSetInformationFile, 5) {
    uint32_t h = a[0], iosb = a[1], in = a[2], cls = a[4];
    auto f = FileFromHandle(h);
    if (!f) return kInvalidHandle;
    if ((f->entry || f->cdrom) && cls != 14 && cls != 4) return kAccessDenied;
    std::error_code ec;
    switch (cls) {
        case 14:  // position
            f->pos = R64(in);
            break;
        case 19:  // allocation: only a size below the end of file cuts it
        case 20:  // end of file
            if (f->fp) {
                std::lock_guard<std::mutex> lock(f->Io());
                f->FlushWrites();
                uint64_t size = Describe(f->host, f->fp).size;
                if (cls == 20 || R64(in) < size) {
#ifdef _WIN32
                    fs::resize_file(f->host, R64(in), ec);
#else
                    // through the open handle: on Horizon truncate by path opens the file again, which the fs
                    // service refuses while this handle holds it
                    if (ftruncate(fileno(f->fp), off_t(R64(in))) != 0)
                        LOG_FIRST(8, "NtSetInformationFile: cannot size %s", f->host.c_str());
#endif
                }
            }
            break;
        case 13:  // disposition
            f->delete_on_close = G<uint8_t>(in) != 0;
            break;
        case 10: {  // rename: ReplaceIfExists, RootDirectory, FileName (ANSI_STRING inline)
            uint32_t root = R32(in + 4);
            std::string target = ReadAnsiString(in + 8);
            Target to = Resolve(target, root);
            if (to.cdrom || to.disc) return kAccessDenied;
            std::string host = to.host;
            if (host.empty()) return kObjectPathNotFound;
            if (f->fp) {
                std::lock_guard<std::mutex> lock(f->Io());
                f->FlushWrites();
                std::fflush(f->fp);
            }
#ifdef __SWITCH__
            // Horizon renames neither an open file nor onto an existing one: the stream is closed around the rename
            // and opened again at the name it then has, and a file in the way is moved aside first, as rename(2)
            // replaces it (not when the names differ only in case: FAT takes both for the same file). The file in the
            // way is removed once the rename is done and put back when it fails, so a failed rename loses nothing.
            if (f->fp) {
                std::shared_ptr<Stream> keep = f->stream;  // its lock outlives the reset
                std::lock_guard<std::mutex> lock(f->Io());
                if (!f->stream) std::fclose(f->fp);
                f->stream.reset();
                f->fp = nullptr;
            }
            std::string aside;
            if (Upper(host) != Upper(f->host.string()) && HostKind(host) == Kind::File) {
                aside = host + ".~replaced";
                std::remove(aside.c_str());
                if (std::rename(host.c_str(), aside.c_str()) != 0) aside.clear();
            }
            fs::rename(f->host, host, ec);
            if (!aside.empty()) {
                if (ec) std::rename(aside.c_str(), host.c_str());
                else std::remove(aside.c_str());
            }
            if (!f->dir) {
                f->fp = OpenHost(ec ? f->host.string() : host, f->writable ? "r+b" : "rb");
                if (!f->fp) LOGW("NtSetInformationFile: cannot open %s again after the rename", host.c_str());
            }
#else
            fs::rename(f->host, host, ec);
#endif
            ForgetHostListings();
            if (ec) return kAccessDenied;
            f->host = host;
            break;
        }
        case 4:  // basic, times and attributes are not kept
            break;
        default:
            LOG_FIRST(8, "NtSetInformationFile: class %u", cls);
            return kInvalidParameter;
    }
    IoStatus(iosb, kSuccess, 0);
    return kSuccess;
}

KERNEL_EXPORT(218, NtQueryVolumeInformationFile, 5) {
    uint32_t iosb = a[1], out = a[2], len = a[3], cls = a[4];
    std::memset(HostPtr(out), 0, len);
    switch (cls) {
        case 3:  // FileFsSizeInformation: 16 GiB total, 8 GiB free in 16 KiB units
            W64(out, 0x100000);
            W64(out + 8, 0x80000);
            W32(out + 0x10, 32);
            W32(out + 0x14, 512);
            IoStatus(iosb, kSuccess, 0x18);
            return kSuccess;
        case 7:  // FileFsFullSizeInformation
            W64(out, 0x100000);
            W64(out + 8, 0x80000);
            W64(out + 0x10, 0x80000);
            W32(out + 0x18, 32);
            W32(out + 0x1C, 512);
            IoStatus(iosb, kSuccess, 0x20);
            return kSuccess;
        case 1:  // FileFsVolumeInformation
            W32(out + 8, 0x12345678);  // VolumeSerialNumber
            IoStatus(iosb, kSuccess, 0x18);
            return kSuccess;
        case 5:  // FileFsAttributeInformation: attributes, max name, name length, "FATX"
            W32(out, 0);
            W32(out + 4, 42);
            W32(out + 8, 4);
            std::memcpy(HostPtr(out + 12), "FATX", 4);
            IoStatus(iosb, kSuccess, 16);
            return kSuccess;
        default:
            LOG_FIRST(8, "NtQueryVolumeInformationFile: class %u", cls);
            return kInvalidParameter;
    }
}

KERNEL_EXPORT(207, NtQueryDirectoryFile, 10) {
    uint32_t h = a[0], event = a[1], apc = a[2], apc_ctx = a[3], iosb = a[4], out = a[5], len = a[6], cls = a[7],
             mask = a[8], restart = a[9];
    auto f = FileFromHandle(h);
    if (!f || !f->dir) return kInvalidHandle;
    if (cls != 1) {
        LOG_FIRST(8, "NtQueryDirectoryFile: class %u", cls);
        return kInvalidParameter;
    }
    std::string pat = mask ? ReadAnsiString(mask) : "*";
    if (!f->listed || (restart & 0xFF)) {
        f->entries.clear();
        f->disc_entries.clear();
        if (f->entry) {
            for (const Disc::Entry& e : f->entry->children)
                if (WildMatch(pat, e.name)) f->disc_entries.push_back(&e);
        } else {
            std::error_code ec;
            for (auto& e : fs::directory_iterator(f->host, ec))
                if (WildMatch(pat, e.path().filename().string())) f->entries.push_back(e);
            std::sort(f->entries.begin(), f->entries.end());
        }
        f->next = 0;
        f->listed = true;
    }
    if (f->next >= (f->entry ? f->disc_entries.size() : f->entries.size())) {
        IoStatus(iosb, kNoMoreFiles, 0);
        return f->next == 0 ? kNoSuchFile : kNoMoreFiles;
    }
    size_t i = f->next++;
    std::string fname = f->entry ? f->disc_entries[i]->name : f->entries[i].path().filename().string();
    uint32_t need = 0x40 + uint32_t(fname.size());
    if (len < need) return kBufferTooSmall;
    std::memset(HostPtr(out), 0, need);
    // times, sizes and attributes sit at the same place
    if (f->entry) FillNetworkInfo(out + 8, *f->disc_entries[i]);
    else FillNetworkInfo(out + 8, f->entries[i].path());
    // FILE_DIRECTORY_INFORMATION has EndOfFile before AllocationSize, the reverse of the network info
    W32(out + 0x38, R32(out + 8 + 0x30));
    uint64_t alloc = R64(out + 8 + 0x20), eof = R64(out + 8 + 0x28);
    W64(out + 0x28, eof);
    W64(out + 0x30, alloc);
    W32(out + 0x3C, uint32_t(fname.size()));
    std::memcpy(HostPtr(out + 0x40), fname.data(), fname.size());
    IoStatus(iosb, kSuccess, need);
    Complete(event, apc, apc_ctx, iosb);
    return kSuccess;
}

KERNEL_EXPORT(210, NtQueryFullAttributesFile, 2) {
    std::string name = ReadAnsiString(R32(a[0] + 4));
    Target t = Resolve(name, R32(a[0]));
    if (t.disc ? !t.entry : t.host.empty() || HostKind(t.host) == Kind::None) {
        LogMissing(name);
        return kObjectNameNotFound;
    }
    if (t.disc) FillNetworkInfo(a[1], *t.entry);
    else FillNetworkInfo(a[1], t.host);
    return kSuccess;
}

KERNEL_EXPORT(195, NtDeleteFile, 1) {
    Target t = Resolve(ReadAnsiString(R32(a[0] + 4)), R32(a[0]));
    if (t.cdrom || t.disc) return kAccessDenied;
    const std::string& host = t.host;
    std::error_code ec;
    if (host.empty() || !fs::remove(host, ec)) return kObjectNameNotFound;
    ForgetHostListings();
    return kSuccess;
}

KERNEL_EXPORT(198, NtFlushBuffersFile, 2) {
    if (auto f = FileFromHandle(a[0]))
        if (f->fp && f->writable) {
            std::lock_guard<std::mutex> lock(f->Io());
            f->FlushWrites();
            std::fflush(f->fp);
        }
    IoStatus(a[1], kSuccess, 0);
    return kSuccess;
}

KERNEL_EXPORT(200, NtFsControlFile, 10) {
    IoStatus(a[4], kSuccess, 0);
    return kSuccess;
}

// IOCTL_SCSI_PASS_THROUGH_DIRECT: the reply goes to the data buffer the SCSI_PASS_THROUGH_DIRECT names
constexpr uint32_t kScsiPassThroughDirect = 0x4D014;
constexpr uint32_t kSptdTransferLength = 0xC;
constexpr uint32_t kSptdDataBuffer = 0x14;
constexpr uint32_t kSptdCdb = 0x1C;
constexpr uint8_t kModeSense10 = 0x5A;
constexpr uint8_t kXboxSecurityPage = 0x3E;
constexpr uint32_t kSecurityPageBytes = 13;  // mode header, page code and length, then the three bytes XAPI checks

// XAPI starts a title whose media must be an Xbox DVD only once the drive's security page reports an
// authenticated disc (page bytes 2 and 4 set, byte 3 one); the game files stand in for that disc
static void ScsiPassThrough(uint32_t sptd) {
    uint32_t cdb = sptd + kSptdCdb;
    if (G<uint8_t>(cdb) != kModeSense10 || (G<uint8_t>(cdb + 2) & 0x3F) != kXboxSecurityPage) return;
    uint32_t data = R32(sptd + kSptdDataBuffer), n = R32(sptd + kSptdTransferLength);
    if (!data || n < kSecurityPageBytes || n > 0xFF) return;
    std::memset(HostPtr(data), 0, n);
    G<uint8_t>(data + 1) = uint8_t(n - 2);  // mode data length, big endian
    G<uint8_t>(data + 8) = kXboxSecurityPage;
    G<uint8_t>(data + 9) = uint8_t(n - 10);
    G<uint8_t>(data + 10) = 1;
    G<uint8_t>(data + 11) = 1;
    G<uint8_t>(data + 12) = 1;
}

KERNEL_EXPORT(196, NtDeviceIoControlFile, 10) {
    uint32_t iosb = a[4], code = a[5], in = a[6], out = a[8], out_len = a[9];
    LOG_FIRST(16, "NtDeviceIoControlFile: code %08X", code);
    if (out && out_len) std::memset(HostPtr(out), 0, out_len);
    if (code == 0x70000 && out_len >= 0x18) {  // IOCTL_DISK_GET_DRIVE_GEOMETRY
        W64(out, 1000);
        W32(out + 8, 12);
        W32(out + 12, 255);
        W32(out + 16, 63);
        W32(out + 20, 512);
    }
    if (code == kScsiPassThroughDirect && in) ScsiPassThrough(in);
    IoStatus(iosb, kSuccess, out_len);
    return kSuccess;
}

KERNEL_EXPORT(67, IoCreateSymbolicLink, 2) {
    CreateSymbolicLink(ReadAnsiString(a[0]), ReadAnsiString(a[1]));
    return kSuccess;
}

KERNEL_EXPORT(69, IoDeleteSymbolicLink, 1) {
    return DeleteSymbolicLink(ReadAnsiString(a[0])) ? kSuccess : kObjectNameNotFound;
}

KERNEL_EXPORT(203, NtOpenSymbolicLinkObject, 2) {
    std::string name = ObjectName(a[1]);
    std::string target = QuerySymbolicLink(name);
    if (target.empty()) return kObjectNameNotFound;
    auto l = std::make_shared<Link>();
    l->target = target;
    W32(a[0], NewHandle(l));
    return kSuccess;
}

KERNEL_EXPORT(215, NtQuerySymbolicLinkObject, 3) {
    ObjectRef o = FromHandle(a[0]);
    if (!o || o->type != ObjType::SymLink) return kInvalidHandle;
    auto& t = static_cast<Link&>(*o).target;
    uint32_t str = a[1];
    uint16_t maxlen = R16(str + 2);
    if (a[2]) W32(a[2], uint32_t(t.size()));
    if (t.size() > maxlen) return kBufferTooSmall;
    std::memcpy(HostPtr(R32(str + 4)), t.data(), t.size());
    W16(str, uint16_t(t.size()));
    return kSuccess;
}

}  // namespace kernel
