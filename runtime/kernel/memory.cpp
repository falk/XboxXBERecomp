#include "kernel/memory.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <vector>

#include "core/log.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#elif defined(__SWITCH__)
#include <switch.h>
#else
#include <sys/mman.h>
#endif

namespace mem {

static uint8_t* g_base = nullptr;
static std::recursive_mutex g_lock;

uint8_t* Base() { return g_base; }

static bool g_wc_aliased = true;
bool WriteCombineAliased() { return g_wc_aliased; }

#ifdef __SWITCH__
// Horizon gives homebrew no way to commit pages at an address of its choosing but aliases of its own heap. The one
// used: svcMapProcessCodeMemory of a heap block at the guest address, made read-write by
// svcSetProcessMemoryPermission (the libnx JIT's SetProcessMemoryPermission path). The pages are then in state
// AliasCodeData (svcQueryMemory type 0x09), which the GPU can map (nvmap, deko3d memory blocks) and
// svcMapProcessMemory can map again (the write combined view as a true alias). Code memory (svcCreateCodeMemory,
// MapOwner), the fallback when the loader does not allow those calls, leaves state CodeOut, which allows neither.
// svcMapPhysicalMemory needs a system resource homebrew does not have (0xFA01). Pages are mapped in 1 MB chunks, a
// run of new chunks at once, and stay mapped. Every alias is made before any device map: the alias calls require
// pages without attributes, and a device map marks them.
// An SVC the loader does not allow ends the process on the console, so each is checked with envIsSyscallHinted.
namespace {

constexpr uint64_t kChunk = 1u << 20;
constexpr uint64_t kGpuAlign = 4u << 20;  // the device map alignment the GPU probe proved (gpuprobe, variant 6)
constexpr uint32_t kSvcCreateCodeMemory = 0x4B, kSvcControlCodeMemory = 0x4C, kSvcSetProcessMemoryPermission = 0x73,
                   kSvcMapProcessMemory = 0x74, kSvcMapProcessCodeMemory = 0x77, kSvcUnmapProcessCodeMemory = 0x78;
std::vector<bool> g_mapped(size_t((1ull << 32) / kChunk), false);
bool g_process_alias = false;  // runs are process code memory aliases (else code memory owner views)
bool g_code_memory = false;    // the loader allows code memory, the fallback

// every mapped run, for Shutdown: the guest address, length, heap source and (code memory) its object
struct Run {
    uint64_t first;
    size_t len;
    void* src;
    Handle code;
    bool alias;
};
std::vector<Run> g_runs;
bool g_wc_mirror = false;  // the write combined view is svcMapProcessMemory of the contiguous one

bool MapRun(uint64_t first, uint64_t end) {
    size_t len = size_t(end - first);
    // a 4 MB aligned run gets a 4 MB aligned source, so the GPU can map it (the contiguous view)
    size_t align = (first % kGpuAlign == 0 && len % kGpuAlign == 0) ? kGpuAlign : 0x1000;
    void* src = aligned_alloc(align, len);
    Result rc = MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
    Handle code = 0;
    // heap pages an earlier program in this process left locked (a service's device mapping, the loader reuses the
    // heap) refuse an alias as an invalid memory state: those stay allocated, never handed out again, and another
    // block is tried
    bool locked = false;  // src is such a block: never freed
    for (int tries = 1; src && g_process_alias; tries++) {
        rc = svcMapProcessCodeMemory(envGetOwnProcessHandle(), u64(g_base + first), u64(src), len);
        locked = R_VALUE(rc) == KERNELRESULT(InvalidMemoryState);
        if (!locked) break;
        // the block's first page not plain heap names the holder (device: a service's mapping; attr locked: a
        // mirror or transfer memory)
        for (uint64_t at = u64(src), stop = u64(src) + len; at < stop;) {
            MemoryInfo mi{};
            u32 pi = 0;
            if (R_FAILED(svcQueryMemory(&mi, &pi, at)) || !mi.size) break;
            if (mi.type != MemType_Heap || mi.attr || mi.perm != Perm_Rw || mi.ipc_refcount || mi.device_refcount) {
                LOGW("memory: heap block %p+%zX holds %llX+%llX type %X attr %X perm %X ipc %u device %u, set aside", src,
                     len, (unsigned long long)mi.addr, (unsigned long long)mi.size, mi.type, mi.attr, mi.perm,
                     mi.ipc_refcount, mi.device_refcount);
                break;
            }
            at = mi.addr + mi.size;
        }
        void* next = tries < 64 ? aligned_alloc(align, len) : nullptr;
        if (!next) break;  // src stays the last locked block, rc its refusal
        src = next;
    }
    if (src && g_process_alias && R_SUCCEEDED(rc)) {
        Handle self = envGetOwnProcessHandle();
        rc = svcSetProcessMemoryPermission(self, u64(g_base + first), len, Perm_Rw);
        // an alias left in place keeps its source locked: the source is then leaked, never freed
        if (R_FAILED(rc) && R_FAILED(svcUnmapProcessCodeMemory(self, u64(g_base + first), u64(src), len))) {
            LOGE("memory: alias of %llX+%zX left read only (%X)", (unsigned long long)first, len, rc);
            return false;
        }
    }
    if (src && g_process_alias && R_FAILED(rc) && R_VALUE(rc) != KERNELRESULT(InvalidMemoryState)) {
        // refused (Ryujinx answers svc 0x77 with 0xE401): code memory from here on, the view then CPU only
        LOGW("memory: process code memory alias of %llX+%zX refused (%X), code memory instead",
             (unsigned long long)first, len, rc);
        g_process_alias = false;
    }
    if (src && !g_process_alias && g_code_memory && R_FAILED(rc)) {
        rc = svcCreateCodeMemory(&code, src, len);
        if (R_SUCCEEDED(rc)) rc = svcControlCodeMemory(code, CodeMapOperation_MapOwner, g_base + first, len, Perm_Rw);
    }
    if (R_FAILED(rc)) {
        LOGE("memory: mapping %llX+%zX failed (%X)", (unsigned long long)first, len, rc);
        // the source's pages as the kernel sees them: an earlier program's device mapping (audio, GPU) or alias over
        // this heap shows as their state and attributes
        for (uint64_t at = u64(src), stop = u64(src) + len; src && at < stop;) {
            MemoryInfo mi{};
            u32 pi = 0;
            if (R_FAILED(svcQueryMemory(&mi, &pi, at)) || !mi.size) break;
            LOGE("memory:   source %llX+%llX type %X attr %X perm %X ipc %u device %u", (unsigned long long)mi.addr,
                 (unsigned long long)mi.size, mi.type, mi.attr, mi.perm, mi.ipc_refcount, mi.device_refcount);
            at = mi.addr + mi.size;
        }
        if (code) svcCloseHandle(code);
        if (!locked) std::free(src);
        return false;
    }
    std::memset(g_base + first, 0, len);
    g_runs.push_back({first, len, src, code, g_process_alias});
    for (uint64_t c = first; c < end; c += kChunk) g_mapped[size_t(c / kChunk)] = true;
    return true;
}

// maps the chunks of [first, end) not mapped yet
bool MapChunks(uint64_t first, uint64_t end) {
    first &= ~(kChunk - 1);
    end = (end + kChunk - 1) & ~(kChunk - 1);
    for (uint64_t c = first; c < end;) {
        if (g_mapped[size_t(c / kChunk)]) {
            c += kChunk;
            continue;
        }
        uint64_t run = c;
        while (run < end && !g_mapped[size_t(run / kChunk)]) run += kChunk;
        if (!MapRun(c, run)) return false;
        c = run;
    }
    return true;
}

}  // namespace
#endif

// physical memory shows at 0x80000000 and again at 0xF0000000 (write combined view)
static bool InPhysical(uint32_t va) {
    return (va >= kContiguousBase && va < kContiguousBase + kPhysicalSize) ||
           (va >= kWriteCombineBase && va < kWriteCombineBase + kPhysicalSize);
}

bool Init() {
    const uint64_t size = 1ull << 32;
#ifdef _WIN32
    HANDLE ram = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, kPhysicalSize, nullptr);
    // a fixed base keeps crash dumps comparable between runs
    for (uint64_t hint : {0x100000000ull, 0x200000000ull, 0x300000000ull, 0ull}) {
        uint8_t* b = static_cast<uint8_t*>(VirtualAlloc(reinterpret_cast<void*>(hint), size, MEM_RESERVE, PAGE_NOACCESS));
        if (!b) continue;
        VirtualFree(b, 0, MEM_RELEASE);
        // reserve around the two physical windows, then map the same memory into both
        const uint64_t cuts[][2] = {{0, kContiguousBase},
                                    {kContiguousBase + kPhysicalSize, kWriteCombineBase},
                                    {kWriteCombineBase + kPhysicalSize, size}};
        bool ok = ram != nullptr;
        for (auto& c : cuts)
            ok = ok && VirtualAlloc(b + c[0], size_t(c[1] - c[0]), MEM_RESERVE, PAGE_NOACCESS) == b + c[0];
        ok = ok && MapViewOfFileEx(ram, FILE_MAP_ALL_ACCESS, 0, 0, kPhysicalSize, b + kContiguousBase) == b + kContiguousBase;
        ok = ok && MapViewOfFileEx(ram, FILE_MAP_ALL_ACCESS, 0, 0, kPhysicalSize, b + kWriteCombineBase) == b + kWriteCombineBase;
        if (ok) {
            g_base = b;
            break;
        }
        for (auto& c : cuts) VirtualFree(b + c[0], 0, MEM_RELEASE);
        UnmapViewOfFile(b + kContiguousBase);
        UnmapViewOfFile(b + kWriteCombineBase);
    }
#elif defined(__SWITCH__)
    // Horizon: 4 GB of the address space, 4 MB aligned, mapped by MapChunks as the guest commits
    // process code memory aliases need the own process handle and svc 0x73, 0x77 and 0x78 (to undo a half made
    // alias); code memory (0x4B, 0x4C) is the fallback, also when the first alias is refused (MapRun)
    g_process_alias = envGetOwnProcessHandle() != INVALID_HANDLE && envIsSyscallHinted(kSvcMapProcessCodeMemory) &&
                      envIsSyscallHinted(kSvcSetProcessMemoryPermission) && envIsSyscallHinted(kSvcUnmapProcessCodeMemory);
    g_code_memory = envIsSyscallHinted(kSvcCreateCodeMemory) && envIsSyscallHinted(kSvcControlCodeMemory);
    if (!g_process_alias && !g_code_memory) {
        LOGE("memory: the loader allows neither process code memory (svc 0x73, 0x77, 0x78) nor code memory (0x4B, 0x4C)");
        return false;
    }
    virtmemLock();
    void* at = virtmemFindAslr(size + kGpuAlign, 0x10000);
    uint8_t* aligned = at ? reinterpret_cast<uint8_t*>((uintptr_t(at) + kGpuAlign - 1) & ~uintptr_t(kGpuAlign - 1)) : nullptr;
    if (at && virtmemAddReservation(at, size + kGpuAlign)) g_base = aligned;
    virtmemUnlock();
    LOGI("memory: guest RAM by %s", g_process_alias ? "process code memory aliases (GPU mappable)" : "code memory (CPU only)");
    if (g_base && !MapChunks(kContiguousBase, kContiguousBase + kPhysicalSize)) g_base = nullptr;
    // the write combined view: the same pages through svcMapProcessMemory on this process (possible over process code
    // memory aliases, not over code memory), else pages of its own; only the XMV film decoder writes through it
    if (g_base) {
        Result rc = MAKERESULT(Module_Libnx, LibnxError_NotFound);
        if (envIsSyscallHinted(kSvcMapProcessMemory))
            rc = svcMapProcessMemory(g_base + kWriteCombineBase, envGetOwnProcessHandle(),
                                     reinterpret_cast<u64>(g_base + kContiguousBase), kPhysicalSize);
        if (R_SUCCEEDED(rc)) {
            for (uint64_t c = kWriteCombineBase; c < kWriteCombineBase + kPhysicalSize; c += kChunk)
                g_mapped[size_t(c / kChunk)] = true;
        } else if (!MapChunks(kWriteCombineBase, kWriteCombineBase + kPhysicalSize)) {
            g_base = nullptr;
        }
        g_wc_aliased = R_SUCCEEDED(rc);
        g_wc_mirror = R_SUCCEEDED(rc);
        LOGI("memory: write combined view %s", R_SUCCEEDED(rc) ? "aliased" : "separate");
    }
#else
    void* p = mmap(reinterpret_cast<void*>(0x100000000ull), size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    g_base = p == MAP_FAILED ? nullptr : static_cast<uint8_t*>(p);
    int fd = g_base ? memfd_create("ram", 0) : -1;
    if (fd < 0 || ftruncate(fd, kPhysicalSize) ||
        mmap(g_base + kContiguousBase, kPhysicalSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0) == MAP_FAILED ||
        mmap(g_base + kWriteCombineBase, kPhysicalSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0) == MAP_FAILED)
        g_base = nullptr;
#endif
    if (!g_base) {
        LOGE("memory: could not reserve the 4 GB guest space");
        return false;
    }
    LOGI("memory: guest space at %p", static_cast<void*>(g_base));
    return true;
}

// page commit map, one byte per 4 KB page
static std::vector<uint8_t> g_committed(0x100000, 0);

bool Commit(uint32_t va, uint32_t size) {
    if (!size || InPhysical(va)) return true;
    uint32_t first = va & ~(kPage - 1);
    uint64_t end = (uint64_t(va) + size + kPage - 1) & ~uint64_t(kPage - 1);
    std::lock_guard<std::recursive_mutex> lock(g_lock);
#ifdef _WIN32
    if (!VirtualAlloc(g_base + first, size_t(end - first), MEM_COMMIT, PAGE_READWRITE)) {
        LOGE("memory: commit %08X+%X failed", first, uint32_t(end - first));
        return false;
    }
#elif defined(__SWITCH__)
    if (!MapChunks(first, end)) {
        LOGE("memory: commit %08X+%X failed", first, uint32_t(end - first));
        return false;
    }
#else
    if (mprotect(g_base + first, size_t(end - first), PROT_READ | PROT_WRITE)) {
        LOGE("memory: commit %08X+%X failed", first, uint32_t(end - first));
        return false;
    }
#endif
    for (uint64_t p = first; p < end; p += kPage) g_committed[size_t(p >> 12)] = 1;
    return true;
}

void Decommit(uint32_t va, uint32_t size) {
    if (InPhysical(va)) return;
    uint32_t first = va & ~(kPage - 1);
    uint64_t end = (uint64_t(va) + size + kPage - 1) & ~uint64_t(kPage - 1);
    std::lock_guard<std::recursive_mutex> lock(g_lock);
#ifdef _WIN32
    VirtualFree(g_base + first, size_t(end - first), MEM_DECOMMIT);
#elif defined(__SWITCH__)
    // the chunks stay mapped: the pages read as zero, as decommitted memory does once committed again
    std::memset(g_base + first, 0, size_t(end - first));
#else
    madvise(g_base + first, size_t(end - first), MADV_DONTNEED);
    mprotect(g_base + first, size_t(end - first), PROT_NONE);
#endif
    for (uint64_t p = first; p < end; p += kPage) g_committed[size_t(p >> 12)] = 0;
}

bool IsCommitted(uint32_t va) { return InPhysical(va) || g_committed[va >> 12] != 0; }

#ifdef __SWITCH__
alignas(0x1000) static uint8_t g_bounce[256 * 1024];
static std::mutex g_bounce_lock;

Bounce LockBounce() {
    g_bounce_lock.lock();
    return {g_bounce, sizeof g_bounce};
}
void UnlockBounce() { g_bounce_lock.unlock(); }

// each thread's own, so one thread's long read does not hold up another's (the audio streams read while a level
// loads); made on a thread's first transfer, on the heap, which the fs service takes
constexpr size_t kThreadBounce = 256 * 1024;
static uint8_t* ThreadBounce() {
    thread_local std::unique_ptr<uint8_t[]> buffer;
    if (!buffer) buffer.reset(new (std::nothrow) uint8_t[kThreadBounce]);
    return buffer.get();
}

size_t FileRead(void* dst, size_t size, std::FILE* f) {
    uint8_t* bounce = ThreadBounce();
    if (!bounce) return 0;
    size_t done = 0;
    while (done < size) {
        size_t want = std::min(size - done, kThreadBounce);
        size_t got = std::fread(bounce, 1, want, f);
        std::memcpy(static_cast<uint8_t*>(dst) + done, bounce, got);
        done += got;
        if (got < want) break;
    }
    return done;
}

size_t FileWrite(const void* src, size_t size, std::FILE* f) {
    uint8_t* bounce = ThreadBounce();
    if (!bounce) return 0;
    size_t done = 0;
    while (done < size) {
        size_t want = std::min(size - done, kThreadBounce);
        std::memcpy(bounce, static_cast<const uint8_t*>(src) + done, want);
        size_t put = std::fwrite(bounce, 1, want, f);
        done += put;
        if (put < want) break;
    }
    return done;
}
#else
Bounce LockBounce() { return {nullptr, 0}; }
void UnlockBounce() {}
size_t FileRead(void* dst, size_t size, std::FILE* f) { return std::fread(dst, 1, size, f); }
size_t FileWrite(const void* src, size_t size, std::FILE* f) { return std::fwrite(src, 1, size, f); }
#endif

// first fit allocator over a guest range
class Ranges {
public:
    void Init(uint32_t start, uint32_t size) { free_[start] = size; }

    void Remove(uint32_t start, uint32_t size) {
        // carve a fixed range out of the free list
        for (auto it = free_.begin(); it != free_.end(); ++it) {
            uint32_t fs = it->first, fz = it->second;
            if (start >= fs && uint64_t(start) + size <= uint64_t(fs) + fz) {
                free_.erase(it);
                if (start > fs) free_[fs] = start - fs;
                if (uint64_t(start) + size < uint64_t(fs) + fz) free_[start + size] = uint32_t(uint64_t(fs) + fz - start - size);
                return;
            }
        }
    }

    uint32_t Alloc(uint32_t size, uint32_t align, uint32_t lo, uint32_t hi, bool top_down) {
        if (!align) align = 1;
        if (top_down) {
            for (auto it = free_.rbegin(); it != free_.rend(); ++it) {
                uint64_t fs = it->first, fe = fs + it->second;
                uint64_t e = std::min<uint64_t>(fe, uint64_t(hi) + 1);
                if (e < size) continue;
                uint64_t a = (e - size) & ~uint64_t(align - 1);
                if (a < fs || a < lo) continue;
                Take(uint32_t(a), size);
                return uint32_t(a);
            }
            return 0;
        }
        for (auto& [fs, fz] : free_) {
            uint64_t a = std::max<uint64_t>(fs, lo);
            a = (a + align - 1) & ~uint64_t(align - 1);
            if (a + size <= uint64_t(fs) + fz && a + size - 1 <= hi) {
                Take(uint32_t(a), size);
                return uint32_t(a);
            }
        }
        return 0;
    }

    bool IsFree(uint32_t start, uint32_t size) const {
        auto it = free_.upper_bound(start);
        if (it == free_.begin()) return false;
        --it;
        return uint64_t(start) + size <= uint64_t(it->first) + it->second;
    }

    bool Free(uint32_t a, uint32_t* size_out = nullptr) {
        auto it = used_.find(a);
        if (it == used_.end()) return false;
        uint32_t size = it->second;
        used_.erase(it);
        if (size_out) *size_out = size;
        Release(a, size);
        return true;
    }

    void Release(uint32_t a, uint32_t size) {
        auto n = free_.emplace(a, size).first;
        auto next = std::next(n);
        if (next != free_.end() && n->first + n->second == next->first) {
            n->second += next->second;
            free_.erase(next);
        }
        if (n != free_.begin()) {
            auto prev = std::prev(n);
            if (prev->first + prev->second == n->first) {
                prev->second += n->second;
                free_.erase(n);
            }
        }
    }

    void Forget(uint32_t a) { used_.erase(a); }

    uint32_t SizeOf(uint32_t a) const {
        auto it = used_.find(a);
        return it == used_.end() ? 0 : it->second;
    }

    uint64_t Used() const {
        uint64_t n = 0;
        for (auto& u : used_) n += u.second;
        return n;
    }

private:
    void Take(uint32_t a, uint32_t size) {
        Remove(a, size);
        used_[a] = size;
    }
    std::map<uint32_t, uint32_t> free_;
    std::map<uint32_t, uint32_t> used_;
};

static Ranges g_contig, g_system, g_stacks;
static std::map<uint32_t, uint32_t> g_stack_tops;
static bool g_ranges_ready = false;

struct Reservation {
    uint32_t size;
    uint32_t protect;
    std::vector<uint8_t> commit;  // per page
};
static std::map<uint32_t, Reservation> g_reserved;
static Ranges g_user;

static void EnsureRanges() {
    if (g_ranges_ready) return;
    g_ranges_ready = true;
    g_contig.Init(kContiguousBase + kKernelDataSize, kPhysicalSize - kKernelDataSize);
    g_system.Init(kSystemBase, kSystemSize);
    g_stacks.Init(kStackBase, kStackSize);
    g_user.Init(kUserLow, kUserHigh - kUserLow);
    Commit(kKernelDataBase, kKernelDataSize);
}

void ReserveImage(uint32_t base, uint32_t size) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    EnsureRanges();
    uint32_t b = base & ~0xFFFFu;
    uint32_t e = (base + size + 0xFFFF) & ~0xFFFFu;
    g_user.Remove(b, e - b);
    Reservation r{e - b, 4, std::vector<uint8_t>((e - b) / kPage, 1)};  // 4 is PAGE_READWRITE
    g_reserved[b] = std::move(r);
    Commit(b, e - b);
}

static Reservation* FindReservation(uint32_t addr, uint32_t* start) {
    auto it = g_reserved.upper_bound(addr);
    if (it == g_reserved.begin()) return nullptr;
    --it;
    if (addr >= it->first + it->second.size) return nullptr;
    *start = it->first;
    return &it->second;
}

uint32_t AllocateVirtual(uint32_t& base, uint32_t& size, uint32_t type, uint32_t protect) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    EnsureRanges();
    if (!size) return 0xC000000D;  // STATUS_INVALID_PARAMETER
    bool reserve = type & kMemReserve;
    bool commit = type & kMemCommit;
    if (!base && commit) reserve = true;
    if (reserve) {
        uint32_t sz = (size + 0xFFFF) & ~0xFFFFu;
        uint32_t a;
        if (base) {
            a = base & ~0xFFFFu;
            sz = ((base + size + 0xFFFF) & ~0xFFFFu) - a;
            if (!g_user.IsFree(a, sz)) return 0xC0000018;  // STATUS_CONFLICTING_ADDRESSES
            g_user.Remove(a, sz);
        } else {
            a = g_user.Alloc(sz, 0x10000, kUserLow, kUserHigh - 1, type & kMemTopDown);
            if (!a) return 0xC0000017;  // STATUS_NO_MEMORY
            g_user.Forget(a);
        }
        g_reserved[a] = Reservation{sz, protect, std::vector<uint8_t>(sz / kPage, 0)};
        base = a;
        size = sz;
    }
    if (commit) {
        uint32_t start;
        Reservation* r = FindReservation(base, &start);
        if (!r) return 0xC0000045;  // STATUS_INVALID_PAGE_PROTECTION stands in for not reserved
        uint32_t first = base & ~(kPage - 1);
        uint32_t end = (base + size + kPage - 1) & ~(kPage - 1);
        if (end > start + r->size) return 0xC0000018;  // STATUS_CONFLICTING_ADDRESSES
        Commit(first, end - first);
        for (uint32_t p = first; p < end; p += kPage) r->commit[(p - start) / kPage] = 1;
        base = first;
        size = end - first;
    }
    return 0;
}

uint32_t FreeVirtual(uint32_t& base, uint32_t& size, uint32_t type) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    uint32_t start;
    Reservation* r = FindReservation(base, &start);
    if (!r) return 0xC000009F;  // STATUS_MEMORY_NOT_ALLOCATED
    if (type & kMemRelease) {
        uint32_t sz = r->size;
        Decommit(start, sz);
        g_reserved.erase(start);
        g_user.Release(start, sz);
        base = start;
        size = sz;
        return 0;
    }
    uint32_t first = base & ~(kPage - 1);
    uint32_t end = size ? (base + size + kPage - 1) & ~(kPage - 1) : start + r->size;
    Decommit(first, end - first);
    for (uint32_t p = first; p < end; p += kPage) r->commit[(p - start) / kPage] = 0;
    base = first;
    size = end - first;
    return 0;
}

bool QueryVirtual(uint32_t addr, RegionInfo& out) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    uint32_t start;
    Reservation* r = FindReservation(addr, &start);
    std::memset(&out, 0, sizeof(out));
    if (!r) {
        out.base = addr & ~(kPage - 1);
        auto it = g_reserved.upper_bound(addr);
        uint32_t next = it == g_reserved.end() ? kUserHigh : it->first;
        out.size = next > out.base ? next - out.base : kPage;
        out.state = 0x10000;  // MEM_FREE
        out.protect = 1;      // PAGE_NOACCESS
        return addr < kUserHigh;
    }
    uint32_t page = (addr - start) / kPage;
    uint8_t c = r->commit[page];
    uint32_t n = page;
    while (n < r->commit.size() && r->commit[n] == c) n++;
    out.base = start + page * kPage;
    out.alloc_base = start;
    out.alloc_protect = r->protect;
    out.size = (n - page) * kPage;
    out.state = c ? kMemCommit : kMemReserve;
    out.protect = c ? r->protect : 0;
    out.type = 0x20000;  // MEM_PRIVATE
    return true;
}

uint32_t AllocContiguous(uint32_t size, uint32_t lowest, uint32_t highest, uint32_t align) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    EnsureRanges();
    size = (size + kPage - 1) & ~(kPage - 1);
    if (!size) size = kPage;
    align = std::max<uint32_t>(align, kPage);
    uint32_t lo = kContiguousBase | (lowest & (kPhysicalSize - 1));
    uint32_t hi = highest >= kPhysicalSize - 1 ? kContiguousBase + kPhysicalSize - 1 : kContiguousBase | highest;
    // highest fit first: low memory stays free for requests limited to it (D3D report pages, first 16 MB)
    uint32_t a = g_contig.Alloc(size, align, lo, hi, true);
    if (!a) {
        LOGE("memory: contiguous allocation of %X bytes failed (%X..%X align %X), %llu KB in use", size, lowest, highest, align,
             (unsigned long long)(g_contig.Used() >> 10));
        return 0;
    }
    Commit(a, size);
    std::memset(g_base + a, 0, size);
    return a;
}

void FreeContiguous(uint32_t va) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    uint32_t size;
    if (g_contig.Free(va, &size)) Decommit(va, size);
}

uint32_t AllocSystem(uint32_t size, uint32_t align) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    EnsureRanges();
    size = (size + 15) & ~15u;
    if (!size) size = 16;
    uint32_t a = g_system.Alloc(size, std::max<uint32_t>(align, 16), kSystemBase, kSystemBase + kSystemSize - 1, false);
    if (!a) return 0;
    Commit(a, size);
    std::memset(g_base + a, 0, size);
    return a;
}

void FreeSystem(uint32_t va) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    g_system.Free(va);
}

uint32_t AllocStack(uint32_t size) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    EnsureRanges();
    size = (size + 0xFFFF) & ~0xFFFFu;
    // one uncommitted guard page below the stack
    uint32_t a = g_stacks.Alloc(size + 0x10000, 0x10000, kStackBase, kStackBase + kStackSize - 1, false);
    if (!a) return 0;
    Commit(a + 0x10000, size);
    g_stack_tops[a + 0x10000 + size] = a;
    return a + 0x10000 + size;
}

void FreeStack(uint32_t top) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    auto it = g_stack_tops.find(top);
    if (it == g_stack_tops.end()) return;
    uint32_t size;
    if (g_stacks.Free(it->second, &size)) Decommit(it->second, size);
    g_stack_tops.erase(it);
}

uint32_t AllocationSize(uint32_t va) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    if (uint32_t s = g_contig.SizeOf(va)) return s;
    if (uint32_t s = g_system.SizeOf(va)) return s;
    uint32_t start;
    if (Reservation* r = FindReservation(va, &start)) return r->size - (va - start);
    return 0;
}

uint32_t PhysicalFromVirtual(uint32_t va) {
    if (InPhysical(va)) return va & (kPhysicalSize - 1);
    return va;
}

uint32_t VirtualFromPhysical(uint32_t pa) {
    if (pa < kPhysicalSize) return kContiguousBase | pa;
    return pa;
}

Stats Query() {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    Stats s{};
    s.total_pages = kPhysicalSize / kPage;
    uint64_t vc = 0;
    for (auto& [a, r] : g_reserved)
        for (uint8_t c : r.commit) vc += c;
    s.virtual_committed = uint32_t(vc);
    s.contiguous_used = uint32_t(g_contig.Used() / kPage);
    s.system_used = uint32_t(g_system.Used() / kPage);
    uint64_t used = vc + s.contiguous_used + s.system_used;
    s.available_pages = used >= s.total_pages ? 0 : uint32_t(s.total_pages - used);
    return s;
}



}  // namespace mem

namespace mem {

GuestRam GuestRamForGpu() {
    GuestRam r{g_base ? g_base + kContiguousBase : nullptr, kPhysicalSize, false};
#ifdef __SWITCH__
    // a GPU memory block over pages nvmap refuses ends the process (deko3d aborts whatever its callback does):
    // the view must be one process code memory alias, state AliasCodeData (type 0x09), from its first page to its last
    if (r.ptr && g_process_alias) {
        MemoryInfo first{}, last{};
        u32 page = 0;
        bool ok = R_SUCCEEDED(svcQueryMemory(&first, &page, u64(r.ptr))) &&
                  R_SUCCEEDED(svcQueryMemory(&last, &page, u64(r.ptr) + kPhysicalSize - 1));
        r.gpu_mappable = ok && (first.type & 0xFF) == MemType_ModuleCodeMutable && (last.type & 0xFF) == MemType_ModuleCodeMutable &&
                         first.addr <= u64(r.ptr) && last.addr + last.size >= u64(r.ptr) + kPhysicalSize;
        if (!r.gpu_mappable)
            LOGW("memory: guest RAM is not GPU mappable (type %X..%X at %p)", first.type & 0xFF, last.type & 0xFF, r.ptr);
    }
#endif
    return r;
}

#ifdef __SWITCH__
// Unmaps the guest space for a return to the loader (the clean exit, switch/headless/clean_exit.cpp): the loader
// reuses this process and its heap for the next program, and heap pages under an alias are locked. Every thread
// that touches guest memory is paused, and the GPU's mappings are gone (the device closed), before this runs.
// Each call is one the loader allows (envIsSyscallHinted): any other ends the process.
bool Shutdown() {
    if (!g_base) return true;
    const Handle self = envGetOwnProcessHandle();
    bool ok = true;
    if (g_wc_mirror) {
        ok = envIsSyscallHinted(0x75) && R_SUCCEEDED(svcUnmapProcessMemory(g_base + kWriteCombineBase, self,
                                                                         u64(g_base + kContiguousBase), kPhysicalSize));
        g_wc_mirror = false;
    }
    for (auto r = g_runs.rbegin(); r != g_runs.rend(); ++r) {
        Result rc;
        if (r->alias)
            rc = envIsSyscallHinted(0x78) ? svcUnmapProcessCodeMemory(self, u64(g_base + r->first), u64(r->src), r->len)
                                          : MAKERESULT(Module_Libnx, LibnxError_NotFound);
        else {
            rc = svcControlCodeMemory(r->code, CodeMapOperation_UnmapOwner, g_base + r->first, r->len, Perm_None);
            if (R_SUCCEEDED(rc)) svcCloseHandle(r->code);
        }
        ok = ok && R_SUCCEEDED(rc);
    }
    g_runs.clear();
    g_base = nullptr;  // the 4 GB reservation is this program's libnx bookkeeping, gone with it
    return ok;
}
#endif

}  // namespace mem
