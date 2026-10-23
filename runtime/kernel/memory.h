#pragma once
#include <cstdint>
#include <cstdio>

namespace mem {

constexpr uint32_t kPage = 0x1000;
constexpr uint32_t kUserLow = 0x00010000;
constexpr uint32_t kUserHigh = 0x7FFE0000;
constexpr uint32_t kContiguousBase = 0x80000000;  // guest VA = kContiguousBase | physical
constexpr uint32_t kPhysicalSize = 64u << 20;
constexpr uint32_t kWriteCombineBase = 0xF0000000;
constexpr uint32_t kKernelDataBase = 0x80000000;   // first physical megabyte holds kernel variables
constexpr uint32_t kKernelDataSize = 0x00100000;
constexpr uint32_t kSystemBase = 0xB0000000;       // pool, system memory, thread blocks
constexpr uint32_t kSystemSize = 0x10000000;
constexpr uint32_t kStackBase = 0xD0000000;
constexpr uint32_t kStackSize = 0x10000000;

// NT allocation flags
constexpr uint32_t kMemCommit = 0x1000, kMemReserve = 0x2000, kMemDecommit = 0x4000, kMemRelease = 0x8000,
                   kMemTopDown = 0x100000, kMemNoZero = 0x800000;

bool Init();
#ifdef __SWITCH__
bool Shutdown();  // unmaps the guest space for a return to the loader (every guest thread paused)
#endif
uint8_t* Base();
// the write combined view (kWriteCombineBase) shows the same pages as the contiguous one; false on Horizon without
// svcMapProcessMemory, where it is pages of its own and a writer through it must write the contiguous view instead
bool WriteCombineAliased();

// Guest RAM for the GPU: the contiguous view, guest physical 0 to kPhysicalSize at Base() + kContiguousBase (the write
// combined view shows the same pages when WriteCombineAliased). gpu_mappable: on Horizon, the view's pages are in a
// state nvmap accepts (checked with svcQueryMemory at each call), so one deko3d memory block may use ptr as storage;
// see ZEROCOPY.md for the flush rules. Call after Init.
struct GuestRam {
    uint8_t* ptr;
    uint32_t size;
    bool gpu_mappable;
};
GuestRam GuestRamForGpu();
bool Commit(uint32_t va, uint32_t size);
void Decommit(uint32_t va, uint32_t size);
bool IsCommitted(uint32_t va);

// user virtual space, NTSTATUS results
uint32_t AllocateVirtual(uint32_t& base, uint32_t& size, uint32_t type, uint32_t protect);
uint32_t FreeVirtual(uint32_t& base, uint32_t& size, uint32_t type);
struct RegionInfo {
    uint32_t base, alloc_base, alloc_protect, size, state, protect, type;
};
bool QueryVirtual(uint32_t addr, RegionInfo& out);
void ReserveImage(uint32_t base, uint32_t size);

uint32_t AllocContiguous(uint32_t size, uint32_t lowest, uint32_t highest, uint32_t align);
void FreeContiguous(uint32_t va);
uint32_t AllocationSize(uint32_t va);  // any allocator, 0 if unknown

// file reads into and writes from guest memory; Horizon's fs service takes no code memory (the guest's pages there)
// as an IPC buffer, so on the Switch they go through a host buffer
size_t FileRead(void* dst, size_t size, std::FILE* f);
size_t FileWrite(const void* src, size_t size, std::FILE* f);
// a host buffer for reads into guest memory with other APIs (Horizon), held while in use
struct Bounce {
    uint8_t* data;
    size_t size;
};
Bounce LockBounce();
void UnlockBounce();

uint32_t AllocSystem(uint32_t size, uint32_t align = 16);
void FreeSystem(uint32_t va);

uint32_t AllocStack(uint32_t size);  // returns the top, guard below the bottom
void FreeStack(uint32_t top);

uint32_t PhysicalFromVirtual(uint32_t va);
uint32_t VirtualFromPhysical(uint32_t pa);

struct Stats {
    uint32_t total_pages, available_pages, virtual_committed, contiguous_used, system_used;
};
Stats Query();

}  // namespace mem
