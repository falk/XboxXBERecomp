#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

#include "kernel/kernel.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <pthread.h>
#endif
#ifdef __SWITCH__
#include <switch.h>
#endif

namespace kernel {

namespace {

thread_local ThreadRef t_current;
std::mutex g_threads_lock;
std::vector<ThreadRef> g_threads;
std::atomic<uint32_t> g_next_id{0x10};

// guest structures per thread
constexpr uint32_t kKpcrSize = 0x400;
constexpr uint32_t kEthreadSize = 0x200;

void SetupGuestBlocks(Thread& t, uint32_t stack_size, uint32_t tls_size) {
    stack_size = std::max<uint32_t>(stack_size, 0x10000);
    tls_size = (tls_size + 3) & ~3u;
    t.stack_top = mem::AllocStack(stack_size + tls_size + 0x1000);
    t.stack_size = stack_size;
    t.kpcr = mem::AllocSystem(kKpcrSize, 64);
    t.ethread = mem::AllocSystem(kEthreadSize, 64);
    // TLS sits at the top of the stack: StackBase + tls_index * 4 must equal TlsData
    t.tls = t.stack_top - tls_size;
    uint32_t k = t.kpcr;
    W32(k + 0x00, 0xFFFFFFFF);                  // NtTib.ExceptionList
    W32(k + 0x04, t.stack_top);                 // NtTib.StackBase
    W32(k + 0x08, t.stack_top - stack_size);    // NtTib.StackLimit
    W32(k + 0x18, k);                           // NtTib.Self
    W32(k + 0x1C, k);                           // SelfPcr
    W32(k + 0x20, k + 0x28);                    // Prcb
    G<uint8_t>(k + 0x24) = 0;                   // Irql
    W32(k + 0x28, t.ethread);                   // PrcbData.CurrentThread
    uint32_t e = t.ethread;
    G<uint8_t>(e + 0) = 6;                      // dispatcher type ThreadObject
    G<uint8_t>(e + 2) = uint8_t(kEthreadSize / 4);  // Header.Size in dwords
    W32(e + 0x1C, t.stack_top);                 // KTHREAD.StackBase
    W32(e + 0x20, t.stack_top - stack_size);    // KTHREAD.StackLimit
    W32(e + 0x28, t.tls);                       // KTHREAD.TlsData
    W32(e + 0x12C, t.id);                       // ETHREAD.UniqueThread
}

void InitContext(Thread& t, X86Context& ctx) {
    std::memset(&ctx, 0, sizeof(ctx));
    ctx.esp = (t.tls & ~15u) - 16;
    ctx.fs_base = t.kpcr;
    ctx.fcw = 0x27F;  // x87 53 bit precision, exceptions masked
    ctx.mxcsr = 0x1F80;  // SSE exceptions masked, round to nearest
    ctx.thread_handle = 0;
    t.ctx = &ctx;
}

void Register(const ThreadRef& t) {
    std::lock_guard<std::mutex> lock(g_threads_lock);
    g_threads.push_back(t);
}

void Unregister(Thread* t) {
    std::lock_guard<std::mutex> lock(g_threads_lock);
    g_threads.erase(std::remove_if(g_threads.begin(), g_threads.end(), [t](const ThreadRef& r) { return r.get() == t; }),
                    g_threads.end());
}

void MarkExited(Thread& t, uint32_t code) {
    t.exit_code = code;
    SetSignal(t, 1);
}

void NameHostThread(const char* name) {
#ifdef _WIN32
    wchar_t w[64];
    size_t i = 0;
    for (; name[i] && i < 63; i++) w[i] = wchar_t(name[i]);
    w[i] = 0;
    using Fn = HRESULT(WINAPI*)(HANDLE, PCWSTR);
    static Fn set = reinterpret_cast<Fn>(reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetThreadDescription")));
    if (set) set(GetCurrentThread(), w);
#elif defined(__SWITCH__)
    (void)name;  // newlib's pthreads on Horizon keep no names
#else
    pthread_setname_np(pthread_self(), name);
#endif
}

// recompiled code nests host frames as deep as the guest's calls, give it room
void Spawn(std::function<void()> fn) {
    auto* f = new std::function<void()>(std::move(fn));
#ifdef _WIN32
    auto entry = [](void* p) -> DWORD {
        std::unique_ptr<std::function<void()>> g(static_cast<std::function<void()>*>(p));
        (*g)();
        return 0;
    };
    HANDLE h = ::CreateThread(nullptr, 64u << 20, entry, f, STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
    if (h) ::CloseHandle(h);
#else
    pthread_attr_t attr;
    pthread_attr_init(&attr);
#ifdef __SWITCH__
    // a Horizon stack is allocated, not only reserved; Black plays in 256 KB
    pthread_attr_setstacksize(&attr, 2u << 20);
#else
    pthread_attr_setstacksize(&attr, 64u << 20);
#endif
    pthread_t th;
    pthread_create(&th, &attr, [](void* p) -> void* {
        std::unique_ptr<std::function<void()>> g(static_cast<std::function<void()>*>(p));
        (*g)();
        return nullptr;
    }, f);
    pthread_detach(th);
    pthread_attr_destroy(&attr);
#endif
}

#ifdef __SWITCH__
// Horizon placement. libnx starts every pthread at priority 0x3B with the whole process core mask.
// The Xbox has one CPU and the PC is x86 (TSO): the title's threads hand data to each other with plain stores, which
// another A57 core may see out of order. So by default every thread that runs guest code (guest threads and the
// runtime's DPC, vertical blank and sound threads) shares one core, at 0x3B, the priority Horizon round-robins, and
// the runtime's own threads (timers, clock) run on the other cores.
//   XBE_PIN=guest[:<core>]                  that default, core 1 unless given
//   XBE_PIN=split[:<core>[,<priority>]]     the game thread alone on <core> (default 1) at <priority> (default 0x2C,
//                                           lower runs first), every other thread on the remaining cores: guest
//                                           threads run in parallel, so only for titles whose handoffs are proven
//   XBE_PIN=off                             libnx's placement: every thread on every core at 0x3B
//   XBE_PRIO=xbox (default) | sliced | off  guest mode: each thread at its Xbox priority, mapped by HorizonPriority, so
//                                           the guest core runs its highest ready thread without time slices, as the
//                                           Xbox's one CPU does; sliced: the same above normal, normal and below at
//                                           0x3B, the one priority Horizon gives time slices (10 ms): the Xbox
//                                           round-robins equal priorities (a thread busy until another runs, a save
//                                           worker beside the game thread, otherwise holds the core); off: every
//                                           guest thread at 0x3B
// The game thread is the XBE entry thread; when the entry thread returns or exits having started threads (XAPI's
// startup runs main() on a thread of its own and returns), the place passes to the first thread it started.
enum class PinMode { Off, Guest, Split };

struct Placement {
    PinMode mode = PinMode::Guest;
    int core = 1;
    int priority = 0x2C;   // the game thread's, in split mode
    bool xbox_priorities = true;  // guest mode: threads at their Xbox priorities
    bool sliced = false;          // those at normal priority and below at 0x3B
    uint32_t all = 0;      // the process core mask
    uint32_t others = 0;   // every core but `core`
};

const Placement& Place() {
    static const Placement p = [] {
        Placement p;
        u64 mask = 0;
        svcGetInfo(&mask, InfoType_CoreMask, CUR_PROCESS_HANDLE, 0);
        p.all = uint32_t(mask);
        const char* v = getenv("XBE_PIN");
        std::string s = v ? v : "guest";
        if (s == "off") {
            p.mode = PinMode::Off;
        } else if (s.rfind("split", 0) == 0 || s.rfind("guest", 0) == 0) {
            p.mode = s[0] == 's' ? PinMode::Split : PinMode::Guest;
            if (s.size() > 6 && s[5] == ':') {
                char* end = nullptr;
                p.core = int(std::strtol(s.c_str() + 6, &end, 0));
                if (end && *end == ',') p.priority = int(std::strtol(end + 1, nullptr, 0));
            }
        } else {
            LOGW("placement: XBE_PIN=%s is not off, guest[:core] or split[:core[,priority]]; guest:1", v);
        }
        const char* prio = getenv("XBE_PRIO");
        p.xbox_priorities = !(prio && std::strcmp(prio, "off") == 0);
        p.sliced = prio && std::strcmp(prio, "sliced") == 0;
        bool valid = p.core >= 0 && p.core < 32 && (p.all >> p.core & 1);
        p.others = valid ? p.all & ~(1u << p.core) : 0;
        if (p.mode != PinMode::Off && !p.others) {
            LOGW("placement: core %d is not one of several in %X, placement off", p.core, p.all);
            p.mode = PinMode::Off;
        }
        static const char* kNames[] = {"off", "guest", "split"};
        LOGI("placement: %s, core %d, cores %X, %s priorities", kNames[int(p.mode)], p.core, p.all,
             p.mode == PinMode::Guest && p.xbox_priorities ? (p.sliced ? "Xbox (normal and below time sliced)" : "Xbox")
                                                            : "equal");
        return p;
    }();
    return p;
}

std::mutex g_place_lock;
Thread* g_entry = nullptr;  // the XBE entry thread
Thread* g_heir = nullptr;   // the first thread the entry thread started
Thread* g_game = nullptr;   // the game thread
int g_next_core = 0;

enum class Role { Game, Guest, Host };  // runs the game thread, other guest code, or host code only

// Horizon runs lower values first; Xbox 8 (normal) is 0x2C, each Xbox level one Horizon level, within the 0x21-0x3B a
// homebrew thread may take; the interrupt level (StartHostThread's threads) above them all at 0x20
int HorizonPriority(int xbox) {
    if (xbox >= kInterruptPriority) return 0x20;
    if (xbox <= 8 && Place().sliced) return 0x3B;
    return std::clamp(0x34 - xbox, 0x21, 0x3B);
}

// caller holds g_place_lock; xbox is the thread's Xbox priority, -1 for a thread without one
void PlaceOn(uint32_t handle, uint32_t id, const char* name, Role role, int xbox = -1) {
    const Placement& p = Place();
    if (p.mode == PinMode::Off || !handle) return;
    Result rc;
    int ideal;
    uint32_t mask;
    if (role == Role::Game || (role == Role::Guest && p.mode == PinMode::Guest)) {
        ideal = p.core;
        mask = 1u << p.core;
    } else {
        ideal = g_next_core;
        do ideal = (ideal + 1) % 32;
        while (!(p.others >> ideal & 1));
        g_next_core = ideal;
        mask = p.others;
    }
    rc = svcSetThreadCoreMask(handle, ideal, mask);
    if (R_SUCCEEDED(rc) && role == Role::Game && p.mode == PinMode::Split) rc = svcSetThreadPriority(handle, u32(p.priority));
    if (R_SUCCEEDED(rc) && role != Role::Host && xbox >= 0 && p.mode == PinMode::Guest && p.xbox_priorities)
        rc = svcSetThreadPriority(handle, u32(HorizonPriority(xbox)));
    s32 prio = 0;
    svcGetThreadPriority(&prio, handle);
    if (R_SUCCEEDED(rc))
        LOGI("placement: thread %X (%s)%s on cores %X, ideal %d, priority 0x%X", id, name,
             role == Role::Game ? " game thread" : "", mask, ideal, prio);
    else
        LOGW("placement: thread %X (%s) not placed (%X)", id, name, rc);
}

// on the started thread's own host thread; guest code runs on it
void PlaceStarted(Thread& t, const char* name) {
    std::lock_guard<std::mutex> lock(g_place_lock);
    t.host_thread = threadGetCurHandle();
    PlaceOn(t.host_thread, t.id, name, g_game == &t ? Role::Game : Role::Guest, t.xbox_priority);
}

// a guest thread about to start, on its creator's thread
void NoteStart(Thread& t) {
    std::lock_guard<std::mutex> lock(g_place_lock);
    if (!g_entry) {
        g_entry = g_game = &t;
    } else if (!g_heir && Current() == g_entry) {
        g_heir = &t;
    }
}

void NoteExit(Thread& t) {
    std::lock_guard<std::mutex> lock(g_place_lock);
    if (&t != g_entry || g_game != &t || !g_heir) return;
    g_game = g_heir;
    PlaceOn(g_heir->host_thread, g_heir->id, "after the entry thread", Role::Game, g_heir->xbox_priority);  // a heir not running yet places itself
}
#else
// Linux test scheduling, XBE_SCHED=fifo[:<cpu>]: every thread that runs guest code is SCHED_FIFO at 10 + its Xbox
// priority and, with <cpu>, bound to that one CPU: strict priority without time slices, as on the Xbox's one CPU and
// on a Horizon core. Needs CAP_SYS_NICE (sudo).
struct Sched {
    bool fifo = false;
    int cpu = -1;
};
const Sched& SchedMode() {
    static const Sched s = [] {
        Sched s;
        const char* v = getenv("XBE_SCHED");
        if (v && std::strncmp(v, "fifo", 4) == 0) {
            s.fifo = true;
            if (v[4] == ':') s.cpu = std::atoi(v + 5);
            LOGI("sched: SCHED_FIFO, cpu %d", s.cpu);
        }
        return s;
    }();
    return s;
}
std::mutex g_sched_lock;
void PlaceStarted(Thread& t, const char*) {
    if (!SchedMode().fifo) return;
    {
        std::lock_guard<std::mutex> lock(g_sched_lock);
        t.host_pthread = uintptr_t(pthread_self());
    }
    if (SchedMode().cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(SchedMode().cpu, &set);
        pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    }
    ApplyPriority(t);
}
void NoteStart(Thread&) {}
void NoteExit(Thread&) {}
#endif

}  // namespace

Thread* Current() { return t_current.get(); }
ThreadRef CurrentRef() { return t_current; }
X86Context& CurrentContext() { return *t_current->ctx; }

std::vector<ThreadRef> Threads() {
    std::lock_guard<std::mutex> lock(g_threads_lock);
    return g_threads;
}

struct StartInfo {
    uint32_t system_routine, start_routine, start_context;
};
static std::unordered_map<Thread*, StartInfo> g_start;
static std::mutex g_start_lock;

ThreadRef CreateThread(uint32_t stack_size, uint32_t tls_size, uint32_t system_routine, uint32_t start_routine,
                       uint32_t start_context, bool suspended) {
    auto t = std::make_shared<Thread>();
    t->id = g_next_id.fetch_add(4);
    SetupGuestBlocks(*t, stack_size, tls_size);
    Bind(t, t->ethread);
    if (suspended) t->suspend = 1;
    std::lock_guard<std::mutex> lock(g_start_lock);
    g_start[t.get()] = {system_routine, start_routine, start_context};
    return t;
}

void StartThread(ThreadRef t) {
    Register(t);
    NoteStart(*t);
    Spawn([t] {
        t_current = t;
        char name[32];
        std::snprintf(name, sizeof(name), "guest %X", t->id);
        NameHostThread(name);
        PlaceStarted(*t, name);
        X86Context ctx;
        InitContext(*t, ctx);
        {
            std::unique_lock<std::mutex> lock(t->apc_lock);
            t->resume_cv.wait(lock, [&] { return t->suspend.load() <= 0; });
        }
        StartInfo si;
        {
            std::lock_guard<std::mutex> lock(g_start_lock);
            si = g_start[t.get()];
            g_start.erase(t.get());
        }
        LOGI("thread %X starts at %08X (%08X, %08X)", t->id, si.system_routine ? si.system_routine : si.start_routine,
             si.start_routine, si.start_context);
        uint32_t code;
        if (si.system_routine)
            code = CallGuest(ctx, si.system_routine, {si.start_routine, si.start_context});
        else
            code = CallGuest(ctx, si.start_routine, {si.start_context});
        LOGI("thread %X returned %08X", t->id, code);
        NoteExit(*t);
        MarkExited(*t, code);
        Unregister(t.get());
        t_current.reset();
    });
}

void StartHostThread(const char* name, std::function<void(X86Context&)> fn) {
    auto t = std::make_shared<Thread>();
    t->id = g_next_id.fetch_add(4);
    // the runtime's guest code threads stand in for interrupts and DPCs (vertical blank, DPC queue, sound): above
    // every thread priority, so they preempt the title's threads as on the Xbox
    t->xbox_priority = kInterruptPriority;
    SetupGuestBlocks(*t, 0x20000, 0x100);
    Bind(t, t->ethread);
    std::string n = name;
    Spawn([t, fn, n] {
        t_current = t;
        NameHostThread(n.c_str());
        PlaceStarted(*t, n.c_str());
        X86Context ctx;
        InitContext(*t, ctx);
        fn(ctx);
        t_current.reset();
    });
}

void ExitThread(uint32_t code) {
    Thread* t = Current();
    if (t) {
        LOGI("thread %X exits with %08X", t->id, code);
        NoteExit(*t);
        MarkExited(*t, code);
        Unregister(t);
    }
    t_current.reset();
#ifdef _WIN32
    ::ExitThread(code);
#else
    pthread_exit(nullptr);
#endif
}

void ApplyPriority(Thread& t) {
#if !defined(_WIN32) && !defined(__SWITCH__)
    if (!SchedMode().fifo) return;
    std::lock_guard<std::mutex> lock(g_sched_lock);
    if (!t.host_pthread) return;  // applied when the thread starts
    sched_param sp{};
    sp.sched_priority = 10 + t.xbox_priority;
    int rc = pthread_setschedparam(pthread_t(t.host_pthread), SCHED_FIFO, &sp);
    LOGI("sched: thread %X at Xbox priority %d%s", t.id, t.xbox_priority, rc ? " refused" : "");
#elif defined(__SWITCH__)
    std::lock_guard<std::mutex> lock(g_place_lock);
    const Placement& p = Place();
    if (!t.host_thread || p.mode != PinMode::Guest || !p.xbox_priorities) return;  // applied when the thread starts
    Result rc = svcSetThreadPriority(t.host_thread, u32(HorizonPriority(t.xbox_priority)));
    LOGI("placement: thread %X at Xbox priority %d, Horizon 0x%X%s", t.id, t.xbox_priority,
         HorizonPriority(t.xbox_priority), R_SUCCEEDED(rc) ? "" : " (refused)");
#else
    (void)t;
#endif
}

void PlaceHostThread(const char* name) {
#ifdef __SWITCH__
    std::lock_guard<std::mutex> lock(g_place_lock);
    PlaceOn(threadGetCurHandle(), 0, name, Role::Host);
#else
    (void)name;
#endif
}

void Resume(Thread& t) {
    std::lock_guard<std::mutex> lock(t.apc_lock);
    if (t.suspend > 0) t.suspend--;
    t.resume_cv.notify_all();
}

uint32_t Suspend(Thread& t) {
    uint32_t prev = uint32_t(t.suspend++);
    if (&t == Current()) SuspendPoint();
    return prev;
}

void SuspendPoint() {
    Thread* t = Current();
    if (!t || t->suspend.load() <= 0) return;
    std::unique_lock<std::mutex> lock(t->apc_lock);
    t->resume_cv.wait(lock, [&] { return t->suspend.load() <= 0; });
}

// The APC is queued before the dispatcher lock is taken: an alertable wait checks the queue under that lock, so it
// either sees the APC or is blocked when the wake comes.
void QueueApc(Thread& t, uint32_t routine, uint32_t a1, uint32_t a2, uint32_t a3) {
    {
        std::lock_guard<std::mutex> lock(t.apc_lock);
        t.apcs.push_back({routine, a1, a2, a3});
    }
    std::lock_guard<std::mutex> lock(DispatchLock());
    if (t.alertable_wait) WakeAlertable(*t.alertable_wait);
}

bool RunApcs(Thread& t) {
    bool ran = false;
    for (;;) {
        std::array<uint32_t, 4> a;
        {
            std::lock_guard<std::mutex> lock(t.apc_lock);
            if (t.apcs.empty()) break;
            a = t.apcs.front();
            t.apcs.pop_front();
        }
        CallGuest(*t.ctx, a[0], {a[1], a[2], a[3]});
        ran = true;
    }
    return ran;
}

}  // namespace kernel
