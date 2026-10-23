// Differential fuzzer for recompiled functions. Runs each __imp__ body on a deterministic random context and lazily
// generated guest memory, with every callee (sub_X, x86_icall, x86_kernel, hooks) replaced by a recorder, and prints
// one digest per (function, trial): final context, guest pages that changed, and the hashed sequence of calls with the
// full register state at each. Two builds of the same driver over old and new generated code must print the same
// lines. Usage: fz <out> [trials] [first] [count]   env FZ_TIMEOUT_MS (default 300)
#include <csetjmp>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>

#include "cpu/x86_ops.h"
#include "fz.h"

namespace {
constexpr uint64_t kSpan = (1ull << 32) + (1ull << 16);
constexpr size_t kMaxPages = 8192;
constexpr uint32_t kBudget = 4096;
enum Outcome { kReturn = 0, kTrap = 1, kBudgetOut = 2, kTimeout = 3, kMemLimit = 4, kFault = 5, kThrown = 6 };

uint8_t* g_base;
uint64_t g_seed;
uint64_t g_pages[kMaxPages];
size_t g_npages;
sigjmp_buf g_jmp;
uint64_t g_trace;
uint32_t g_calls;
uint64_t g_tsc;
uint32_t g_trap_va;
bool g_dump;

void DumpCtx(const char* tag, const X86Context& c) {
    std::fprintf(stderr, "%s eax %08X ecx %08X edx %08X ebx %08X esp %08X ebp %08X esi %08X edi %08X flags %u%u%u%u%u top %u fsw %04X\n", tag, c.eax, c.ecx, c.edx, c.ebx, c.esp, c.ebp, c.esi, c.edi, c.cf, c.zf, c.sf, c.of, c.pf, c.top, c.fsw);
    for (int i = 0; i < 8; i++) std::fprintf(stderr, "  xmm%d %08X %08X %08X %08X  mm%d %016llX st%d %a\n", i, c.xmm[i].u[0], c.xmm[i].u[1], c.xmm[i].u[2], c.xmm[i].u[3], i, (unsigned long long)c.mm[i], i, c.st[i]);
}

inline uint64_t Mix(uint64_t z) {
    z += 0x9E3779B97F4A7C15ull;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

uint32_t Word0(uint64_t h) {
    uint32_t r = uint32_t(h), sel = uint32_t(h >> 32) & 15;
    if (sel < 6) return r & 0x3F;
    if (sel < 8) return 0;
    if (sel < 11) {
        float f = float(int32_t(r % 2001) - 1000) / 10.0f;
        uint32_t u;
        std::memcpy(&u, &f, 4);
        return u;
    }
    if (sel < 13) return 0x00100000u + (r & 0x00FFFFFCu);
    if (sel == 13) return r & 0xFFFF;
    return r;
}

// The host's default NaN: the only NaN the inputs hold. With two NaN operands the result is the first one's, and C++
// leaves the operand order of a commutative operation to the compiler, so payload differences between NaNs would make
// two correct builds disagree; NaNs the game computes are all the default one.
#if defined(__aarch64__)
constexpr uint32_t kNaN = 0x7FC00000u;
#else
constexpr uint32_t kNaN = 0xFFC00000u;
#endif
uint32_t Canon(uint32_t w) {
    if (((w >> 23) & 0xFF) == 0xFF && (w & 0x7FFFFF)) return kNaN;
    if (((w >> 20) & 0x7FF) == 0x7FF) w &= ~(1u << 20);  // nor the high half of a double NaN
    return w;
}

uint32_t Word(uint64_t h) { return Canon(Word0(h)); }

uint32_t InitWord(uint64_t addr) { return Word(Mix(g_seed ^ (addr * 0x9E3779B97F4A7C15ull))); }

void FillPage(uint64_t page, uint32_t* p) {
    for (unsigned i = 0; i < 1024; i++) p[i] = InitWord(page * 4096 + i * 4);
}

void OnSegv(int, siginfo_t* si, void*) {
    uint8_t* a = static_cast<uint8_t*>(si->si_addr);
    if (g_base && a >= g_base && a < g_base + kSpan) {
        uint64_t page = uint64_t(a - g_base) >> 12;
        if (g_npages >= kMaxPages) siglongjmp(g_jmp, kMemLimit);
        uint8_t* p = g_base + page * 4096;
        g_pages[g_npages++] = page;  // recorded first, so a reset finds it whatever interrupts the fill
        mprotect(p, 4096, PROT_READ | PROT_WRITE);
        FillPage(page, reinterpret_cast<uint32_t*>(p));
        return;
    }
    siglongjmp(g_jmp, kFault);
}

void OnAlarm(int) { siglongjmp(g_jmp, kTimeout); }

// the context up to the runtime owned fields
constexpr size_t kCtxBytes = offsetof(X86Context, thread_handle);

uint64_t HashBytes(uint64_t h, const void* p, size_t n) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t w;
        std::memcpy(&w, b + i, 8);
        h = Mix(h ^ w);
    }
    for (; i < n; i++) h = Mix(h ^ b[i]);
    return h;
}

void Record(uint32_t what, X86Context& ctx) {
    if (g_dump) { char t[32]; std::snprintf(t, sizeof t, "call %08X", what); DumpCtx(t, ctx); }
    g_trace = Mix(g_trace ^ what);
    g_trace = HashBytes(g_trace, &ctx, kCtxBytes);
    if (++g_calls > kBudget) siglongjmp(g_jmp, kBudgetOut);
}

// a callee: pops its return address and leaves eax, ecx, edx and the SSE and MMX registers as functions of the trace
void Callee(X86Context& ctx) {
    uint64_t h = Mix(g_trace);
    // a callee may leave anything in every register; it pops its return address and 0 to 3 stdcall arguments
    ctx.esp += 4 + 4 * uint32_t(Mix(h + 7) & 3);
    ctx.eax = Word(h);
    ctx.ecx = Word(Mix(h + 1));
    ctx.edx = Word(Mix(h + 2));
    ctx.ebx = Word(Mix(h + 3));
    ctx.ebp = Word(Mix(h + 4));
    ctx.esi = Word(Mix(h + 5));
    ctx.edi = Word(Mix(h + 6));
    for (int i = 0; i < 8; i++) {
        for (int l = 0; l < 4; l++) ctx.xmm[i].u[l] = Word(Mix(h + 16 + uint64_t(i) * 4 + uint64_t(l)));
        ctx.mm[i] = Mix(h + 64 + uint64_t(i));
    }
    // now and then a C++ catch continuation is thrown through the caller, with an esp above or below its frame
    if ((Mix(h + 9) & 31) == 0) {
        uint32_t esp = ctx.esp + ((Mix(h + 10) & 1) ? 0x40u : uint32_t(-0x40));
        throw X86Resume{0x00ABC000u ^ uint32_t(Mix(h + 11) & 0xFFF), esp};
    }
}

void Reset() {
    for (size_t i = 0; i < g_npages; i++) {
        uint8_t* p = g_base + g_pages[i] * 4096;
        madvise(p, 4096, MADV_DONTNEED);
        mprotect(p, 4096, PROT_NONE);
    }
    g_npages = 0;
}

uint64_t MemDigest() {
    // pages whose content differs from the generated content, in address order
    uint64_t sorted[kMaxPages];
    std::memcpy(sorted, g_pages, g_npages * 8);
    for (size_t i = 1; i < g_npages; i++)
        for (size_t j = i; j > 0 && sorted[j - 1] > sorted[j]; j--) std::swap(sorted[j - 1], sorted[j]);
    static uint32_t init[1024];
    uint64_t h = 0;
    for (size_t i = 0; i < g_npages; i++) {
        uint8_t* p = g_base + sorted[i] * 4096;
        FillPage(sorted[i], init);
        if (std::memcmp(p, init, 4096) == 0) continue;
        if (g_dump)
            for (int w = 0; w < 1024; w++)
                if (std::memcmp(p + w * 4, &init[w], 4)) {
                    uint32_t v;
                    std::memcpy(&v, p + w * 4, 4);
                    std::fprintf(stderr, "  mem %08llX = %08X (was %08X)\n", (unsigned long long)(sorted[i] * 4096 + w * 4), v, init[w]);
                }
        h = Mix(h ^ sorted[i]);
        h = HashBytes(h, p, 4096);
    }
    return h;
}

void InitCtx(X86Context& ctx, uint64_t s) {
    std::memset(&ctx, 0, sizeof(ctx));
    auto r = [&](int k) { return Mix(s * 31 + uint64_t(k)); };
    uint32_t* gpr = &ctx.eax;
    for (int i = 0; i < 8; i++) gpr[i] = Word(r(i));
    ctx.esp = 0x00E00000u + (uint32_t(r(20)) & 0xFFC);
    ctx.cf = r(21) & 1;
    ctx.zf = r(22) & 1;
    ctx.sf = r(23) & 1;
    ctx.of = r(24) & 1;
    ctx.pf = r(25) & 1;
    ctx.fs_base = 0x00D00000u;
    ctx.fcw = 0x027F;
    ctx.mxcsr = 0x1F80;
    for (int i = 0; i < 8; i++) ctx.st[i] = double(int64_t(r(30 + i) % 20001) - 10000) / 100.0;
    for (int i = 0; i < 8; i++) ctx.mm[i] = r(40 + i);
    for (int i = 0; i < 8; i++)
        for (int l = 0; l < 4; l++) {
            uint64_t h = r(50 + i * 4 + l);
            uint32_t sel = uint32_t(h >> 40) & 31;
            float f;
            if (sel == 0) { uint32_t nan = kNaN; std::memcpy(&f, &nan, 4); }
            else if (sel == 1) f = -0.0f;
            else if (sel == 2) f = __builtin_inff();
            else if (sel == 3) f = 1e-40f;
            else if (sel == 4) f = 0.0f;
            else f = float(int32_t(uint32_t(h) % 20001) - 10000) / 100.0f;
            std::memcpy(&ctx.xmm[i].u[l], &f, 4);
            if (sel == 5) ctx.xmm[i].u[l] = Word(h);
        }
}
}  // namespace

// no dispatch table: every indirect call takes x86_icall, the recorder
// the dispatch table of the fast path: each function's recorder at its guest address (the slow path records the same)
X86Func* const* x86_icall_table = nullptr;
uint32_t x86_icall_lo = 0, x86_icall_count = 0;
static void BuildIcallTable() {
    uint32_t lo = ~0u, hi = 0;
    for (const FzEntry* e = fz_stubs; e->fn; e++) {
        if (e->va >= 0xFFFF0000u) continue;
        lo = e->va < lo ? e->va : lo;
        hi = e->va > hi ? e->va : hi;
    }
    auto* t = static_cast<X86Func**>(std::calloc(hi - lo + 1, sizeof(X86Func*)));
    for (const FzEntry* e = fz_stubs; e->fn; e++)
        if (e->va >= lo && e->va <= hi) t[e->va - lo] = e->fn;
    x86_icall_table = t;
    x86_icall_lo = lo;
    x86_icall_count = hi - lo + 1;
}

void fz_stub(uint32_t callee, X86Context& ctx, uint8_t*) {
    Record(callee, ctx);
    Callee(ctx);
}

uint32_t fz_hook(int id, X86Context& ctx, uint8_t*) {
    Record(0xFC000000u + uint32_t(id), ctx);
    return uint32_t(Mix(g_trace));
}

void x86_icall(X86Context& ctx, uint8_t*, uint32_t target) {
    Record(target, ctx);  // as the recorder the fast path reaches through the table
    Callee(ctx);
}
void x86_kernel(X86Context& ctx, uint8_t*, uint32_t ordinal) {
    Record(0xFA000000u + ordinal, ctx);
    Callee(ctx);
}
void x86_resume(X86Context& ctx, uint8_t*, const X86Resume& r) {
    Record(0xF9000000u ^ r.target, ctx);
    siglongjmp(g_jmp, kTrap);
}
[[noreturn]] void x86_trap(X86Context& ctx, uint32_t va, const char*) {
    Record(0xF8000000u ^ va, ctx);
    g_trap_va = va;
    siglongjmp(g_jmp, kTrap);
}
void x86_priv(X86Context& ctx, uint32_t va, const char*) { Record(0xF7000000u ^ va, ctx); }
uint32_t x86_trace(X86Context& ctx, uint32_t va, uint32_t ret) {
    Record(0xF6000000u ^ va, ctx);
    return ret ? ret : 1;
}
uint64_t x86_rdtsc() { return g_tsc += 1000; }
void x86_cpuid(X86Context& ctx) {
    Record(0xF5000000u, ctx);
    switch (ctx.eax) {
        case 0: ctx.eax = 2; ctx.ebx = 0x756E6547; ctx.edx = 0x49656E69; ctx.ecx = 0x6C65746E; break;
        case 1: ctx.eax = 0x0000068A; ctx.ebx = 0; ctx.ecx = 0; ctx.edx = 0x0383F9FF; break;
        default: ctx.eax = ctx.ebx = ctx.ecx = ctx.edx = 0; break;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "fz <out> [trials] [first] [count] [only_va]\n");
        return 2;
    }
    FILE* out = std::fopen(argv[1], "w");
    int trials = argc > 2 ? std::atoi(argv[2]) : 4;
    size_t first = argc > 3 ? std::strtoul(argv[3], nullptr, 0) : 0;
    size_t count = argc > 4 ? std::strtoul(argv[4], nullptr, 0) : ~size_t(0);
    uint32_t only = argc > 5 ? uint32_t(std::strtoul(argv[5], nullptr, 16)) : 0;
    g_dump = std::getenv("FZ_DUMP") != nullptr;
#if defined(__aarch64__)
    // default NaN mode: every NaN result is the default NaN, so the operand order the compiler picks for a
    // commutative operation (unspecified in the generated C++) cannot show; everything else is compared exactly
    if (!std::getenv("FZ_NO_DN")) {
        uint64_t fpcr;
        __asm__ volatile("mrs %0, fpcr" : "=r"(fpcr));
        fpcr |= 1ull << 25;
        __asm__ volatile("msr fpcr, %0" ::"r"(fpcr));
    }
#endif
    int only_trial = std::getenv("FZ_TRIAL") ? std::atoi(std::getenv("FZ_TRIAL")) : -1;
    unsigned timeout_ms = std::getenv("FZ_TIMEOUT_MS") ? unsigned(std::atoi(std::getenv("FZ_TIMEOUT_MS"))) : 300;
    g_base = static_cast<uint8_t*>(mmap(nullptr, kSpan, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0));
    if (g_base == MAP_FAILED) {
        std::perror("mmap");
        return 1;
    }
    static uint8_t altstack[1 << 16];
    stack_t ss{};
    ss.ss_sp = altstack;
    ss.ss_size = sizeof(altstack);
    sigaltstack(&ss, nullptr);
    struct sigaction sa{};
    sa.sa_sigaction = OnSegv;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGALRM);  // a timeout never lands inside a page fill
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
    signal(SIGALRM, OnAlarm);
    size_t n = 0;
    while (fz_table[n].fn) n++;
    size_t stats[7] = {};
    BuildIcallTable();
    for (size_t i = first; i < n && i - first < count; i++) {
        if (only && fz_table[i].va != only) continue;
        for (int t = 0; t < trials; t++) {
            if (only_trial >= 0 && t != only_trial) continue;
            static X86Context ctx alignas(64);
            uint64_t s = Mix((uint64_t(fz_table[i].va) << 8) ^ uint64_t(t));
            g_seed = Mix(s ^ 0x5EED);
            InitCtx(ctx, s);
            g_trace = 0;
            g_calls = 0;
            g_tsc = 0;
            g_trap_va = 0;
            itimerval it{};
            it.it_value.tv_sec = timeout_ms / 1000;
            it.it_value.tv_usec = (timeout_ms % 1000) * 1000;
            volatile int outcome = sigsetjmp(g_jmp, 1);
            uint64_t thrown = 0;
            if (outcome == 0) {
                setitimer(ITIMER_REAL, &it, nullptr);
                try {
                    fz_table[i].fn(ctx, g_base);
                } catch (const X86Resume& r) {
                    outcome = kThrown;
                    thrown = (uint64_t(r.target) << 32) | r.esp;
                }
            }
            itimerval zero{};
            setitimer(ITIMER_REAL, &zero, nullptr);
            uint64_t d = 0;
            if (g_dump) DumpCtx("end", ctx);
            if (outcome != kTimeout && outcome != kMemLimit && outcome != kFault) {
                d = HashBytes(Mix(uint64_t(outcome)), &ctx, kCtxBytes);
                d = Mix(d ^ g_trace ^ thrown);
                d = Mix(d ^ MemDigest());
            }
            stats[outcome]++;
            std::fprintf(out, "%08X %d %d %016llx\n", fz_table[i].va, t, int(outcome), (unsigned long long)d);
            Reset();
        }
    }
    std::fclose(out);
    std::fprintf(stderr, "fz: return %zu trap %zu budget %zu timeout %zu memlimit %zu fault %zu thrown %zu\n", stats[0], stats[1],
                 stats[2], stats[3], stats[4], stats[5], stats[6]);
    return 0;
}

// step tracing for one-function bisection builds (mkstep.py)
void fz_step(uint32_t va, const X86Context& c, const X86Xmm* x) {
    std::fprintf(stderr, "step %08X eax %08X ecx %08X edx %08X ebx %08X esp %08X ebp %08X esi %08X edi %08X", va, c.eax, c.ecx,
                 c.edx, c.ebx, c.esp, c.ebp, c.esi, c.edi);
    for (int i = 0; i < 8; i++) std::fprintf(stderr, " %08X%08X%08X%08X", x[i].u[0], x[i].u[1], x[i].u[2], x[i].u[3]);
    std::fprintf(stderr, "\n");
}
