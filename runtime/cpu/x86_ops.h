#pragma once
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

#include "x86_context.h"

typedef uint16_t __attribute__((aligned(1), may_alias)) x86_u16u;
typedef uint32_t __attribute__((aligned(1), may_alias)) x86_u32u;
typedef uint64_t __attribute__((aligned(1), may_alias)) x86_u64u;
typedef float __attribute__((aligned(1), may_alias)) x86_f32u;
typedef double __attribute__((aligned(1), may_alias)) x86_f64u;

#define X86_MEM8(a) (*(uint8_t*)(base + (uint32_t)(a)))
#define X86_MEM16(a) (*(x86_u16u*)(base + (uint32_t)(a)))
#define X86_MEM32(a) (*(x86_u32u*)(base + (uint32_t)(a)))
#define X86_MEM64(a) (*(x86_u64u*)(base + (uint32_t)(a)))
#define X86_MEMF32(a) (*(x86_f32u*)(base + (uint32_t)(a)))
#define X86_MEMF64(a) (*(x86_f64u*)(base + (uint32_t)(a)))
#define X86_PTR(T, a) ((T*)(base + (uint32_t)(a)))

// The recompiled code is built on the player's PC into a DLL beside the executable (app/game_code.cpp). The executable
// exports the runtime and its overrides, which the DLL imports; a function with no override links to its body.
#ifdef X86_GAME_CODE
#define X86_HOST_API __declspec(dllimport)
#define X86_HOST_EXPORT
#define X86_WEAK_FUNC(name, impl) __pragma(comment(linker, "/alternatename:" #name "=" #impl))
// the DLL links without a C runtime: the two symbols clang expects from one
extern "C" __attribute__((used)) inline int _fltused = 0;
#pragma comment(linker, "/alternatename:??_7type_info@@6B@=_fltused")  // catch clauses only compare type names
#elif defined(_WIN32)
#define X86_HOST_API __declspec(dllexport)
#define X86_HOST_EXPORT __declspec(dllexport)
#else
// the headless harness links the generated code into its executable
#define X86_HOST_API
#define X86_HOST_EXPORT
#define X86_WEAK_FUNC(name, impl) \
    extern "C" __attribute__((weak, noinline)) void name(X86Context& __restrict ctx, uint8_t* base) { impl(ctx, base); }
// The name of a recompiled function, bound to its body; a host function of the same name replaces it everywhere (direct
// calls and the dispatch table). On ELF the name is a weak alias of the body, so a call reaches the body with no extra
// branch and the body exists once; elsewhere it is a weak function that calls the body.
#if defined(__ELF__)
#define X86_WEAK_ALIAS(name, impl) \
    extern "C" __attribute__((weak, alias(#impl))) void name(X86Context& __restrict ctx, uint8_t* base);
#else
#define X86_WEAK_ALIAS(name, impl) X86_WEAK_FUNC(name, impl)
#endif
#endif

#define X86_FUNC(name) extern "C" X86_HOST_EXPORT void name(X86Context& __restrict ctx, uint8_t* base)
#define X86_EXTERN_FUNC(name) extern "C" void name(X86Context& __restrict ctx, uint8_t* base)
// [xbe] trace: logs the caller and arguments on entry, eax on return
#define X86_TRACED_FUNC(name, impl, va)                                       \
    extern "C" void name##_traced(X86Context& __restrict ctx, uint8_t* base) { \
        uint32_t x86_ret = x86_trace(ctx, va, 0);                             \
        impl(ctx, base);                                                      \
        x86_trace(ctx, va, x86_ret);                                          \
    }                                                                         \
    X86_WEAK_FUNC(name, name##_traced)

#define X86_PUSH32(v)            \
    do {                         \
        uint32_t _v = (v);       \
        ctx.esp -= 4;            \
        X86_MEM32(ctx.esp) = _v; \
    } while (0)

// push in a function whose registers are locals (x86_esp)
#define X86_PUSHL(v)               \
    do {                           \
        uint32_t _v = (v);         \
        x86_esp -= 4;              \
        X86_MEM32(x86_esp) = _v;   \
    } while (0)

#define X86_SAVE_FLAGS() (ctx.cf = cf, ctx.zf = zf, ctx.sf = sf, ctx.of = of, ctx.pf = pf)
#define X86_LOAD_FLAGS() uint32_t cf = ctx.cf, zf = ctx.zf, sf = ctx.sf, of = ctx.of, pf = ctx.pf
#define X86_BARRIER() __asm__ volatile("" ::: "memory")
#define X86_PARITY(r) ((uint32_t)(__builtin_parity((uint32_t)(r)&0xFF) ^ 1))

#define X87_ST(i) ctx.st[(ctx.top + (i)) & 7]

// runtime services, implemented in cpu/dispatch.cpp
X86_HOST_API void x86_icall(X86Context& ctx, uint8_t* base, uint32_t target);
// The common indirect call inline: the dispatch table holds a host function per guest code byte, with the low bit set
// on C++ catch continuations; those, empty slots and targets outside the code go through x86_icall.
extern X86_HOST_API X86Func* const* x86_icall_table;
extern X86_HOST_API uint32_t x86_icall_lo, x86_icall_count;
inline void x86_icall_fast(X86Context& ctx, uint8_t* base, uint32_t target) {
    uint32_t i = target - x86_icall_lo;
    if (i < x86_icall_count) {
        uintptr_t f = reinterpret_cast<uintptr_t>(x86_icall_table[i]);
        if (f && !(f & 1)) {
            ctx.last_icall = target;
            reinterpret_cast<X86Func*>(f)(ctx, base);
            return;
        }
    }
    x86_icall(ctx, base, target);
}
// a jump to a C++ catch continuation unwinds the host stack to the frame that resumes there (esp as the CRT set it)
struct X86Resume {
    uint32_t target, esp;
};
X86_HOST_API void x86_resume(X86Context& ctx, uint8_t* base, const X86Resume& r);
X86_HOST_API void x86_kernel(X86Context& ctx, uint8_t* base, uint32_t ordinal);
[[noreturn]] X86_HOST_API void x86_trap(X86Context& ctx, uint32_t va, const char* what);
X86_HOST_API void x86_priv(X86Context& ctx, uint32_t va, const char* what);
// ret 0 on entry, returns the return address
X86_HOST_API uint32_t x86_trace(X86Context& ctx, uint32_t va, uint32_t ret);
X86_HOST_API uint64_t x86_rdtsc();
X86_HOST_API void x86_cpuid(X86Context& ctx);

inline void x87_push(X86Context& ctx, double v) {
    ctx.top = (ctx.top - 1) & 7;
    ctx.st[ctx.top] = v;
}
inline void x87_pop(X86Context& ctx) { ctx.top = (ctx.top + 1) & 7; }

// precision control: results round to 24 bits when the control word asks for it. The _cw forms take the control word
// from a function's local copy (x87_cw, see the recompiler's static x87 stack), the ctx forms read it from the context.
inline double x87_precw(uint16_t cw, double v) { return (cw & 0x300) ? v : double(float(v)); }
inline double x87_prec(X86Context& ctx, double v) { return x87_precw(ctx.fcw, v); }

// C0 bit 8, C2 bit 10, C3 bit 14
inline void x87_compare(X86Context& ctx, double a, double b) {
    uint16_t c;
    if (std::isnan(a) || std::isnan(b)) c = 0x4500;
    else if (a > b) c = 0;
    else if (a < b) c = 0x0100;
    else c = 0x4000;
    ctx.fsw = uint16_t((ctx.fsw & ~0x4500) | c);
}

// TOP lives in status word bits 11 to 13; x87_status_top takes TOP from a function whose stack is in locals
inline uint16_t x87_status_top(X86Context& ctx, uint32_t top) { return uint16_t((ctx.fsw & ~0x3800) | ((top & 7) << 11)); }
inline uint16_t x87_status(X86Context& ctx) { return x87_status_top(ctx, ctx.top); }

inline double x87_round_cw(uint16_t cw, double v) {
    switch ((cw >> 10) & 3) {  // control word RC field
        case 0: return std::nearbyint(v);
        case 1: return std::floor(v);
        case 2: return std::ceil(v);
        default: return std::trunc(v);
    }
}
inline double x87_round(X86Context& ctx, double v) { return x87_round_cw(ctx.fcw, v); }

// out of range gives the integer indefinite value, as the FPU does
inline int32_t x87_to_i32_cw(uint16_t cw, double v) {
    double r = x87_round_cw(cw, v);
    if (!(r >= -2147483648.0 && r <= 2147483647.0)) return INT32_MIN;
    return int32_t(r);
}
inline int16_t x87_to_i16_cw(uint16_t cw, double v) {
    double r = x87_round_cw(cw, v);
    if (!(r >= -32768.0 && r <= 32767.0)) return INT16_MIN;
    return int16_t(r);
}
inline int64_t x87_to_i64_cw(uint16_t cw, double v) {
    double r = x87_round_cw(cw, v);
    if (!(r >= -9223372036854775808.0 && r < 9223372036854775808.0)) return INT64_MIN;
    return int64_t(r);
}
inline int32_t x87_to_i32(X86Context& ctx, double v) { return x87_to_i32_cw(ctx.fcw, v); }
inline int16_t x87_to_i16(X86Context& ctx, double v) { return x87_to_i16_cw(ctx.fcw, v); }
inline int64_t x87_to_i64(X86Context& ctx, double v) { return x87_to_i64_cw(ctx.fcw, v); }

inline double x87_load80(const uint8_t* p) {
    uint64_t mant;
    uint16_t se;
    std::memcpy(&mant, p, 8);
    std::memcpy(&se, p + 8, 2);
    int sign = se >> 15;
    int exp = se & 0x7FFF;
    double v;
    if (exp == 0 && mant == 0) v = 0.0;
    else if (exp == 0x7FFF) v = (mant << 1) ? NAN : INFINITY;
    else v = std::ldexp(double(mant), exp - 16383 - 63);
    return sign ? -v : v;
}

inline void x87_store80(uint8_t* p, double v) {
    uint64_t mant = 0;
    uint16_t se = std::signbit(v) ? 0x8000 : 0;
    double a = std::fabs(v);
    if (std::isnan(v)) {
        se |= 0x7FFF;
        mant = 0xC000000000000000ull;
    } else if (std::isinf(v)) {
        se |= 0x7FFF;
        mant = 0x8000000000000000ull;
    } else if (a != 0.0) {
        int e;
        double m = std::frexp(a, &e);  // a = m * 2^e, m in [0.5,1)
        mant = uint64_t(std::ldexp(m, 64));
        se |= uint16_t(e - 1 + 16383);
    }
    std::memcpy(p, &mant, 8);
    std::memcpy(p + 8, &se, 2);
}

// FXAM class of v (st0) into C3 C2 C0, C1 = sign
inline uint32_t x87_examine_v(X86Context& ctx, double v) {
    uint16_t c;
    if (std::isnan(v)) c = 0x0100;
    else if (std::isinf(v)) c = 0x0500;
    else if (v == 0.0) c = 0x4000;
    else if (std::fpclassify(v) == FP_SUBNORMAL) c = 0x4400;
    else c = 0x0400;
    if (std::signbit(v)) c |= 0x0200;
    ctx.fsw = uint16_t((ctx.fsw & ~0x4700) | c);
    return 0;
}
inline uint32_t x87_examine(X86Context& ctx) { return x87_examine_v(ctx, X87_ST(0)); }

// SSE registers held in a function's locals (see the recompiler's PromoteRegs) are uint32 vectors; float lanes are bit
// casts, the 64 bit halves elements of a uint64 view. Packed arithmetic is written as clang vector operations: lane for
// lane the same IEEE operations as the scalar forms, as one vector instruction.
typedef float x86_v4f __attribute__((vector_size(16)));
typedef uint32_t x86_v4u __attribute__((vector_size(16)));
typedef uint64_t x86_v2q __attribute__((vector_size(16)));
inline float x86_f(uint32_t u) { return __builtin_bit_cast(float, u); }
inline uint32_t x86_u(float f) { return __builtin_bit_cast(uint32_t, f); }
inline uint64_t x86_q(x86_v4u v, int i) { return ((x86_v2q)v)[i]; }
inline x86_v4u x86_setq(x86_v4u v, int i, uint64_t q) {
    x86_v2q t = (x86_v2q)v;
    t[i] = q;
    return (x86_v4u)t;
}
inline x86_v4u x86_vu(const X86Xmm& x) {
    x86_v4u r;
    std::memcpy(&r, &x, 16);
    return r;
}
inline X86Xmm x86_xm(x86_v4u v) {
    X86Xmm r;
    std::memcpy(&r, &v, 16);
    return r;
}
inline x86_v4u x86_ld128(const uint8_t* p) {
    x86_v4u r;
    std::memcpy(&r, p, 16);
    return r;
}
inline void x86_st128(uint8_t* p, x86_v4u v) { std::memcpy(p, &v, 16); }
#define X86_LD128(a) x86_ld128(base + (uint32_t)(a))
#define X86_ST128(a, v) x86_st128(base + (uint32_t)(a), (v))
// add, sub and mul with their operands kept in the instruction's order: with two NaN operands the result is the first
// one's (x86: the destination; A64 FADD, FSUB, FMUL: Operand1), and a compiler may swap the operands of + and *.
// The asm is not volatile: unused results are removed and common ones shared (as src/game/hot_ordered.h).
#if defined(__aarch64__)
#define X86_ORDERED_PS(name, insn)                                                               \
    inline x86_v4u name(x86_v4u a, x86_v4u b) {                                                  \
        x86_v4f r;                                                                               \
        __asm__(insn " %0.4s, %1.4s, %2.4s" : "=w"(r) : "w"((x86_v4f)a), "w"((x86_v4f)b));       \
        return (x86_v4u)r;                                                                       \
    }
#define X86_ORDERED_SS(name, insn)                                     \
    inline float name(float a, float b) {                              \
        float r;                                                       \
        __asm__(insn " %s0, %s1, %s2" : "=w"(r) : "w"(a), "w"(b));     \
        return r;                                                      \
    }
X86_ORDERED_PS(x86_addps, "fadd")
X86_ORDERED_PS(x86_subps, "fsub")
X86_ORDERED_PS(x86_mulps, "fmul")
X86_ORDERED_SS(x86_addss, "fadd")
X86_ORDERED_SS(x86_subss, "fsub")
X86_ORDERED_SS(x86_mulss, "fmul")
#elif defined(__x86_64__) || defined(__i386__)
#define X86_ORDERED_PS(name, insn)                                  \
    inline x86_v4u name(x86_v4u a, x86_v4u b) {                     \
        x86_v4f r = (x86_v4f)a;                                     \
        __asm__(insn " %1, %0" : "+x"(r) : "x"((x86_v4f)b));        \
        return (x86_v4u)r;                                          \
    }
#define X86_ORDERED_SS(name, insn)                     \
    inline float name(float a, float b) {              \
        __asm__(insn " %1, %0" : "+x"(a) : "x"(b));    \
        return a;                                      \
    }
X86_ORDERED_PS(x86_addps, "addps")
X86_ORDERED_PS(x86_subps, "subps")
X86_ORDERED_PS(x86_mulps, "mulps")
X86_ORDERED_SS(x86_addss, "addss")
X86_ORDERED_SS(x86_subss, "subss")
X86_ORDERED_SS(x86_mulss, "mulss")
#else
inline x86_v4u x86_addps(x86_v4u a, x86_v4u b) { return (x86_v4u)((x86_v4f)a + (x86_v4f)b); }
inline x86_v4u x86_subps(x86_v4u a, x86_v4u b) { return (x86_v4u)((x86_v4f)a - (x86_v4f)b); }
inline x86_v4u x86_mulps(x86_v4u a, x86_v4u b) { return (x86_v4u)((x86_v4f)a * (x86_v4f)b); }
inline float x86_addss(float a, float b) { return a + b; }
inline float x86_subss(float a, float b) { return a - b; }
inline float x86_mulss(float a, float b) { return a * b; }
#endif
#undef X86_ORDERED_PS
#undef X86_ORDERED_SS

// MXCSR.FZ, flush to zero: the title sets it (sub_0002B480), and then an SSE arithmetic result that is denormal
// becomes a zero of its sign. Denormal operands are still used as they are (the Pentium III has no DAZ), so this
// cannot be FPCR.FZ (which also flushes inputs, and would reach the x87 emulation and host code). x86_fzmask(mxcsr)
// is 0x7FFFFFFF with FZ set and 0 without; x86_ftz clears the magnitude of the denormal lanes under it.
// The FTZ experiment was interrupted before validation. Keep the reviewed codegen
// behavior by default; opt in only for correctness/performance experiments.
inline uint32_t x86_fzmask(uint32_t mxcsr) {
#ifdef XBE_EXPERIMENTAL_SSE_FTZ
    return (mxcsr & 0x8000u) ? 0x7FFFFFFFu : 0u;
#else
    (void)mxcsr;
    return 0;
#endif
}
inline x86_v4u x86_ftz(x86_v4u r, uint32_t m) {
#ifndef XBE_EXPERIMENTAL_SSE_FTZ
    (void)m; return r;
#else
    x86_v4u tiny = (x86_v4u)((r & 0x7FFFFFFFu) < 0x00800000u);
    return r & ~(tiny & m);
#endif
}
inline float x86_ftzs(float f, uint32_t m) {
#ifndef XBE_EXPERIMENTAL_SSE_FTZ
    (void)m; return f;
#else
    uint32_t u = x86_u(f);
    return (u & 0x7FFFFFFFu) < 0x00800000u ? x86_f(u & ~m) : f;
#endif
}

// a where m is set, b elsewhere
inline x86_v4u x86_vsel(x86_v4u m, x86_v4u a, x86_v4u b) { return (m & a) | (~m & b); }
// minps/maxps: a < b ? a : b and a > b ? a : b per lane, as sse_min and sse_max
inline x86_v4u x86_minps(x86_v4u a, x86_v4u b) { return x86_vsel((x86_v4u)((x86_v4f)a < (x86_v4f)b), a, b); }
inline x86_v4u x86_maxps(x86_v4u a, x86_v4u b) { return x86_vsel((x86_v4u)((x86_v4f)a > (x86_v4f)b), a, b); }
// cmpps: all ones where the predicate holds, as sse_cmp
inline x86_v4u x86_cmpps(x86_v4u x, x86_v4u y, int pred) {
    x86_v4f a = (x86_v4f)x, b = (x86_v4f)y;
    switch (pred & 7) {
        case 0: return (x86_v4u)(a == b);
        case 1: return (x86_v4u)(a < b);
        case 2: return (x86_v4u)(a <= b);
        case 3: return (x86_v4u)(a != a) | (x86_v4u)(b != b);
        case 4: return ~(x86_v4u)(a == b);
        case 5: return ~(x86_v4u)(a < b);
        case 6: return ~(x86_v4u)(a <= b);
        default: return ~((x86_v4u)(a != a) | (x86_v4u)(b != b));
    }
}

inline float sse_min(float a, float b) { return a < b ? a : b; }
inline float sse_max(float a, float b) { return a > b ? a : b; }

inline uint32_t sse_cmp(float a, float b, int pred) {
    bool r;
    switch (pred & 7) {
        case 0: r = a == b; break;
        case 1: r = a < b; break;
        case 2: r = a <= b; break;
        case 3: r = std::isnan(a) || std::isnan(b); break;
        case 4: r = !(a == b); break;
        case 5: r = !(a < b); break;
        case 6: r = !(a <= b); break;
        default: r = !(std::isnan(a) || std::isnan(b)); break;
    }
    return r ? 0xFFFFFFFFu : 0u;
}

inline int32_t sse_cvt(float v) {
    float r = std::nearbyint(v);
    if (!(r >= -2147483648.0f && r < 2147483648.0f)) return INT32_MIN;
    return int32_t(r);
}
inline int32_t sse_cvtt(float v) {
    if (!(v >= -2147483648.0f && v < 2147483648.0f)) return INT32_MIN;
    return int32_t(v);
}

template <typename T>
constexpr T sat(int64_t v) {
    constexpr int64_t lo = std::numeric_limits<T>::min(), hi = std::numeric_limits<T>::max();
    return T(v < lo ? lo : v > hi ? hi : v);
}
static_assert(sat<int16_t>(-300) == -300 && sat<int16_t>(40000) == 32767 && sat<int8_t>(-5) == -5);

// lane wise helpers on 64 bit MMX values
template <typename T, typename F>
inline uint64_t mmx_map2(uint64_t a, uint64_t b, F f) {
    constexpr int n = 8 / sizeof(T);
    T x[n], y[n], r[n];
    std::memcpy(x, &a, 8);
    std::memcpy(y, &b, 8);
    for (int i = 0; i < n; i++) r[i] = T(f(x[i], y[i]));
    uint64_t out;
    std::memcpy(&out, r, 8);
    return out;
}

// rep movs: element by element semantics, fast path when the ranges cannot interfere
inline void x86_rep_movs(X86Context& ctx, uint8_t* base, uint32_t w) {
    uint32_t n = ctx.ecx;
    if (!n) return;
    uint32_t bytes = n * w;
    if (!ctx.df && (ctx.edi - ctx.esi >= bytes || ctx.edi <= ctx.esi)) {
        std::memmove(base + ctx.edi, base + ctx.esi, bytes);
        ctx.esi += bytes;
        ctx.edi += bytes;
        ctx.ecx = 0;
        return;
    }
    int32_t d = ctx.df ? -int32_t(w) : int32_t(w);
    for (; n; n--) {
        std::memcpy(base + ctx.edi, base + ctx.esi, w);
        ctx.esi += d;
        ctx.edi += d;
    }
    ctx.ecx = 0;
}

inline void x86_rep_stos(X86Context& ctx, uint8_t* base, uint32_t w) {
    uint32_t n = ctx.ecx;
    if (!n) return;
    if (!ctx.df && w == 1) {
        std::memset(base + ctx.edi, uint8_t(ctx.eax), n);
        ctx.edi += n;
        ctx.ecx = 0;
        return;
    }
    int32_t d = ctx.df ? -int32_t(w) : int32_t(w);
    uint32_t v = ctx.eax;
    for (; n; n--) {
        std::memcpy(base + ctx.edi, &v, w);
        ctx.edi += d;
    }
    ctx.ecx = 0;
}
