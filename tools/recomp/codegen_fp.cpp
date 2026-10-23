#include <cstdarg>
#include <cstdio>

#include "codegen.h"

static std::string F(const char* f, ...) __attribute__((format(printf, 1, 2)));
static std::string F(const char* f, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, f);
    std::vsnprintf(buf, sizeof(buf), f, ap);
    va_end(ap);
    return buf;
}

static int StIndex(const ZydisDecodedOperand& o) {
    if (o.type == ZYDIS_OPERAND_TYPE_REGISTER && o.reg.value >= ZYDIS_REGISTER_ST0 && o.reg.value <= ZYDIS_REGISTER_ST7)
        return int(o.reg.value - ZYDIS_REGISTER_ST0);
    return -1;
}

static int XmmIndex(const ZydisDecodedOperand& o) {
    if (o.type == ZYDIS_OPERAND_TYPE_REGISTER && o.reg.value >= ZYDIS_REGISTER_XMM0 && o.reg.value <= ZYDIS_REGISTER_XMM7)
        return int(o.reg.value - ZYDIS_REGISTER_XMM0);
    return -1;
}

static int MmIndex(const ZydisDecodedOperand& o) {
    if (o.type == ZYDIS_OPERAND_TYPE_REGISTER && o.reg.value >= ZYDIS_REGISTER_MM0 && o.reg.value <= ZYDIS_REGISTER_MM7)
        return int(o.reg.value - ZYDIS_REGISTER_MM0);
    return -1;
}

// With the static x87 stack (x87_static_, codegen_x87.cpp) st(i) is a local slot known from the depth, a push or pop
// only moves the depth, and the control word is the local x87_cw; otherwise the stack is ctx.st at ctx.top.
bool CodeGen::EmitX87(uint32_t va, const ZydisDecodedInstruction& in, const ZydisDecodedOperand* ops) {
    if (!ZydisMnemonicGetString(in.mnemonic) || ZydisMnemonicGetString(in.mnemonic)[0] != 'f') return false;
    auto m = in.mnemonic;
    int vis = in.operand_count_visible;
    int mi = -1;
    for (int i = 0; i < vis; i++)
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY) mi = i;
    std::string open = mi >= 0 ? "\t{ uint32_t ea = " + AddrExpr(ops[mi]) + "; " : "\t{ ";
    auto emit = [&](const std::string& s) { Line(open + s + " }"); };
    // value of a floating memory operand
    auto fmem = [&](const ZydisDecodedOperand& o) -> std::string {
        if (o.size == 32) return "(double)X86_MEMF32(ea)";
        if (o.size == 64) return "X86_MEMF64(ea)";
        return "x87_load80(X86_PTR(uint8_t, ea))";
    };
    auto imem = [&](const ZydisDecodedOperand& o) -> std::string {
        if (o.size == 16) return "(double)(int16_t)X86_MEM16(ea)";
        if (o.size == 64) return "(double)(int64_t)X86_MEM64(ea)";
        return "(double)(int32_t)X86_MEM32(ea)";
    };
    const bool sx = x87_static_;
    int& xd = x87_depth_;  // depth as the instruction pushes and pops (static stack); X87Check compares it to the plan
    // st(i) at the current depth; push and pop move it, so a name is taken before the push or pop it precedes
    auto st = [&](int i) { return sx ? F("x87_f%d", ((i - xd) % 8 + 8) % 8) : F("X87_ST(%d)", i); };
    auto push = [&](const std::string& v) -> std::string {
        if (!sx) return "x87_push(ctx, " + v + ");";
        xd++;
        return st(0) + " = " + v + ";";
    };
    auto pop = [&]() -> std::string {
        if (!sx) return " x87_pop(ctx);";
        xd--;
        return "";
    };
    const char* prec = sx ? "x87_precw(x87_cw, " : "x87_prec(ctx, ";
    const char* cw = sx ? "x87_cw" : "ctx.fcw";
    auto top = [&]() { return sx ? F("(x87_T + %du) & 7", ((-xd) % 8 + 8) % 8) : std::string("ctx.top"); };
    auto status = [&]() { return sx ? "x87_status_top(ctx, " + top() + ")" : std::string("x87_status(ctx)"); };

    struct Arith {
        ZydisMnemonic m;
        const char* op;
        bool rev, pop, integer;
    };
    static const Arith arith[] = {
        {ZYDIS_MNEMONIC_FADD, "+", false, false, false},   {ZYDIS_MNEMONIC_FADDP, "+", false, true, false},
        {ZYDIS_MNEMONIC_FIADD, "+", false, false, true},   {ZYDIS_MNEMONIC_FSUB, "-", false, false, false},
        {ZYDIS_MNEMONIC_FSUBP, "-", false, true, false},   {ZYDIS_MNEMONIC_FISUB, "-", false, false, true},
        {ZYDIS_MNEMONIC_FSUBR, "-", true, false, false},   {ZYDIS_MNEMONIC_FSUBRP, "-", true, true, false},
        {ZYDIS_MNEMONIC_FISUBR, "-", true, false, true},   {ZYDIS_MNEMONIC_FMUL, "*", false, false, false},
        {ZYDIS_MNEMONIC_FMULP, "*", false, true, false},   {ZYDIS_MNEMONIC_FIMUL, "*", false, false, true},
        {ZYDIS_MNEMONIC_FDIV, "/", false, false, false},   {ZYDIS_MNEMONIC_FDIVP, "/", false, true, false},
        {ZYDIS_MNEMONIC_FIDIV, "/", false, false, true},   {ZYDIS_MNEMONIC_FDIVR, "/", true, false, false},
        {ZYDIS_MNEMONIC_FDIVRP, "/", true, true, false},   {ZYDIS_MNEMONIC_FIDIVR, "/", true, false, true},
    };
    for (auto& a : arith) {
        if (a.m != m) continue;
        std::string dst, src;
        if (mi >= 0) {
            dst = st(0);
            src = a.integer ? imem(ops[mi]) : fmem(ops[mi]);
        } else if (vis >= 2) {
            dst = st(StIndex(ops[0]));
            src = st(StIndex(ops[1]));
        } else {
            dst = st(1);
            src = st(0);
        }
        std::string expr = a.rev ? "(s " + std::string(a.op) + " d)" : "(d " + std::string(a.op) + " s)";
        std::string p = a.pop ? pop() : "";
        emit(F("double s = %s; double d = %s; %s = %s%s);%s", src.c_str(), dst.c_str(), dst.c_str(), prec, expr.c_str(), p.c_str()));
        return true;
    }

    switch (m) {
        case ZYDIS_MNEMONIC_FLD:
            if (mi >= 0) emit(push(fmem(ops[mi])));
            else {
                std::string v = st(StIndex(ops[0]));
                emit(sx ? push(v) : F("double v = %s; x87_push(ctx, v);", v.c_str()));
            }
            return true;
        case ZYDIS_MNEMONIC_FILD:
            emit(push(imem(ops[mi])));
            return true;
        case ZYDIS_MNEMONIC_FST:
        case ZYDIS_MNEMONIC_FSTP: {
            std::string s0 = st(0);
            if (mi >= 0) {
                auto& o = ops[mi];
                std::string pop_ = m == ZYDIS_MNEMONIC_FSTP ? pop() : "";
                if (o.size == 32) emit(F("X86_MEMF32(ea) = (float)%s;%s", s0.c_str(), pop_.c_str()));
                else if (o.size == 64) emit(F("X86_MEMF64(ea) = %s;%s", s0.c_str(), pop_.c_str()));
                else emit(F("x87_store80(X86_PTR(uint8_t, ea), %s);%s", s0.c_str(), pop_.c_str()));
            } else {
                std::string si = st(StIndex(ops[0]));
                std::string pop_ = m == ZYDIS_MNEMONIC_FSTP ? pop() : "";
                emit(F("%s = %s;%s", si.c_str(), s0.c_str(), pop_.c_str()));
            }
            return true;
        }
        case ZYDIS_MNEMONIC_FIST:
        case ZYDIS_MNEMONIC_FISTP:
        case ZYDIS_MNEMONIC_FISTTP: {
            auto& o = ops[mi];
            std::string s0 = st(0);
            std::string pop_ = m != ZYDIS_MNEMONIC_FIST ? pop() : "";
            std::string v = m == ZYDIS_MNEMONIC_FISTTP ? "std::trunc(" + s0 + ")" : s0;
            const char* bits = o.size == 16 ? "16" : o.size == 64 ? "64" : "32";
            std::string store = F("X86_MEM%s(ea) = (uint%s_t)", bits, bits);
            if (sx) {
                // fcw 0xC00 sets rounding to truncate for the store
                std::string c = m == ZYDIS_MNEMONIC_FISTTP ? "x87_cw | 0xC00" : "x87_cw";
                emit(F("%sx87_to_i%s_cw(%s, %s);", store.c_str(), bits, c.c_str(), v.c_str()) + pop_);
            } else {
                std::string pre = m == ZYDIS_MNEMONIC_FISTTP ? "uint16_t cw = ctx.fcw; ctx.fcw |= 0xC00; " : "";
                std::string post = m == ZYDIS_MNEMONIC_FISTTP ? " ctx.fcw = cw;" : "";
                emit(pre + F("%sx87_to_i%s(ctx, %s);", store.c_str(), bits, v.c_str()) + post + pop_);
            }
            return true;
        }
        case ZYDIS_MNEMONIC_FXCH: {
            int i = vis ? StIndex(ops[0]) : 1;
            std::string s0 = st(0), si = st(i);
            emit(F("double t = %s; %s = %s; %s = t;", s0.c_str(), s0.c_str(), si.c_str(), si.c_str()));
            return true;
        }
        case ZYDIS_MNEMONIC_FCOM:
        case ZYDIS_MNEMONIC_FCOMP:
        case ZYDIS_MNEMONIC_FUCOM:
        case ZYDIS_MNEMONIC_FUCOMP:
        case ZYDIS_MNEMONIC_FICOM:
        case ZYDIS_MNEMONIC_FICOMP: {
            bool p = m == ZYDIS_MNEMONIC_FCOMP || m == ZYDIS_MNEMONIC_FUCOMP || m == ZYDIS_MNEMONIC_FICOMP;
            bool integer = m == ZYDIS_MNEMONIC_FICOM || m == ZYDIS_MNEMONIC_FICOMP;
            std::string src = mi >= 0 ? (integer ? imem(ops[mi]) : fmem(ops[mi])) : vis ? st(StIndex(ops[0])) : st(1);
            std::string s0 = st(0);
            std::string pop_ = p ? pop() : "";
            emit(F("x87_compare(ctx, %s, %s);%s", s0.c_str(), src.c_str(), pop_.c_str()));
            return true;
        }
        case ZYDIS_MNEMONIC_FCOMPP:
        case ZYDIS_MNEMONIC_FUCOMPP: {
            std::string s0 = st(0), s1 = st(1);
            std::string p1 = pop(), p2 = pop();
            emit(F("x87_compare(ctx, %s, %s);%s%s", s0.c_str(), s1.c_str(), p1.c_str(), p2.c_str()));
            return true;
        }
        case ZYDIS_MNEMONIC_FCOMI:
        case ZYDIS_MNEMONIC_FCOMIP:
        case ZYDIS_MNEMONIC_FUCOMI:
        case ZYDIS_MNEMONIC_FUCOMIP: {
            bool p = m == ZYDIS_MNEMONIC_FCOMIP || m == ZYDIS_MNEMONIC_FUCOMIP;
            std::string s0 = st(0), si = st(StIndex(ops[1]));
            std::string pop_ = p ? pop() : "";
            emit(F("double a = %s, b = %s; bool u = a != a || b != b; zf = u || a == b; pf = u; cf = u || a < b; of = 0; sf = 0;%s",
                   s0.c_str(), si.c_str(), pop_.c_str()));
            return true;
        }
        case ZYDIS_MNEMONIC_FTST:
            emit("x87_compare(ctx, " + st(0) + ", 0.0);");
            return true;
        case ZYDIS_MNEMONIC_FXAM:
            emit(sx ? "x87_examine_v(ctx, " + st(0) + ");" : std::string("x87_examine(ctx);"));
            return true;
        case ZYDIS_MNEMONIC_FCHS: emit(F("%s = -%s;", st(0).c_str(), st(0).c_str())); return true;
        case ZYDIS_MNEMONIC_FABS: emit(F("%s = std::fabs(%s);", st(0).c_str(), st(0).c_str())); return true;
        case ZYDIS_MNEMONIC_FSQRT: emit(F("%s = %sstd::sqrt(%s));", st(0).c_str(), prec, st(0).c_str())); return true;
        // clearing C2 (0x400) reports the argument in range
        case ZYDIS_MNEMONIC_FSIN: emit(F("%s = std::sin(%s); ctx.fsw &= ~0x400;", st(0).c_str(), st(0).c_str())); return true;
        case ZYDIS_MNEMONIC_FCOS: emit(F("%s = std::cos(%s); ctx.fsw &= ~0x400;", st(0).c_str(), st(0).c_str())); return true;
        case ZYDIS_MNEMONIC_FSINCOS: {
            std::string s0 = st(0);
            std::string p = push("std::cos(v)");
            emit(F("double v = %s; %s = std::sin(v); %s ctx.fsw &= ~0x400;", s0.c_str(), s0.c_str(), p.c_str()));
            return true;
        }
        case ZYDIS_MNEMONIC_FPTAN: {
            std::string s0 = st(0);
            std::string p = push("1.0");
            emit(F("%s = std::tan(%s); %s ctx.fsw &= ~0x400;", s0.c_str(), s0.c_str(), p.c_str()));
            return true;
        }
        case ZYDIS_MNEMONIC_FPATAN:
        case ZYDIS_MNEMONIC_FYL2X:
        case ZYDIS_MNEMONIC_FYL2XP1: {
            std::string s0 = st(0), s1 = st(1);
            std::string e = m == ZYDIS_MNEMONIC_FPATAN ? F("std::atan2(%s, %s)", s1.c_str(), s0.c_str())
                          : m == ZYDIS_MNEMONIC_FYL2X ? F("%s * std::log2(%s)", s1.c_str(), s0.c_str())
                                                      : F("%s * std::log2(%s + 1.0)", s1.c_str(), s0.c_str());
            std::string p = pop();
            emit(F("double v = %s;%s %s = v;", e.c_str(), p.c_str(), st(0).c_str()));
            return true;
        }
        case ZYDIS_MNEMONIC_F2XM1: emit(F("%s = std::exp2(%s) - 1.0;", st(0).c_str(), st(0).c_str())); return true;
        case ZYDIS_MNEMONIC_FSCALE:
            emit(F("%s = std::ldexp(%s, (int)std::trunc(%s));", st(0).c_str(), st(0).c_str(), st(1).c_str()));
            return true;
        case ZYDIS_MNEMONIC_FRNDINT:
            emit(sx ? F("%s = x87_round_cw(x87_cw, %s);", st(0).c_str(), st(0).c_str())
                    : F("%s = x87_round(ctx, %s);", st(0).c_str(), st(0).c_str()));
            return true;
        case ZYDIS_MNEMONIC_FPREM:
            emit(F("%s = std::fmod(%s, %s); ctx.fsw &= ~0x400;", st(0).c_str(), st(0).c_str(), st(1).c_str()));
            return true;
        case ZYDIS_MNEMONIC_FPREM1:
            emit(F("%s = std::remainder(%s, %s); ctx.fsw &= ~0x400;", st(0).c_str(), st(0).c_str(), st(1).c_str()));
            return true;
        case ZYDIS_MNEMONIC_FXTRACT: {
            std::string s0 = st(0);
            std::string p = push("mnt * 2.0");
            emit(F("int e; double v = %s; double mnt = std::frexp(v, &e); %s = (double)(e - 1); %s", s0.c_str(), s0.c_str(), p.c_str()));
            return true;
        }
        case ZYDIS_MNEMONIC_FLD1: emit(push("1.0")); return true;
        case ZYDIS_MNEMONIC_FLDZ: emit(push("0.0")); return true;
        case ZYDIS_MNEMONIC_FLDPI: emit(push("3.14159265358979323846")); return true;
        case ZYDIS_MNEMONIC_FLDL2E: emit(push("1.44269504088896340736")); return true;
        case ZYDIS_MNEMONIC_FLDL2T: emit(push("3.32192809488736234787")); return true;
        case ZYDIS_MNEMONIC_FLDLN2: emit(push("0.693147180559945309417")); return true;
        case ZYDIS_MNEMONIC_FLDLG2: emit(push("0.301029995663981195214")); return true;
        case ZYDIS_MNEMONIC_FLDCW: emit(F("%s = X86_MEM16(ea);", cw)); return true;
        case ZYDIS_MNEMONIC_FNSTCW: emit(F("X86_MEM16(ea) = %s;", cw)); return true;
        case ZYDIS_MNEMONIC_FNSTSW:
            if (mi >= 0) emit("X86_MEM16(ea) = " + status() + ";");
            else emit("ctx.eax = (ctx.eax & 0xFFFF0000u) | " + status() + ";");
            return true;
        case ZYDIS_MNEMONIC_FNCLEX: emit("ctx.fsw &= 0x7F00;"); return true;  // keeps condition codes and TOP
        case ZYDIS_MNEMONIC_FFREE: return true;
        case ZYDIS_MNEMONIC_FINCSTP:
            if (sx) pop();
            else emit("ctx.top = (ctx.top + 1) & 7;");
            return true;
        case ZYDIS_MNEMONIC_FDECSTP:
            if (sx) xd++;
            else emit("ctx.top = (ctx.top - 1) & 7;");
            return true;
        case ZYDIS_MNEMONIC_FCMOVB: case ZYDIS_MNEMONIC_FCMOVBE: case ZYDIS_MNEMONIC_FCMOVE: case ZYDIS_MNEMONIC_FCMOVNB:
        case ZYDIS_MNEMONIC_FCMOVNBE: case ZYDIS_MNEMONIC_FCMOVNE: case ZYDIS_MNEMONIC_FCMOVNU: case ZYDIS_MNEMONIC_FCMOVU: {
            bool saved = pending_.valid;
            pending_.valid = false;
            std::string c = Cond(m);
            pending_.valid = saved;
            emit(F("if (%s) %s = %s;", c.c_str(), st(0).c_str(), st(StIndex(ops[1])).c_str()));
            return true;
        }
        case ZYDIS_MNEMONIC_FNSTENV:
        case ZYDIS_MNEMONIC_FNSAVE:
            emit(F("X86_MEM32(ea) = %s; X86_MEM32(ea + 4) = %s; X86_MEM32(ea + 8) = 0xFFFF;", cw, status().c_str()));
            return true;
        // these set TOP: with the static stack the locals go to ctx first and come back after (the plan's rebase)
        case ZYDIS_MNEMONIC_FNINIT:  // 0x37F is the power on control word
        case ZYDIS_MNEMONIC_FLDENV:
        case ZYDIS_MNEMONIC_FRSTOR: {
            std::string op = m == ZYDIS_MNEMONIC_FNINIT ? "ctx.fcw = 0x37F; ctx.fsw = 0; ctx.top = 0;"
                : "ctx.fcw = (uint16_t)X86_MEM32(ea); ctx.fsw = (uint16_t)X86_MEM32(ea + 4); ctx.top = (ctx.fsw >> 11) & 7;";
            if (sx) {
                auto it = x87_.find(va);
                op = X87Out() + op + " " + X87In(it->second.out);
                xd = it->second.out;
            }
            emit(op);
            return true;
        }
        default:
            return false;
    }
}

// SSE registers are vector locals of the function (x86_v4u x86_xmmN, see PromoteRegs): lanes are read and written as
// uint32 elements, float lanes through x86_f/x86_u bit casts, the 64 bit halves through x86_q/x86_setq. Packed
// arithmetic is one vector operation, lane for lane the same IEEE operation with the operands in the same order.
bool CodeGen::EmitSse(uint32_t va, const ZydisDecodedInstruction& in, const ZydisDecodedOperand* ops) {
    auto m = in.mnemonic;
    int mi = -1;
    for (int i = 0; i < in.operand_count_visible; i++)
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY) mi = i;
    std::string open = mi >= 0 ? "\t{ uint32_t ea = " + AddrExpr(ops[mi]) + "; " : "\t{ ";
    auto emit = [&](const std::string& s) { Line(open + s + " }"); };
    int d = XmmIndex(ops[0]);
    int s = in.operand_count_visible > 1 ? XmmIndex(ops[1]) : -1;
    auto X = [](int i) { return F("x86_xmm%d", i); };
    std::string D = d >= 0 ? X(d) : "";
    // 128 bit source as an x86_v4u expression
    auto src128 = [&]() -> std::string { return s >= 0 ? X(s) : std::string("X86_LD128(ea)"); };
    auto srcf0 = [&]() -> std::string { return s >= 0 ? F("x86_f(%s[0])", X(s).c_str()) : std::string("X86_MEMF32(ea)"); };
    struct Bin {
        ZydisMnemonic ps, ss;
        const char* expr;
    };
    static const Bin bins[] = {
        {ZYDIS_MNEMONIC_ADDPS, ZYDIS_MNEMONIC_ADDSS, "x86_addss(a, b)"},
        {ZYDIS_MNEMONIC_SUBPS, ZYDIS_MNEMONIC_SUBSS, "x86_subss(a, b)"},
        {ZYDIS_MNEMONIC_MULPS, ZYDIS_MNEMONIC_MULSS, "x86_mulss(a, b)"},
        {ZYDIS_MNEMONIC_DIVPS, ZYDIS_MNEMONIC_DIVSS, "a / b"},
        {ZYDIS_MNEMONIC_MINPS, ZYDIS_MNEMONIC_MINSS, "sse_min(a, b)"},
        {ZYDIS_MNEMONIC_MAXPS, ZYDIS_MNEMONIC_MAXSS, "sse_max(a, b)"},
        {ZYDIS_MNEMONIC_SQRTPS, ZYDIS_MNEMONIC_SQRTSS, "std::sqrt(b)"},
        {ZYDIS_MNEMONIC_RCPPS, ZYDIS_MNEMONIC_RCPSS, "1.0f / b"},
        {ZYDIS_MNEMONIC_RSQRTPS, ZYDIS_MNEMONIC_RSQRTSS, "1.0f / std::sqrt(b)"},
    };
    for (auto& b : bins) {
        if (m == b.ps) {
            // add, sub and mul keep the operand order (the NaN a lane ends with), divide cannot be reordered
            const char* fn = m == ZYDIS_MNEMONIC_ADDPS ? "x86_addps" : m == ZYDIS_MNEMONIC_SUBPS ? "x86_subps"
                           : m == ZYDIS_MNEMONIC_MULPS ? "x86_mulps" : nullptr;
            // results that are denormal flush to zero under MXCSR.FZ (x86_fz, the thread's mask)
            if (fn)
                emit(F("x86_v4u v = %s; %s = x86_ftz(%s(%s, v), x86_fz);", src128().c_str(), D.c_str(), fn, D.c_str()));
            else if (m == ZYDIS_MNEMONIC_DIVPS)
                emit(F("x86_v4u v = %s; %s = x86_ftz((x86_v4u)((x86_v4f)%s / (x86_v4f)v), x86_fz);", src128().c_str(), D.c_str(), D.c_str()));
            else if (m == ZYDIS_MNEMONIC_RCPPS)  // the approximation flushes tiny results whatever FZ says
                emit(F("x86_v4u v = %s; for (int i = 0; i < 4; i++) %s[i] = x86_u(x86_ftzs(1.0f / x86_f(v[i]), 0x7FFFFFFFu));", src128().c_str(), D.c_str()));
            else if (m == ZYDIS_MNEMONIC_MINPS || m == ZYDIS_MNEMONIC_MAXPS)
                emit(F("x86_v4u v = %s; %s = x86_%s(%s, v);", src128().c_str(), D.c_str(), m == ZYDIS_MNEMONIC_MINPS ? "minps" : "maxps",
                       D.c_str()));
            else
                emit(F("x86_v4u v = %s; for (int i = 0; i < 4; i++) { float a = x86_f(%s[i]), b = x86_f(v[i]); (void)a; %s[i] = x86_u(%s); }",
                       src128().c_str(), D.c_str(), D.c_str(), b.expr));
            return true;
        }
        if (m == b.ss) {
            // add, sub, mul and div flush a denormal result under MXCSR.FZ; rcpss flushes it always; min, max, sqrt and
            // rsqrt cannot make one from these operands (min and max return an operand as it is)
            bool arith = m == ZYDIS_MNEMONIC_ADDSS || m == ZYDIS_MNEMONIC_SUBSS || m == ZYDIS_MNEMONIC_MULSS || m == ZYDIS_MNEMONIC_DIVSS;
            std::string e = arith ? F("x86_ftzs(%s, x86_fz)", b.expr) : m == ZYDIS_MNEMONIC_RCPSS ? F("x86_ftzs(%s, 0x7FFFFFFFu)", b.expr) : b.expr;
            emit(F("float a = x86_f(%s[0]), b = %s; (void)a; %s[0] = x86_u(%s);", D.c_str(), srcf0().c_str(), D.c_str(), e.c_str()));
            return true;
        }
    }
    switch (m) {
        case ZYDIS_MNEMONIC_MOVAPS:
        case ZYDIS_MNEMONIC_MOVUPS:
        case ZYDIS_MNEMONIC_MOVNTPS:
        case ZYDIS_MNEMONIC_MOVAPD:
        case ZYDIS_MNEMONIC_MOVUPD:
        case ZYDIS_MNEMONIC_MOVDQA:
        case ZYDIS_MNEMONIC_MOVDQU:
            if (d >= 0) emit(F("%s = %s;", D.c_str(), src128().c_str()));
            else emit(F("X86_ST128(ea, %s);", X(s).c_str()));
            return true;
        case ZYDIS_MNEMONIC_MOVSS:
            if (d >= 0 && s >= 0) emit(F("%s[0] = %s[0];", D.c_str(), X(s).c_str()));
            else if (d >= 0) emit(F("%s = (x86_v4u){X86_MEM32(ea), 0u, 0u, 0u};", D.c_str()));
            else emit(F("X86_MEM32(ea) = %s[0];", X(s).c_str()));
            return true;
        case ZYDIS_MNEMONIC_MOVLPS:
            if (d >= 0) emit(F("%s = x86_setq(%s, 0, X86_MEM64(ea));", D.c_str(), D.c_str()));
            else emit(F("X86_MEM64(ea) = x86_q(%s, 0);", X(s).c_str()));
            return true;
        case ZYDIS_MNEMONIC_MOVHPS:
            if (d >= 0) emit(F("%s = x86_setq(%s, 1, X86_MEM64(ea));", D.c_str(), D.c_str()));
            else emit(F("X86_MEM64(ea) = x86_q(%s, 1);", X(s).c_str()));
            return true;
        case ZYDIS_MNEMONIC_MOVLHPS: emit(F("%s = x86_setq(%s, 1, x86_q(%s, 0));", D.c_str(), D.c_str(), X(s).c_str())); return true;
        case ZYDIS_MNEMONIC_MOVHLPS: emit(F("%s = x86_setq(%s, 0, x86_q(%s, 1));", D.c_str(), D.c_str(), X(s).c_str())); return true;
        case ZYDIS_MNEMONIC_ANDPS:
        case ZYDIS_MNEMONIC_ANDNPS:
        case ZYDIS_MNEMONIC_ORPS:
        case ZYDIS_MNEMONIC_XORPS: {
            const char* e = m == ZYDIS_MNEMONIC_ANDPS ? "a & b" : m == ZYDIS_MNEMONIC_ANDNPS ? "~a & b" : m == ZYDIS_MNEMONIC_ORPS ? "a | b" : "a ^ b";
            emit(F("x86_v4u a = %s, b = %s; %s = %s;", D.c_str(), src128().c_str(), D.c_str(), e));
            return true;
        }
        case ZYDIS_MNEMONIC_CMPPS:
            emit(F("x86_v4u v = %s; %s = x86_cmpps(%s, v, %d);", src128().c_str(), D.c_str(), D.c_str(), int(ops[2].imm.value.u)));
            return true;
        case ZYDIS_MNEMONIC_CMPSS:
            emit(F("%s[0] = sse_cmp(x86_f(%s[0]), %s, %d);", D.c_str(), D.c_str(), srcf0().c_str(), int(ops[2].imm.value.u)));
            return true;
        case ZYDIS_MNEMONIC_COMISS:
        case ZYDIS_MNEMONIC_UCOMISS:
            emit(F("float a = x86_f(%s[0]), b = %s; fa = a; fb = b; bool u = a != a || b != b; zf = u || a == b; pf = u; cf = u || a < b; of = 0; sf = 0;",
                   D.c_str(), srcf0().c_str()));
            pending_ = {true, false, 32, true};
            return true;
        case ZYDIS_MNEMONIC_CVTSI2SS:
            emit(F("%s[0] = x86_u((float)(int32_t)%s);", D.c_str(), Read(ops[1], "ea").c_str()));
            return true;
        case ZYDIS_MNEMONIC_CVTSS2SI:
            emit(RegWrite(ops[0].reg.value, F("(uint32_t)sse_cvt(%s)", srcf0().c_str())));
            return true;
        case ZYDIS_MNEMONIC_CVTTSS2SI:
            emit(RegWrite(ops[0].reg.value, F("(uint32_t)sse_cvtt(%s)", srcf0().c_str())));
            return true;
        case ZYDIS_MNEMONIC_CVTPI2PS: {
            std::string src = MmIndex(ops[1]) >= 0 ? F("ctx.mm[%d]", MmIndex(ops[1])) : "X86_MEM64(ea)";
            emit(F("uint64_t v = %s; %s[0] = x86_u((float)(int32_t)(uint32_t)v); %s[1] = x86_u((float)(int32_t)(uint32_t)(v >> 32));",
                   src.c_str(), D.c_str(), D.c_str()));
            return true;
        }
        case ZYDIS_MNEMONIC_CVTPS2PI:
        case ZYDIS_MNEMONIC_CVTTPS2PI: {
            const char* fn = m == ZYDIS_MNEMONIC_CVTPS2PI ? "sse_cvt" : "sse_cvtt";
            emit(F("x86_v4u v = %s; ctx.mm[%d] = (uint64_t)(uint32_t)%s(x86_f(v[0])) | ((uint64_t)(uint32_t)%s(x86_f(v[1])) << 32);",
                   src128().c_str(), MmIndex(ops[0]), fn, fn));
            return true;
        }
        case ZYDIS_MNEMONIC_SHUFPS: {
            int imm = int(ops[2].imm.value.u);
            emit(F("x86_v4u v = %s; %s = __builtin_shufflevector(%s, v, %d, %d, %d, %d);", src128().c_str(), D.c_str(), D.c_str(), imm & 3,
                   (imm >> 2) & 3, 4 + ((imm >> 4) & 3), 4 + ((imm >> 6) & 3)));
            return true;
        }
        case ZYDIS_MNEMONIC_UNPCKLPS:
            emit(F("x86_v4u v = %s; %s = __builtin_shufflevector(%s, v, 0, 4, 1, 5);", src128().c_str(), D.c_str(), D.c_str()));
            return true;
        case ZYDIS_MNEMONIC_UNPCKHPS:
            emit(F("x86_v4u v = %s; %s = __builtin_shufflevector(%s, v, 2, 6, 3, 7);", src128().c_str(), D.c_str(), D.c_str()));
            return true;
        case ZYDIS_MNEMONIC_MOVMSKPS: {
            std::string S = X(s);
            emit(RegWrite(ops[0].reg.value, F("(%s[0] >> 31) | (%s[1] >> 31) << 1 | (%s[2] >> 31) << 2 | (%s[3] >> 31) << 3", S.c_str(),
                                              S.c_str(), S.c_str(), S.c_str())));
            return true;
        }
        case ZYDIS_MNEMONIC_LDMXCSR: emit("ctx.mxcsr = X86_MEM32(ea); X86_FZ_RELOAD;"); return true;
        case ZYDIS_MNEMONIC_STMXCSR: emit("X86_MEM32(ea) = ctx.mxcsr;"); return true;
        default:
            return false;
    }
}

bool CodeGen::EmitMmx(uint32_t va, const ZydisDecodedInstruction& in, const ZydisDecodedOperand* ops) {
    auto m = in.mnemonic;
    int mi = -1;
    for (int i = 0; i < in.operand_count_visible; i++)
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY) mi = i;
    std::string open = mi >= 0 ? "\t{ uint32_t ea = " + AddrExpr(ops[mi]) + "; " : "\t{ ";
    auto emit = [&](const std::string& s) { Line(open + s + " }"); };
    int d = MmIndex(ops[0]);
    int s = in.operand_count_visible > 1 ? MmIndex(ops[1]) : -1;
    if (d < 0 && s < 0 && m != ZYDIS_MNEMONIC_MOVD && m != ZYDIS_MNEMONIC_MOVQ) return false;
    std::string src = s >= 0 ? F("ctx.mm[%d]", s) : mi >= 0 ? "X86_MEM64(ea)" : "0ull";
    if (in.operand_count_visible > 1 && ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) src = F("%lluull", (unsigned long long)ops[1].imm.value.u);
    std::string D = d >= 0 ? F("ctx.mm[%d]", d) : "";

    struct Lane {
        ZydisMnemonic m;
        const char* type;
        const char* expr;
    };
    static const Lane lanes[] = {
        {ZYDIS_MNEMONIC_PADDB, "uint8_t", "a + b"},
        {ZYDIS_MNEMONIC_PADDW, "uint16_t", "a + b"},
        {ZYDIS_MNEMONIC_PADDD, "uint32_t", "a + b"},
        {ZYDIS_MNEMONIC_PADDSB, "int8_t", "sat<int8_t>((int)a + b)"},
        {ZYDIS_MNEMONIC_PADDSW, "int16_t", "sat<int16_t>((int)a + b)"},
        {ZYDIS_MNEMONIC_PADDUSB, "uint8_t", "sat<uint8_t>((int)a + b)"},
        {ZYDIS_MNEMONIC_PADDUSW, "uint16_t", "sat<uint16_t>((int)a + b)"},
        {ZYDIS_MNEMONIC_PSUBB, "uint8_t", "a - b"},
        {ZYDIS_MNEMONIC_PSUBW, "uint16_t", "a - b"},
        {ZYDIS_MNEMONIC_PSUBD, "uint32_t", "a - b"},
        {ZYDIS_MNEMONIC_PSUBSB, "int8_t", "sat<int8_t>((int)a - b)"},
        {ZYDIS_MNEMONIC_PSUBSW, "int16_t", "sat<int16_t>((int)a - b)"},
        {ZYDIS_MNEMONIC_PSUBUSB, "uint8_t", "sat<uint8_t>((int)a - b)"},
        {ZYDIS_MNEMONIC_PSUBUSW, "uint16_t", "sat<uint16_t>((int)a - b)"},
        {ZYDIS_MNEMONIC_PMULLW, "int16_t", "(int16_t)((int)a * b)"},
        {ZYDIS_MNEMONIC_PMULHW, "int16_t", "(int16_t)(((int)a * b) >> 16)"},
        {ZYDIS_MNEMONIC_PMULHUW, "uint16_t", "(uint16_t)(((uint32_t)a * b) >> 16)"},
        {ZYDIS_MNEMONIC_PCMPEQB, "uint8_t", "a == b ? 0xFF : 0"},
        {ZYDIS_MNEMONIC_PCMPEQW, "uint16_t", "a == b ? 0xFFFF : 0"},
        {ZYDIS_MNEMONIC_PCMPEQD, "uint32_t", "a == b ? 0xFFFFFFFFu : 0"},
        {ZYDIS_MNEMONIC_PCMPGTB, "int8_t", "a > b ? -1 : 0"},
        {ZYDIS_MNEMONIC_PCMPGTW, "int16_t", "a > b ? -1 : 0"},
        {ZYDIS_MNEMONIC_PCMPGTD, "int32_t", "a > b ? -1 : 0"},
        {ZYDIS_MNEMONIC_PAVGB, "uint8_t", "(a + b + 1) >> 1"},
        {ZYDIS_MNEMONIC_PAVGW, "uint16_t", "(a + b + 1) >> 1"},
        {ZYDIS_MNEMONIC_PMAXUB, "uint8_t", "a > b ? a : b"},
        {ZYDIS_MNEMONIC_PMINUB, "uint8_t", "a < b ? a : b"},
        {ZYDIS_MNEMONIC_PMAXSW, "int16_t", "a > b ? a : b"},
        {ZYDIS_MNEMONIC_PMINSW, "int16_t", "a < b ? a : b"},
    };
    for (auto& l : lanes)
        if (l.m == m) {
            emit(F("%s = mmx_map2<%s>(%s, %s, [](%s a, %s b) { return %s; });", D.c_str(), l.type, D.c_str(), src.c_str(),
                   l.type, l.type, l.expr));
            return true;
        }
    auto shift = [&](const char* type, const char* op, int bits) {
        bool arith = type[0] == 'i';
        if (arith)
            emit(F("uint64_t n = %s; if (n > %d) n = %d; %s = mmx_map2<%s>(%s, 0, [n](%s a, %s) { return (%s)(a >> n); });",
                   src.c_str(), bits - 1, bits - 1, D.c_str(), type, D.c_str(), type, type, type));
        else
            emit(F("uint64_t n = %s; %s = n >= %d ? 0 : mmx_map2<%s>(%s, 0, [n](%s a, %s) { return (%s)(a %s n); });", src.c_str(),
                   D.c_str(), bits, type, D.c_str(), type, type, type, op));
    };
    switch (m) {
        case ZYDIS_MNEMONIC_MOVQ:
            if (d >= 0) emit(F("%s = %s;", D.c_str(), src.c_str()));
            else emit(F("X86_MEM64(ea) = ctx.mm[%d];", s));
            return true;
        case ZYDIS_MNEMONIC_MOVNTQ:
            emit(F("X86_MEM64(ea) = ctx.mm[%d];", s));
            return true;
        case ZYDIS_MNEMONIC_MOVD:
            if (d >= 0) emit(F("%s = (uint32_t)(%s);", D.c_str(), Read(ops[1], "ea").c_str()));
            else emit(Write(ops[0], "ea", F("(uint32_t)ctx.mm[%d]", s)));
            return true;
        case ZYDIS_MNEMONIC_PAND: emit(F("%s &= %s;", D.c_str(), src.c_str())); return true;
        case ZYDIS_MNEMONIC_PANDN: emit(F("%s = ~%s & %s;", D.c_str(), D.c_str(), src.c_str())); return true;
        case ZYDIS_MNEMONIC_POR: emit(F("%s |= %s;", D.c_str(), src.c_str())); return true;
        case ZYDIS_MNEMONIC_PXOR: emit(F("%s ^= %s;", D.c_str(), src.c_str())); return true;
        case ZYDIS_MNEMONIC_PSLLW: shift("uint16_t", "<<", 16); return true;
        case ZYDIS_MNEMONIC_PSLLD: shift("uint32_t", "<<", 32); return true;
        case ZYDIS_MNEMONIC_PSRLW: shift("uint16_t", ">>", 16); return true;
        case ZYDIS_MNEMONIC_PSRLD: shift("uint32_t", ">>", 32); return true;
        case ZYDIS_MNEMONIC_PSRAW: shift("int16_t", ">>", 16); return true;
        case ZYDIS_MNEMONIC_PSRAD: shift("int32_t", ">>", 32); return true;
        case ZYDIS_MNEMONIC_PSLLQ: emit(F("uint64_t n = %s; %s = n >= 64 ? 0 : %s << n;", src.c_str(), D.c_str(), D.c_str())); return true;
        case ZYDIS_MNEMONIC_PSRLQ: emit(F("uint64_t n = %s; %s = n >= 64 ? 0 : %s >> n;", src.c_str(), D.c_str(), D.c_str())); return true;
        case ZYDIS_MNEMONIC_PMADDWD:
            emit(F("int16_t a[4], b[4]; uint64_t x = %s, y = %s; std::memcpy(a, &x, 8); std::memcpy(b, &y, 8); "
                   "int32_t r0 = a[0] * b[0] + a[1] * b[1], r1 = a[2] * b[2] + a[3] * b[3]; %s = (uint64_t)(uint32_t)r0 | ((uint64_t)(uint32_t)r1 << 32);",
                   D.c_str(), src.c_str(), D.c_str()));
            return true;
        case ZYDIS_MNEMONIC_PSADBW:
            emit(F("uint8_t a[8], b[8]; uint64_t x = %s, y = %s; std::memcpy(a, &x, 8); std::memcpy(b, &y, 8); uint32_t s = 0; "
                   "for (int i = 0; i < 8; i++) s += a[i] > b[i] ? a[i] - b[i] : b[i] - a[i]; %s = s;",
                   D.c_str(), src.c_str(), D.c_str()));
            return true;
        case ZYDIS_MNEMONIC_PUNPCKLBW:
        case ZYDIS_MNEMONIC_PUNPCKHBW:
        case ZYDIS_MNEMONIC_PUNPCKLWD:
        case ZYDIS_MNEMONIC_PUNPCKHWD:
        case ZYDIS_MNEMONIC_PUNPCKLDQ:
        case ZYDIS_MNEMONIC_PUNPCKHDQ: {
            int sz = (m == ZYDIS_MNEMONIC_PUNPCKLBW || m == ZYDIS_MNEMONIC_PUNPCKHBW) ? 1
                     : (m == ZYDIS_MNEMONIC_PUNPCKLWD || m == ZYDIS_MNEMONIC_PUNPCKHWD) ? 2 : 4;
            bool hi = m == ZYDIS_MNEMONIC_PUNPCKHBW || m == ZYDIS_MNEMONIC_PUNPCKHWD || m == ZYDIS_MNEMONIC_PUNPCKHDQ;
            emit(F("uint8_t a[8], b[8], r[8]; uint64_t x = %s, y = %s; std::memcpy(a, &x, 8); std::memcpy(b, &y, 8); "
                   "for (int i = 0; i < %d; i++) { std::memcpy(r + i * %d, a + %d + i * %d, %d); std::memcpy(r + i * %d + %d, b + %d + i * %d, %d); } "
                   "std::memcpy(&%s, r, 8);",
                   D.c_str(), src.c_str(), 4 / sz, 2 * sz, hi ? 4 : 0, sz, sz, 2 * sz, sz, hi ? 4 : 0, sz, sz, D.c_str()));
            return true;
        }
        case ZYDIS_MNEMONIC_PACKSSWB:
        case ZYDIS_MNEMONIC_PACKUSWB:
            emit(F("int16_t a[4], b[4]; %s r[8]; uint64_t x = %s, y = %s; std::memcpy(a, &x, 8); std::memcpy(b, &y, 8); "
                   "for (int i = 0; i < 4; i++) { r[i] = sat<%s>(a[i]); r[i + 4] = sat<%s>(b[i]); } std::memcpy(&%s, r, 8);",
                   m == ZYDIS_MNEMONIC_PACKSSWB ? "int8_t" : "uint8_t", D.c_str(), src.c_str(),
                   m == ZYDIS_MNEMONIC_PACKSSWB ? "int8_t" : "uint8_t", m == ZYDIS_MNEMONIC_PACKSSWB ? "int8_t" : "uint8_t", D.c_str()));
            return true;
        case ZYDIS_MNEMONIC_PACKSSDW:
            emit(F("int32_t a[2], b[2]; int16_t r[4]; uint64_t x = %s, y = %s; std::memcpy(a, &x, 8); std::memcpy(b, &y, 8); "
                   "r[0] = sat<int16_t>(a[0]); r[1] = sat<int16_t>(a[1]); r[2] = sat<int16_t>(b[0]); r[3] = sat<int16_t>(b[1]); std::memcpy(&%s, r, 8);",
                   D.c_str(), src.c_str(), D.c_str()));
            return true;
        case ZYDIS_MNEMONIC_PSHUFW: {
            int imm = int(ops[2].imm.value.u);
            emit(F("uint16_t a[4], r[4]; uint64_t x = %s; std::memcpy(a, &x, 8); r[0] = a[%d]; r[1] = a[%d]; r[2] = a[%d]; r[3] = a[%d]; std::memcpy(&%s, r, 8);",
                   src.c_str(), imm & 3, (imm >> 2) & 3, (imm >> 4) & 3, (imm >> 6) & 3, D.c_str()));
            return true;
        }
        case ZYDIS_MNEMONIC_PEXTRW:
            emit(RegWrite(ops[0].reg.value, F("(uint16_t)(ctx.mm[%d] >> (16 * (%d & 3)))", s, int(ops[2].imm.value.u))));
            return true;
        case ZYDIS_MNEMONIC_PINSRW: {
            int sh = 16 * (int(ops[2].imm.value.u) & 3);
            emit(F("%s = (%s & ~(0xFFFFull << %d)) | ((uint64_t)(uint16_t)(%s) << %d);", D.c_str(), D.c_str(), sh,
                   Read(ops[1], "ea").c_str(), sh));
            return true;
        }
        case ZYDIS_MNEMONIC_PMOVMSKB:
            emit(RegWrite(ops[0].reg.value, F("[&] { uint32_t r = 0; for (int i = 0; i < 8; i++) r |= ((ctx.mm[%d] >> (i * 8 + 7)) & 1) << i; return r; }()", s)));
            return true;
        default:
            return false;
    }
}
