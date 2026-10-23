#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

#include "codegen.h"

// Static x87 stack. The FPU stack of the context is a ring of eight doubles, ctx.st, whose top is ctx.top; the dynamic
// code reads st(i) as ctx.st[(ctx.top + i) & 7] at run time. Within most functions the stack depth relative to entry is
// the same on every path to an instruction, so st(i) is a known slot of the ring relative to the entry top: those
// slots become locals (x87_f0 ... x87_f7, slot N is ctx.st[(x87_T + N) & 7]) the compiler keeps in registers, pushes
// and pops are only a change of the depth the recompiler tracks, and the control word is the local x87_cw.
//
// The locals go back to ctx (the slots changed since the last sync, TOP, the control word if fldcw changed it) before
// every call, tail call, indirect jump and return, and are reloaded after a call (the compiler drops the loads it does
// not need). Instructions that set TOP from outside the stack (fninit, fldenv, frstor) sync around themselves too.
// Results are the same doubles with the same rounding helpers as the dynamic code: it is the same arithmetic, only the
// storage moves. The depth after a call is not known (the callee may return a value in st0, or pop), so after every sync
// the base is taken again from ctx.top: x87_T = ctx.top + depth, where depth is a free variable that is settled by the
// paths that meet later (union-find with offsets). A function whose paths disagree on the depth keeps the dynamic code.

static std::string F(const char* f, ...) __attribute__((format(printf, 1, 2)));
static std::string F(const char* f, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, f);
    std::vsnprintf(buf, sizeof(buf), f, ap);
    va_end(ap);
    return buf;
}

namespace {

struct Effect {
    bool fpu = false;     // an x87 instruction EmitX87 writes
    bool known = true;    // its stack effect is modelled
    bool rebase = false;  // sets TOP from outside the stack: sync before, base reloaded after
    bool writes = true;   // may write a stack slot
    bool cw = false;      // writes the control word
    int delta = 0;        // pushes less pops
    int sti = -1;         // highest explicit st(i) operand
    int dst = -1;         // st(i) of the first operand when it is a register
    int vis = 0;
    ZydisMnemonic m = ZYDIS_MNEMONIC_INVALID;
};

Effect X87Effect(const ZydisDecodedInstruction& in, const ZydisDecodedOperand* ops) {
    Effect e;
    const char* name = ZydisMnemonicGetString(in.mnemonic);
    if (!name || name[0] != 'f') return e;
    bool mem = false;
    for (int i = 0; i < in.operand_count_visible; i++) {
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY) mem = true;
        if (ops[i].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[i].reg.value >= ZYDIS_REGISTER_ST0 && ops[i].reg.value <= ZYDIS_REGISTER_ST7)
            e.sti = std::max(e.sti, int(ops[i].reg.value - ZYDIS_REGISTER_ST0));
    }
    e.fpu = true;
    e.m = in.mnemonic;
    e.vis = in.operand_count_visible;
    if (in.operand_count_visible && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value >= ZYDIS_REGISTER_ST0 &&
        ops[0].reg.value <= ZYDIS_REGISTER_ST7)
        e.dst = int(ops[0].reg.value - ZYDIS_REGISTER_ST0);
    switch (in.mnemonic) {
        // no x87 state (EmitInteger writes them as nothing)
        case ZYDIS_MNEMONIC_FNOP: case ZYDIS_MNEMONIC_FWAIT:
            return Effect{};
        case ZYDIS_MNEMONIC_FLD: case ZYDIS_MNEMONIC_FILD: case ZYDIS_MNEMONIC_FLD1: case ZYDIS_MNEMONIC_FLDZ:
        case ZYDIS_MNEMONIC_FLDPI: case ZYDIS_MNEMONIC_FLDL2E: case ZYDIS_MNEMONIC_FLDL2T: case ZYDIS_MNEMONIC_FLDLN2:
        case ZYDIS_MNEMONIC_FLDLG2:
            e.delta = 1;
            return e;
        case ZYDIS_MNEMONIC_FST: e.writes = !mem; return e;
        case ZYDIS_MNEMONIC_FSTP: e.writes = !mem; e.delta = -1; return e;
        case ZYDIS_MNEMONIC_FIST: e.writes = false; return e;
        case ZYDIS_MNEMONIC_FISTP: case ZYDIS_MNEMONIC_FISTTP: e.writes = false; e.delta = -1; return e;
        case ZYDIS_MNEMONIC_FADD: case ZYDIS_MNEMONIC_FIADD: case ZYDIS_MNEMONIC_FSUB: case ZYDIS_MNEMONIC_FISUB:
        case ZYDIS_MNEMONIC_FSUBR: case ZYDIS_MNEMONIC_FISUBR: case ZYDIS_MNEMONIC_FMUL: case ZYDIS_MNEMONIC_FIMUL:
        case ZYDIS_MNEMONIC_FDIV: case ZYDIS_MNEMONIC_FIDIV: case ZYDIS_MNEMONIC_FDIVR: case ZYDIS_MNEMONIC_FIDIVR:
            return e;
        case ZYDIS_MNEMONIC_FADDP: case ZYDIS_MNEMONIC_FSUBP: case ZYDIS_MNEMONIC_FSUBRP: case ZYDIS_MNEMONIC_FMULP:
        case ZYDIS_MNEMONIC_FDIVP: case ZYDIS_MNEMONIC_FDIVRP:
            e.delta = -1;
            return e;
        case ZYDIS_MNEMONIC_FXCH: return e;
        case ZYDIS_MNEMONIC_FCOM: case ZYDIS_MNEMONIC_FUCOM: case ZYDIS_MNEMONIC_FICOM: case ZYDIS_MNEMONIC_FCOMI:
        case ZYDIS_MNEMONIC_FUCOMI: case ZYDIS_MNEMONIC_FTST: case ZYDIS_MNEMONIC_FXAM:
            e.writes = false;
            return e;
        case ZYDIS_MNEMONIC_FCOMP: case ZYDIS_MNEMONIC_FUCOMP: case ZYDIS_MNEMONIC_FICOMP: case ZYDIS_MNEMONIC_FCOMIP:
        case ZYDIS_MNEMONIC_FUCOMIP:
            e.writes = false;
            e.delta = -1;
            return e;
        case ZYDIS_MNEMONIC_FCOMPP: case ZYDIS_MNEMONIC_FUCOMPP: e.writes = false; e.delta = -2; return e;
        case ZYDIS_MNEMONIC_FCHS: case ZYDIS_MNEMONIC_FABS: case ZYDIS_MNEMONIC_FSQRT: case ZYDIS_MNEMONIC_FSIN:
        case ZYDIS_MNEMONIC_FCOS: case ZYDIS_MNEMONIC_F2XM1: case ZYDIS_MNEMONIC_FSCALE: case ZYDIS_MNEMONIC_FRNDINT:
        case ZYDIS_MNEMONIC_FPREM: case ZYDIS_MNEMONIC_FPREM1:
            return e;
        case ZYDIS_MNEMONIC_FSINCOS: case ZYDIS_MNEMONIC_FPTAN: case ZYDIS_MNEMONIC_FXTRACT: e.delta = 1; return e;
        case ZYDIS_MNEMONIC_FPATAN: case ZYDIS_MNEMONIC_FYL2X: case ZYDIS_MNEMONIC_FYL2XP1: e.delta = -1; return e;
        case ZYDIS_MNEMONIC_FLDCW: e.writes = false; e.cw = true; return e;
        case ZYDIS_MNEMONIC_FNSTCW: case ZYDIS_MNEMONIC_FNSTSW: case ZYDIS_MNEMONIC_FNCLEX: case ZYDIS_MNEMONIC_FFREE:
        case ZYDIS_MNEMONIC_FNSTENV: case ZYDIS_MNEMONIC_FNSAVE:
            e.writes = false;
            return e;
        case ZYDIS_MNEMONIC_FINCSTP: e.writes = false; e.delta = -1; return e;
        case ZYDIS_MNEMONIC_FDECSTP: e.writes = false; e.delta = 1; return e;
        case ZYDIS_MNEMONIC_FNINIT: case ZYDIS_MNEMONIC_FLDENV: case ZYDIS_MNEMONIC_FRSTOR:
            e.writes = false;
            e.rebase = true;
            return e;
        case ZYDIS_MNEMONIC_FCMOVB: case ZYDIS_MNEMONIC_FCMOVBE: case ZYDIS_MNEMONIC_FCMOVE: case ZYDIS_MNEMONIC_FCMOVNB:
        case ZYDIS_MNEMONIC_FCMOVNBE: case ZYDIS_MNEMONIC_FCMOVNE: case ZYDIS_MNEMONIC_FCMOVNU: case ZYDIS_MNEMONIC_FCMOVU:
            return e;
        default:
            e.known = false;  // femms and anything EmitX87 does not write: keep the function dynamic
            return e;
    }
}

int Slot(int i, int depth) { return ((i - depth) % 8 + 8) % 8; }

// slots an instruction may read or write: st0, st1 and its explicit operand before, st0 and st1 after
uint16_t Touched(const Effect& e, int in, int out) {
    uint16_t m = uint16_t(1u << Slot(0, in) | 1u << Slot(1, in) | 1u << Slot(0, out) | 1u << Slot(1, out));
    if (e.sti >= 0) m |= uint16_t(1u << Slot(e.sti, in));
    return m;
}

// slots an instruction writes, as EmitX87 writes it; anything not listed gets Touched
uint16_t Written(const Effect& e, int in, int out) {
    if (!e.writes) return 0;
    auto bit = [](int i, int d) { return uint16_t(1u << Slot(i, d)); };
    switch (e.m) {
        case ZYDIS_MNEMONIC_FLD: case ZYDIS_MNEMONIC_FILD: case ZYDIS_MNEMONIC_FLD1: case ZYDIS_MNEMONIC_FLDZ:
        case ZYDIS_MNEMONIC_FLDPI: case ZYDIS_MNEMONIC_FLDL2E: case ZYDIS_MNEMONIC_FLDL2T: case ZYDIS_MNEMONIC_FLDLN2:
        case ZYDIS_MNEMONIC_FLDLG2:
            return bit(0, out);
        case ZYDIS_MNEMONIC_FST: case ZYDIS_MNEMONIC_FSTP:
            return e.dst >= 0 ? bit(e.dst, in) : Touched(e, in, out);
        case ZYDIS_MNEMONIC_FADD: case ZYDIS_MNEMONIC_FIADD: case ZYDIS_MNEMONIC_FSUB: case ZYDIS_MNEMONIC_FISUB:
        case ZYDIS_MNEMONIC_FSUBR: case ZYDIS_MNEMONIC_FISUBR: case ZYDIS_MNEMONIC_FMUL: case ZYDIS_MNEMONIC_FIMUL:
        case ZYDIS_MNEMONIC_FDIV: case ZYDIS_MNEMONIC_FIDIV: case ZYDIS_MNEMONIC_FDIVR: case ZYDIS_MNEMONIC_FIDIVR:
        case ZYDIS_MNEMONIC_FADDP: case ZYDIS_MNEMONIC_FSUBP: case ZYDIS_MNEMONIC_FSUBRP: case ZYDIS_MNEMONIC_FMULP:
        case ZYDIS_MNEMONIC_FDIVP: case ZYDIS_MNEMONIC_FDIVRP:
            // the memory form and "op st0, st(i)" write st0, "op st(i), st0" st(i), the bare form st1
            return e.dst >= 0 && e.vis >= 2 ? bit(e.dst, in) : Touched(e, in, out);
        case ZYDIS_MNEMONIC_FXCH: return uint16_t(bit(0, in) | bit(e.sti >= 0 ? e.sti : 1, in));
        case ZYDIS_MNEMONIC_FCHS: case ZYDIS_MNEMONIC_FABS: case ZYDIS_MNEMONIC_FSQRT: case ZYDIS_MNEMONIC_FSIN:
        case ZYDIS_MNEMONIC_FCOS: case ZYDIS_MNEMONIC_F2XM1: case ZYDIS_MNEMONIC_FSCALE: case ZYDIS_MNEMONIC_FRNDINT:
        case ZYDIS_MNEMONIC_FPREM: case ZYDIS_MNEMONIC_FPREM1:
        case ZYDIS_MNEMONIC_FCMOVB: case ZYDIS_MNEMONIC_FCMOVBE: case ZYDIS_MNEMONIC_FCMOVE: case ZYDIS_MNEMONIC_FCMOVNB:
        case ZYDIS_MNEMONIC_FCMOVNBE: case ZYDIS_MNEMONIC_FCMOVNE: case ZYDIS_MNEMONIC_FCMOVNU: case ZYDIS_MNEMONIC_FCMOVU:
            return bit(0, in);
        case ZYDIS_MNEMONIC_FSINCOS: case ZYDIS_MNEMONIC_FPTAN: case ZYDIS_MNEMONIC_FXTRACT:
            return uint16_t(bit(0, in) | bit(0, out));
        case ZYDIS_MNEMONIC_FPATAN: case ZYDIS_MNEMONIC_FYL2X: case ZYDIS_MNEMONIC_FYL2XP1:
            return bit(0, out);
        default:
            return Touched(e, in, out);
    }
}

// union-find over depth variables with offsets: value(v) = value(parent[v]) + off[v]
struct DepthVars {
    std::vector<int> parent, off;
    int Add() {
        parent.push_back(int(parent.size()));
        off.push_back(0);
        return int(parent.size()) - 1;
    }
    int Find(int v, int& d) {
        d = 0;
        int r = v;
        while (parent[r] != r) {
            d += off[r];
            r = parent[r];
        }
        // compress
        int acc = d;
        while (parent[v] != v) {
            int p = parent[v], o = off[v];
            parent[v] = r;
            off[v] = acc;
            acc -= o;
            v = p;
        }
        return r;
    }
    // value(a) + oa == value(b) + ob
    bool Unify(int a, int oa, int b, int ob) {
        int da, db;
        int ra = Find(a, da), rb = Find(b, db);
        if (ra == rb) return da + oa == db + ob;
        parent[ra] = rb;
        off[ra] = db + ob - da - oa;
        return true;
    }
};

}  // namespace

bool CodeGen::X87Plan(const std::vector<uint32_t>& body, std::string& why) {
    x87_.clear();
    x87_used_ = 0;
    struct Node {
        Effect e;
        bool sync = false;  // a call: locals to ctx before, base reloaded after
        std::vector<uint32_t> succ;
    };
    std::map<uint32_t, Node> nodes;
    bool any = false;
    for (uint32_t va : body) {
        Node& n = nodes[va];
        const Insn* info = an_.InsnAt(va);
        ZydisDecodedInstruction in;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!info || info->flow == Flow::Invalid || !an_.Decode(va, in, ops)) continue;  // a trap
        if (an_.cfg.hooks.count(va)) {
            why = "hook";
            return false;
        }
        n.e = X87Effect(in, ops);
        if (n.e.fpu && !n.e.known) {
            why = std::string("unmodelled ") + ZydisMnemonicGetString(in.mnemonic);
            return false;
        }
        any |= n.e.fpu;
        uint32_t next = va + info->len;
        auto edge = [&](uint32_t t) {
            if (body_set_.count(t)) n.succ.push_back(t);
        };
        switch (info->flow) {
            case Flow::Normal: edge(next); break;
            case Flow::Call:
            case Flow::CallIndirect:
                n.sync = !(info->flow == Flow::Call && info->target == next);  // call $+5 only pushes eip
                edge(next);
                break;
            case Flow::Jcc:
                edge(next);
                edge(info->target);
                break;
            case Flow::Jmp: edge(info->target); break;
            case Flow::JmpIndirect: {
                auto jt = an_.jump_tables.find(va);
                if (jt != an_.jump_tables.end())
                    for (uint32_t t : jt->second.targets) edge(t);
                break;
            }
            default: break;  // ret, traps
        }
        if (n.e.rebase) n.sync = true;
    }
    if (!any) {
        why = "";
        return false;
    }
    // every call and return syncs the locals with ctx; where there is little x87 work between them the dynamic code,
    // which touches ctx only at the x87 instructions themselves, is as fast and smaller
    size_t fpu = 0, syncs = 0;
    for (auto& [va, n] : nodes) {
        fpu += n.e.fpu;
        syncs += n.sync;
    }
    if (an_.cfg.x87_static_ratio > 0 && double(fpu) < an_.cfg.x87_static_ratio * double(syncs)) {
        why = "few x87 instructions per call";
        return false;
    }

    // depths: entry is variable 0 at offset 0, each sync starts a variable of its own
    DepthVars vars;
    vars.Add();
    std::map<uint32_t, int> sync_var;
    std::map<uint32_t, std::pair<int, int>> state;  // va -> (variable, offset) before the instruction
    std::vector<uint32_t> work{entry_};
    state[entry_] = {0, 0};
    while (!work.empty()) {
        uint32_t va = work.back();
        work.pop_back();
        Node& n = nodes[va];
        auto [v, o] = state[va];
        std::pair<int, int> out{v, o + n.e.delta};
        if (n.sync) {
            auto it = sync_var.find(va);
            if (it == sync_var.end()) it = sync_var.emplace(va, vars.Add()).first;
            out = {it->second, 0};
        }
        for (uint32_t s : n.succ) {
            auto it = state.find(s);
            if (it == state.end()) {
                state[s] = out;
                work.push_back(s);
            } else if (!vars.Unify(it->second.first, it->second.second, out.first, out.second)) {
                why = "depth differs between paths";
                return false;
            }
        }
    }
    // the entry's set takes the value that puts entry at depth 0, the others 0
    int d0;
    int r0 = vars.Find(0, d0);
    auto depth = [&](std::pair<int, int> s) {
        int d;
        int r = vars.Find(s.first, d);
        return (r == r0 ? -d0 : 0) + d + s.second;
    };
    for (uint32_t va : body) {
        auto it = state.find(va);
        if (it == state.end()) continue;  // not reached from the entry (a hook target); never emitted as static
        Node& n = nodes[va];
        X87Point& p = x87_[va];
        p.sync = n.sync;
        p.in = depth(it->second);
        if (n.sync) p.out = depth({sync_var[va], 0});
        else p.out = p.in + n.e.delta;
        if (n.e.fpu) x87_used_ |= uint8_t(Touched(n.e, p.in, p.out));
    }
    if (x87_.size() != body.size()) {
        why = "unreached instruction";
        return false;
    }

    // slots changed since the last sync: forward union to a fixed point
    for (bool changed = true; changed;) {
        changed = false;
        for (uint32_t va : body) {
            Node& n = nodes[va];
            X87Point& p = x87_[va];
            uint16_t out = p.dirty_in;
            if (n.sync) out = 0;
            else if (n.e.fpu) {
                out |= Written(n.e, p.in, p.out);
                if (n.e.cw) out |= 0x100;
                if (n.e.delta) out |= 0x200;
            }
            p.dirty_out = out;
            for (uint32_t s : n.succ) {
                X87Point& q = x87_[s];
                if ((q.dirty_in | out) != q.dirty_in) {
                    q.dirty_in |= out;
                    changed = true;
                }
            }
        }
    }
    return true;
}

std::string CodeGen::X87Out() const {
    if (!x87_static_) return "";
    // TOP is only written when a push or pop may have moved it since the last sync (or entry): otherwise ctx.top is
    // still x87_T less the depth
    std::string s;
    if (x87_dirty_ & 0x200) s = x87_depth_ % 8 == 0 ? "ctx.top = x87_T; " : F("ctx.top = (x87_T + %du) & 7; ", Slot(0, x87_depth_));
    for (int k = 0; k < 8; k++)
        if (x87_dirty_ & (1u << k)) s += F("ctx.st[(x87_T + %d) & 7] = x87_f%d; ", k, k);
    if (x87_dirty_ & 0x100) s += "ctx.fcw = x87_cw; ";
    return s;
}

std::string CodeGen::X87In(int depth) const {
    if (!x87_static_) return "";
    std::string s = depth % 8 == 0 ? "x87_T = ctx.top & 7; " : F("x87_T = (ctx.top + %du) & 7; ", ((depth % 8) + 8) % 8);
    for (int k = 0; k < 8; k++)
        if (x87_used_ & (1u << k)) s += F("x87_f%d = ctx.st[(x87_T + %d) & 7]; ", k, k);
    return s + "x87_cw = ctx.fcw;";
}

std::string CodeGen::X87Prologue() const {
    std::string s = "\tuint32_t x87_T = ctx.top & 7;\n";
    for (int k = 0; k < 8; k++)
        if (x87_used_ & (1u << k)) s += F("\tdouble x87_f%d = ctx.st[(x87_T + %d) & 7];\n", k, k);
    return s + "\tuint16_t x87_cw = ctx.fcw;\n";
}

void CodeGen::X87Check(uint32_t va, const std::string& emitted) const {
    static const char* const dynamic[] = {"X87_ST(", "x87_push(", "x87_pop(", "x87_prec(", "x87_status(", "x87_examine(",
                                          "x87_round(", "x87_to_i16(", "x87_to_i32(", "x87_to_i64("};
    const X87Point& p = x87_.at(va);
    const char* bad = nullptr;
    for (const char* d : dynamic)
        if (emitted.find(d) != std::string::npos) bad = d;
    if (!bad && !p.sync && x87_depth_ != p.out) bad = "a depth other than the plan's";
    if (!bad) return;
    std::fprintf(stderr, "x87 static stack: %08X in %s emitted %s\n%s", va, FuncName(entry_).c_str(), bad, emitted.c_str());
    std::exit(1);
}

std::string CodeGen::X87BeforeTraps(const std::string& emitted, const std::string& out) {
    // x86_trap ends the game and x86_priv only logs, but both get the context, so it must hold the stack first
    static const std::string traps[] = {"x86_trap(ctx,", "x86_priv(ctx,"};
    if (out.empty()) return emitted;
    auto next = [&](size_t from) {
        size_t p = std::string::npos;
        for (const std::string& t : traps) p = std::min(p, emitted.find(t, from));
        return p;
    };
    if (next(0) == std::string::npos) return emitted;
    std::string r;
    size_t i = 0;
    for (size_t p; (p = next(i)) != std::string::npos;) {
        // the call's end: its closing parenthesis and ';', skipping the string literal of the message
        size_t e = emitted.find('(', p) + 1;
        for (int depth = 1; e < emitted.size() && depth; e++) {
            char c = emitted[e];
            if (c == '"') {
                for (e++; e < emitted.size() && emitted[e] != '"'; e++)
                    if (emitted[e] == '\\') e++;
            } else if (c == '(') depth++;
            else if (c == ')') depth--;
        }
        if (e < emitted.size() && emitted[e] == ';') e++;
        r += emitted.substr(i, p - i) + "{ " + out + emitted.substr(p, e - p) + " }";
        i = e;
    }
    return r + emitted.substr(i);
}
