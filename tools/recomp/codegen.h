#pragma once
#include <filesystem>
#include <map>
#include <set>
#include <string>

#include "analysis.h"

class CodeGen {
public:
    CodeGen(const Analysis& an, std::filesystem::path out) : an_(an), out_(std::move(out)) {}
    bool Run();

private:
    struct Op {
        const ZydisDecodedOperand* o = nullptr;
        std::string ea;  // name of the address temp when memory
    };

    std::string EmitFunction(uint32_t entry);
    bool CheckHooks(const std::vector<uint32_t>& funcs) const;
    int RetBytes(const std::vector<uint32_t>& body) const;  // the one ret n of a body, or -1
    void EmitHooks(uint32_t va, bool after);
    void EmitInsn(uint32_t va, const ZydisDecodedInstruction& in, const ZydisDecodedOperand* ops, uint32_t next_body);

    // operand helpers
    std::string RegRead(ZydisRegister r) const;
    std::string RegWrite(ZydisRegister r, const std::string& v) const;
    std::string AddrExpr(const ZydisDecodedOperand& o, bool with_segment = true) const;
    std::string Read(const ZydisDecodedOperand& o, const std::string& ea) const;
    std::string Write(const ZydisDecodedOperand& o, const std::string& ea, const std::string& v) const;
    std::string Mem(unsigned bits, const std::string& ea) const;
    std::string CType(unsigned bits, bool is_signed = false) const;

    std::string Cond(ZydisMnemonic m);
    std::string Target(uint32_t t);  // goto or tail call
    std::string Hex(uint32_t v) const;
    std::string FuncName(uint32_t va) const;
    void Line(const std::string& s) { body_ += s; body_ += '\n'; }
    void Unimpl(uint32_t va, const ZydisDecodedInstruction& in, const ZydisDecodedOperand* ops);
    std::string Text(uint32_t va, const ZydisDecodedInstruction& in, const ZydisDecodedOperand* ops) const;

    // instruction groups
    bool EmitInteger(uint32_t va, const ZydisDecodedInstruction& in, const ZydisDecodedOperand* ops);
    bool EmitString(uint32_t va, const ZydisDecodedInstruction& in, const ZydisDecodedOperand* ops);
    bool EmitX87(uint32_t va, const ZydisDecodedInstruction& in, const ZydisDecodedOperand* ops);
    bool EmitSse(uint32_t va, const ZydisDecodedInstruction& in, const ZydisDecodedOperand* ops);
    bool EmitMmx(uint32_t va, const ZydisDecodedInstruction& in, const ZydisDecodedOperand* ops);

    const Analysis& an_;
    std::filesystem::path out_;
    std::string body_;
    uint32_t entry_ = 0;
    std::set<uint32_t> body_set_;
    std::set<uint32_t> labels_;
    // cmp/test/comiss peephole: the operands of the last compare, in ca/cb (integer) or fa/fb (comiss/ucomiss)
    struct Pending {
        bool valid = false;
        bool is_test = false;
        unsigned bits = 32;
        bool is_float = false;
    } pending_;
    std::map<std::string, size_t> unimpl_;
    size_t insn_count_ = 0;
    int ret_bytes_ = -1;

    // Static x87 stack (codegen_x87.cpp): in a function where the stack depth relative to entry is known at every
    // instruction, st(i) is a local double (x87_fN, N the ring slot relative to the base x87_T) and the control word
    // the local x87_cw; they go back to ctx before anything that may read it and are reloaded after.
    struct X87Point {
        int in = 0, out = 0;              // depth before and after the instruction
        uint16_t dirty_in = 0, dirty_out = 0;  // changed since the last sync: slots (bits 0-7), control word (8), TOP (9)
        bool sync = false;                // a call or an instruction that sets TOP: out is a new base
    };
    bool X87Plan(const std::vector<uint32_t>& body, std::string& why);
    std::string X87Out() const;  // locals to ctx at the current point (x87_depth_, x87_dirty_), "" without the plan
    std::string X87In(int depth) const;  // ctx to locals after a call, the depth after it given
    std::string X87Prologue() const;
    void X87Check(uint32_t va, const std::string& emitted) const;  // the instruction kept to the plan
    static std::string X87BeforeTraps(const std::string& emitted, const std::string& out);  // out before each x86_trap and x86_priv
    bool x87_static_ = false;
    std::map<uint32_t, X87Point> x87_;
    uint8_t x87_used_ = 0;  // slots the function may touch
    int x87_depth_ = 0;
    uint16_t x87_dirty_ = 0;
    size_t x87_funcs_ = 0, x87_static_funcs_ = 0;
    std::map<std::string, size_t> x87_fallback_;  // reason -> functions
    std::vector<uint32_t> x87_fallback_funcs_;
};
