#pragma once
#include <cstdint>
#include "cpu/x86_context.h"
struct FzEntry {
    uint32_t va;
    X86Func* fn;
};
extern const FzEntry fz_table[];
extern const FzEntry fz_stubs[];  // the recorder of every sub_X, by guest address
void fz_stub(uint32_t callee, X86Context& ctx, uint8_t* base);
uint32_t fz_hook(int id, X86Context& ctx, uint8_t* base);
