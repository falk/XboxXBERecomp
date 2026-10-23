#!/usr/bin/env python3
# gen_stubs.py <gen dir> <out.cpp>: a stub for every sub_X the generated code calls by name, stubs for the hook
# functions, and the table of __imp__ bodies (guest address, body) the fuzzer runs
import re, sys, glob
gen, out = sys.argv[1], sys.argv[2]
shared = open(gen + '/x86_recomp_shared.h').read()
subs = re.findall(r'X86_EXTERN_FUNC\((sub_[0-9A-F]+)\);', shared)
hooks = re.findall(r'^(void|bool) (\w+)\(X86Context& ctx, uint8_t\* base\);', shared, re.M)
bodies = set()
for f in glob.glob(gen + '/x86_recomp.*.cpp'):
    for m in re.finditer(r'^X86_FUNC\(__imp__(sub_[0-9A-F]+)\)', open(f).read(), re.M):
        bodies.add(m.group(1))
o = ['#include "cpu/x86_ops.h"', '#include "fz.h"']
for s in subs:
    o.append(f'extern "C" void {s}(X86Context& ctx, uint8_t* base) {{ fz_stub(0x{s[4:]}u, ctx, base); }}')
for i, (ret, h) in enumerate(hooks):
    if ret == 'void':
        o.append(f'void {h}(X86Context& ctx, uint8_t* base) {{ fz_hook({i}, ctx, base); }}')
    else:
        o.append(f'bool {h}(X86Context& ctx, uint8_t* base) {{ return fz_hook({i}, ctx, base) & 1; }}')
body = sorted(bodies, key=lambda s: int(s[4:], 16))
for b in body:
    o.append(f'extern "C" void __imp__{b}(X86Context& ctx, uint8_t* base);')
o.append('const FzEntry fz_table[] = {')
for b in body:
    o.append(f'\t{{0x{b[4:]}u, __imp__{b}}},')
o.append('\t{0, nullptr},\n};')
o.append('const FzEntry fz_stubs[] = {')
for su in subs:
    o.append(f'\t{{0x{su[4:]}u, {su}}},')
o.append('\t{0, nullptr},\n};')
open(out, 'w').write('\n'.join(o) + '\n')
print(len(subs), 'stubs', len(hooks), 'hooks', len(body), 'bodies')
