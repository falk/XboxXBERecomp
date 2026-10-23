#!/usr/bin/env python3
# cmp.py a b: compare two fuzzer outputs; a trial counts when neither side timed out, hit the page limit or faulted (3, 4, 5)
import sys
def load(p):
    d = {}
    for line in open(p):
        va, t, o, h = line.split()
        d[(va, t)] = (int(o), h)
    return d
a, b = load(sys.argv[1]), load(sys.argv[2])
same = diff = skip = 0
bad = []
for k in sorted(set(a) | set(b)):
    if k not in a or k not in b:
        bad.append((k, 'missing')); diff += 1; continue
    (oa, ha), (ob, hb) = a[k], b[k]
    if oa in (3, 4, 5) or ob in (3, 4, 5):
        skip += 1; continue
    if (oa, ha) == (ob, hb): same += 1
    else:
        diff += 1; bad.append((k, f'{oa}:{ha} vs {ob}:{hb}'))
print(f'same {same} differ {diff} skipped {skip}')
funcs = sorted(set(k[0] for k, _ in bad))
print('differing functions:', len(funcs), ' '.join(funcs[:40]))

sys.exit(1 if diff else 0)
