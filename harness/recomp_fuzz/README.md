# Differential recompiler checks

Build the same game with the baseline and candidate SDKs, keeping their generated
C++ and runtime headers separate. This harness substitutes a recorder for callees,
then compares final registers, memory changes, and call contexts for every function.

```
JOBS=4 ./build.sh /path/to/generated /path/to/sdk/runtime /tmp/fuzz-candidate a64 -fno-math-errno
FZ_TIMEOUT_MS=1500 ./run.sh /tmp/fuzz-candidate/fz /tmp/candidate.txt 4 2 qemu-aarch64
python3 cmp.py /tmp/baseline.txt /tmp/candidate.txt
```

The ARM build requires clang, an aarch64 Linux cross linker/sysroot, and qemu-user.
The `x86` build runs directly on an x86 Linux host. Do not use this Linux executable
as a Horizon performance benchmark.

Important limits: trials that time out or exhaust the memory budget are excluded.
Default-NaN mode and input canonicalization hide NaN payload/sign differences; this
suite does not prove x86 NaN operand-order exactness. It also does not establish
threading correctness or real-hardware performance. Preserve logs and the compared
SDK revisions when reporting a pass.

`XBE_EXPERIMENTAL_SSE_FTZ` enables the interrupted software FTZ experiment. It stays
disabled in normal builds pending separate x86-oracle and game validation.
