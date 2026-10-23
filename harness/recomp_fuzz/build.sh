#!/bin/bash
# build.sh <gen dir> <runtime dir (holding cpu/)> <out dir> <x86|a64> [extra flags...]: the fuzzer over one generated tree
# env: GEN_FLAGS (default -O2 -fno-strict-aliasing -ffp-contract=off), JOBS
set -e
GEN=$(realpath "$1"); RT=$(realpath "$2"); OUT=$3; ARCH=$4; shift 4; EXTRA="$*"
F=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT/obj"; OUT=$(realpath "$OUT")
case $ARCH in
    x86) CXX="clang++ -march=x86-64-v2"; LD="clang++" ;;
    a64) CXX="clang++ --target=aarch64-linux-gnu -mcpu=cortex-a57"; LD="clang++ --target=aarch64-linux-gnu -static -fuse-ld=bfd" ;;
esac
FLAGS="-std=gnu++20 ${GEN_FLAGS:--O2 -fno-strict-aliasing -ffp-contract=off} -w -g0 $EXTRA -I$RT -I$GEN -I$F"
python3 "$F/gen_stubs.py" "$GEN" "$OUT/stubs.cpp"
for f in "$GEN"/x86_recomp.*.cpp; do
    b=$(basename "$f" .cpp)
    { echo '#include "x86_recomp_shared.h"'; echo '#undef X86_WEAK_ALIAS'; echo '#define X86_WEAK_ALIAS(name, impl)';
      echo '#undef X86_TRACED_FUNC'; echo '#define X86_TRACED_FUNC(name, impl, va)'; echo "#include \"$f\""; } > "$OUT/obj/$b.wrap.tmp"
    cmp -s "$OUT/obj/$b.wrap.tmp" "$OUT/obj/$b.wrap.cpp" || mv "$OUT/obj/$b.wrap.tmp" "$OUT/obj/$b.wrap.cpp"
done
export CXX FLAGS OUT
echo "$CXX $FLAGS" > "$OUT/flags.new"; cmp -s "$OUT/flags.new" "$OUT/flags" || { rm -f "$OUT"/obj/*.o; mv "$OUT/flags.new" "$OUT/flags"; }
export GEN RT
ls "$OUT"/obj/*.wrap.cpp | xargs -P "${JOBS:-$(nproc)}" -I{} sh -c 'o={}; o=${o%.wrap.cpp}.o; g=$GEN/$(basename $o .o).cpp; [ "$o" -nt "$g" ] && [ "$o" -nt "$GEN/x86_recomp_shared.h" ] && [ "$o" -nt "$RT/cpu/x86_ops.h" ] && [ "$o" -nt "$RT/cpu/x86_context.h" ] && exit 0; $CXX $FLAGS -c {} -o $o.tmp && mv $o.tmp $o' 
$CXX -std=gnu++20 -O2 -g -I"$RT" -I"$F" -c "$F/fz_rt.cpp" -o "$OUT/fz_rt.o"
$CXX -std=gnu++20 -O1 -g0 -w -I"$RT" -I"$GEN" -I"$F" -c "$OUT/stubs.cpp" -o "$OUT/stubs.o"
$LD -o "$OUT/fz" "$OUT/fz_rt.o" "$OUT/stubs.o" "$OUT"/obj/*.o
echo "built $OUT/fz"
