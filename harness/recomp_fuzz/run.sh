#!/bin/bash
# run.sh <fz exe> <out.txt> [trials] [parts] [runner]: the whole table in parallel parts, joined in order
FZ=$1; OUT=$2; T=${3:-4}; P=${4:-2}; RUN=${5:-}
N=16000; per=$(( (N + P - 1) / P )); pids=()
for k in $(seq 0 $((P - 1))); do
    $RUN "$FZ" "$OUT.part$k" "$T" $((k * per)) "$per" 2> "$OUT.err$k" & pids+=($!)
done
wait "${pids[@]}"
cat $(for k in $(seq 0 $((P - 1))); do echo "$OUT.part$k"; done) > "$OUT"; cat "$OUT".err*; rm -f "$OUT".part* "$OUT".err*
