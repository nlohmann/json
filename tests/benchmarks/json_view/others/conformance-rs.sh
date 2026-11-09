#!/bin/bash
# the Rust conformance run, one file per process; a file that aborts the process (stack overflow) is rerun one
# variant per process, and a variant that aborts is printed as crashed
B=$1; D=$2
VARS=$($B --conformance $D 1 y_structure_lonely_int.json | sed -n 's/^conformance: [^|]* | \(.*\) | [a-z]*$/\1/p')
for f in $(ls $D | grep '\.json$'); do
  out=$($B --conformance $D 1 "$f" 2>/dev/null)
  if [ $? = 0 ]; then echo "$out" | grep '^conformance:'; continue; fi
  while IFS= read -r v; do
    o=$(CONF_VARIANT="$v" $B --conformance $D 1 "$f" 2>/dev/null)
    if [ $? = 0 ]; then echo "$o" | grep '^conformance:'; else echo "conformance: $f | $v | crashed"; fi
  done <<< "$VARS"
done
echo "done: conformance"
