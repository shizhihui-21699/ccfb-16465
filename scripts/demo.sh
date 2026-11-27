#!/usr/bin/env bash
# Walk through what unhusk does, on the synthetic corpus.
#
#   ./scripts/demo.sh            # narrated run
#   ./scripts/demo.sh --plain    # same commands, no pauses
set -uo pipefail
cd "$(dirname "$0")/.."
B=./target/release/unhusk
PAUSE=${PAUSE:-1.2}

if [ ! -x "$B" ]; then
  cargo build --release -q || exit 1
fi

run() {
  echo
  echo "\$ $1"
  [ -t 1 ] && sleep "$PAUSE"
  eval "$1"
}

if [ -z "${1:-}" ]; then clear; fi

echo "================================================================"
echo " 1. Static triage is fast: a 20 MB app in under a second."
echo "================================================================"
run "$B triage fixtures/packer.apk | head -12"

echo
echo "================================================================"
echo " 2. A stub whose payload is XOR-encrypted in the DEX."
echo "    The shipped bytecode cannot show what it does; the sandbox"
echo "    runs it, catches the decrypted DEX, and executes the payload."
echo "================================================================"
run "$B scan fixtures/packer.apk | sed -n '1,34p'"

echo
echo "================================================================"
echo " 3. The call graph, with recovered methods marked [runtime]."
echo "================================================================"
run "$B scan fixtures/packer.apk | sed -n '/EXECUTED CALL GRAPH/,\$p' | head -14"

echo
echo "================================================================"
echo " 4. A sample that checks the build fingerprint, probes for root"
echo "    paths, and only fires after a date gate. The sandbox answers"
echo "    the checks, sweeps several clock windows, and compares a"
echo "    hardened device profile against an obvious emulator."
echo "================================================================"
run "$B scan fixtures/evasive.apk | sed -n '1,52p'"

echo
echo "================================================================"
echo " 5. The same sample's evasion finding shows BOTH profiles'"
echo "    values: that contrast is the evidence the check exists."
echo "================================================================"
run "$B scan fixtures/evasive.apk | sed -n '/emulator \\/ virtual device/,/reached from/p' | head -14"

echo
echo "================================================================"
echo " 6. A packer that keeps its decryptor in libdecrypt.so."
echo "    The JNI export is resolved, the AArch64 routine runs, and"
echo "    the modified buffer is handed back to the classloader."
echo "================================================================"
run "$B scan fixtures/native.apk | sed -n '1,30p'"

echo
echo "================================================================"
echo " 7. Machine-readable output, and extraction of the payload."
echo "================================================================"
run "$B scan fixtures/packer.apk --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps({\"verdict\":d[\"verdict\"],\"score\":d[\"score\"],\"rules\":[f[\"rule\"] for f in d[\"findings\"]],\"recovered\":[p[\"sha1\"] for p in d[\"recovered_payloads\"]]}, indent=2))'"
run "rm -rf /tmp/unhusk-payloads; $B scan fixtures/packer.apk --extract /tmp/unhusk-payloads | grep extracted"

echo
echo "================================================================"
echo " 8. Batch mode: parallel, per-sample budget, only flagged rows."
echo "================================================================"
run "$B batch fixtures --budget-secs 20 --min-severity medium"

echo
echo "================================================================"
echo " 9. A benign app gets no findings — the point of the exercise."
echo "================================================================"
run "$B scan fixtures/hello.apk | sed -n '1,12p'"
echo
