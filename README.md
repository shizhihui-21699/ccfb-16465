# unhusk

Static + dynamic analysis for packed Android samples, in Rust.

`unhusk` answers one question for a malware analyst: **what does this APK
actually do, once the packer is out of the way?** It parses the APK, runs the
Dalvik bytecode in a bounded sandbox that models the Android framework,
recovers code decrypted at runtime (in DEX *or* in a `.so`), and reports the
behaviour with the call path that reached it.

```
$ unhusk scan suspicious.apk
================================================================================================
 unhusk report — com.example.packer
================================================================================================
 apk sha256 : fe9ce8ebe4b1b2b45d2e0a9735e8aff0c73e86d64397238475aa595ca0f7f95c
 package    : com.example.packer
 version    : -   minSdk 21 / targetSdk 30
 profile    : pixel6-a13 (multi-window)   runtime 8 ms   75285 instructions
 stop       : completed

 VERDICT: malicious (runtime code executed) (score 48)   2 finding(s)

 1. [CRIT] Runtime-unpacked DEX recovered and executed (2 method(s))
    rule: runtime-dex-recovered   technique: T1406 Obfuscated Files or Information
    The sample decrypted 1 DEX payload(s) at runtime and installed them through a
    classloader. This is the signature of a packer: the shipped DEX is only a stub
    and the behaviour an analyst would need to review is not in it.
    indicators:
      - file:/data/data/com.example.packer/files/payload.dex (sha1 a9ea7c62…, 1 classes)
    reached from:
      ← com.example.packer.Loader.run(Ljava/lang/String;)V
      ← com.example.packer.Stub.run()V
      ← <entry>
```

## Why it is built this way

The problem has four hard parts, and each one shapes a design decision:

**Packer shells keep changing.** There is no signature that survives them. So
`unhusk` does not try to *recognise* a packer — it implements the *interface a
packer must use*. A loader has to hand its decrypted payload to one of a small
set of platform APIs (`DexClassLoader`, `PathClassLoader`,
`InMemoryDexClassLoader`, `DexFile.loadDex`, `ClassLoader.loadClass`). Those
are intercepted, whatever the shell looks like around them. The same applies
to native decryptors: a JNI export is resolved by its mangled name and run.

**Samples detect analysis environments.** The sandbox presents a *coherent*
device profile: `Build.MODEL`, `DEVICE`, `HARDWARE`, the fingerprint and
`/proc/cpuinfo` all agree, the SIM has an operator, sensors report real values,
and no root or emulator artefacts exist on disk. Reads of `Build.*`,
telephony, sensors and root paths are recorded, so the report can show the
evasion strategy even when it is what stopped the payload.

**Payloads are gated on time and state.** Malware activates in a date window,
after a delay, or only when a particular check passes. The pipeline runs the
same sample under **several emulated clock windows** and unions what it saw.
It also runs a **naive-emulator comparison pass**: behaviour that appears under
the hardened profile but not the emulator one is exactly what the sample was
hiding, and the report prints the property values side by side.

**Each sample gets minutes, not hours.** Every run has a fixed instruction and
wall-clock budget shared across all passes. Hitting it produces a partial
report with an explicit caveat — never a hang, never a silent zero. Runs are
deterministic (fixed seed, fixed clock) so a result can be reproduced.

## What the report contains

* **Findings**, ranked, each with severity, MITRE technique, indicators,
  the call path from the entry point, and the raw events behind it. Rules
  collapse repeated observations: three root-path probes are one finding.
* **Runtime-recovered payloads**, with SHA-1 so they can be extracted and
  re-analysed.
* **Network egress**, including whether the body was built or decrypted at
  runtime rather than being a constant in the APK.
* **The executed call graph**, with recovered methods marked `[runtime]`.
* **Caveats**, always: what the budget cut off, what the emulator could not
  model.

## Usage

```bash
cargo build --release
B=./target/release/unhusk

$B scan sample.apk                     # full analysis, text report
$B scan sample.apk --json              # machine-readable (schema unhusk/report/v1)
$B scan sample.apk --extract out/      # also write recovered DEX payloads
$B scan sample.apk --fail-on critical  # exit 1 when a critical finding exists

$B triage sample.apk                   # static facts only, <1s
$B batch samples/ --out reports/       # parallel, per-sample budget
$B graph sample.apk                    # executed call graph as Graphviz DOT
```

Exit codes: `0` no finding at the threshold, `1` a finding met it, `2` the
input could not be analysed.

## Architecture

Six crates, each with one job:

| crate | responsibility |
|---|---|
| `unhusk-dex` | DEX decoder: bounds-checked, dependency-free, produces a resolved model |
| `unhusk-apk` | ZIP container, binary `AndroidManifest.xml`, packer fingerprints |
| `unhusk-vm` | the bounded Dalvik interpreter, Android/JDK model, AArch64 emulator |
| `unhusk-engine` | the pipeline: triage, budget allocation, multi-pass strategy |
| `unhusk-report` | trace → findings → text/JSON; the call graph |
| `unhusk-cli` | `unhusk` binary |

The interpreter is a straight-line walker over `unhusk-dex`'s decoded
instruction table. Untrusted input is the norm, so every decode is
bounds-checked and every inconsistency is a typed error; there is a test suite
that mutates a DEX header byte by byte and asserts no panic.

## Honest limits

This is a fast, wide net, not a complete Dalvik runtime. What it does **not**
do, and says so in the report:

* **AArch64 coverage is partial.** The native emulator implements the
  instruction classes a compiler emits for byte manipulation (loads/stores,
  add/sub/logic/shift, branches, multiply/divide). Anything else stops with the
  exact PC and encoding. A packer whose decryptor uses NEON, floating point
  crypto, or self-modifying code will not be fully unpacked.
* **JNI is modelled, not executed.** `GetByteArrayElements` and friends answer
  from the same buffer the arguments came from; a stub that builds its output
  through several JNI objects may not produce a recoverable payload.
* **Only AArch64 is emulated.** ARMv7-only libraries are reported but not run.
* **Obfuscated control flow is followed, not solved.** Opaque predicates and
  flattening are executed as written. The sample is handed plausible state, and
  if that state reaches the payload, so does the run.
* **The framework model is a subset.** Calls the model does not know return a
  default. The trace records which calls were modelled and which were not, so a
  reader can tell where the picture stops.
* **No network egress by default.** Requests are recorded, never sent. This is
  a deliberate safety default and is a single flag in `NetworkModel`.

## Building

```bash
cargo build --release
cargo test                      # 40+ tests, no Android toolchain needed
```

The test corpus (`fixtures/*.apk`) is committed, so tests do not require
`javac`/`d8`. To regenerate it after changing a fixture source:

```bash
JAVA_HOME=/path/to/jdk17+ python3 -I tools/make_fixtures.py
```

This needs `javac`, `d8`, `aapt2` and `android.jar` (Android build-tools). The
AArch64 `.so` used by the native fixture is prebuilt under `fixtures/native/`;
`fixtures/native/decrypt.c` documents how it was built.

## Layout

```
crates/dex        DEX parser + instruction decoder
crates/apk        ZIP/APK reader, binary manifest, static heuristics
crates/vm         interpreter, framework model, AArch64 emulator
crates/engine     analysis pipeline
crates/report     findings, call graph, rendering
crates/cli        unhusk binary
fixtures/         synthetic APK corpus + sources
tools/            fixture generator
```
