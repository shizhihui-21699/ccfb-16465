# Design notes

The decisions that are easy to get wrong, and why this code makes them the way
it does. Read this before changing the interpreter or the pipeline.

## 1. Packer without packer signatures

A static detector that matches class names (`com/qihoo/util/…`) has a short
shelf life: rename the package and it is gone. So the *primary* recovery path
does not depend on recognising anything.

The insight is that a packer's options are constrained by the platform. To get
code into a running process on Android you must reach one of:

| API | shape |
|---|---|
| `new DexClassLoader(path, …)` | a file you wrote |
| `new PathClassLoader(path, …)` | a file you wrote |
| `new InMemoryDexClassLoader(buf)` | bytes in memory |
| `DexFile.loadDex(path, …)` | a file you wrote |
| `Security.loadClass(name)` / `Class.forName` | a name, after a loader exists |

That is the whole interface. `unhusk` intercepts those five and watches the
bytes that flow into them. Whatever the shell looks like, it must eventually
call one of these with a valid DEX — so we get the payload without knowing the
packer's name.

Static fingerprints (`heuristics.rs`) still exist, but only as *triage*: they
raise a prior so the pipeline spends budget on the right classes. They are
never the basis of a finding.

### Watch the write, not the load

The `DexClassLoader` call is too late to see the plaintext in some packers: the
DEX is decrypted, written, and the path is passed as a constant. Both halves
are recorded:

* every `FileOutputStream.write` of a buffer whose head is `dex\n035` is
  registered in `pending_files`;
* every `DexClassLoader`/`PathClassLoader` construction looks the path up in
  the virtual filesystem.

So a payload is recovered whether it is loaded from a file, from memory, or
from a path that was only ever a string.

## 2. The interpreter stops rather than guesses

There is a temptation to make an interpreter "best effort": an unknown opcode
does something harmless and execution continues. That is worse than useless for
malware analysis, because the trace then contains behaviour the sample never
performed, indistinguishable from what it did.

Every unimplemented construct here is a typed stop (`StopReason::Unsupported`)
that carries the opcode and PC. The report surfaces it as a caveat. If a
finding depends on a branch we could not evaluate, the caveat says so.

The same rule applies in the native emulator: a decoder that does not recognise
an encoding returns the raw instruction word in the error, not a zero.

## 3. Lazy class initialisation is not optional

The first version of this interpreter did not implement `<clinit>`, and a
packer fixture silently did nothing: its key and payload were assigned in the
static initialiser, and every `sget` read the default null.

Dalvik (via ART) runs `<clinit>` before the first *active use* of a class:
a static field read or write, a static method call, or `new-instance`. The
implementation has to honour that, including the intermediate state a static
initialiser sees when it touches its own class (`S_INIT`), or recursive
initialisation loops forever.

Implementation detail worth knowing when touching this: when `<clinit>` is
pushed it goes on *top* of the frame stack, so the instruction that triggered
it must be rewound **in the caller's frame**. `rewind_frame(depth, pc)` takes
the depth explicitly for this reason — `rewind_one` (the obvious API) rewinds
the initialiser instead.

Constant *array* statics need separate care: a `static final byte[] KEY = {…}`
lives in the class's `static_values` table, not in any method body. Nothing
executes to build it, so it is materialised on first read
(`materialise_encoded`).

## 4. Evasion: answer the check, then watch what it gates

Anti-analysis code is not an obstacle to route around; it is *the first
finding*. Three mechanisms:

**A coherent profile.** `pixel_profile()` is internally consistent: the
fingerprint contains the device name, the ABI list matches `cpuinfo`, the SIM
has an operator, sensors exist. Cross-checks pass.

**A comparison pass.** `naive_emulator_profile()` is a deliberately obvious
emulator. Running both and diffing tells you exactly which reads the sample
used to decide, because the *value* differed. The report prints
`MODEL: "Pixel 6" vs "sdk"` — the evidence that the check exists, independent
of whether the payload fired.

**A clock sweep.** Date-gated payloads need several windows. The pipeline runs
`[0, +1y, +3y, -1y]` by default and unions the traces; deduplication by
`(kind, caller, subject, args, result)` keeps four passes from producing four
copies of every line.

The remaining limit, stated in the report: if a check depends on state we
cannot model (a real accelerometer trace over time, a specific Wi-Fi network
list), the sample may still refuse to proceed.

## 5. Native decryptors

The AArch64 emulator exists for one job: run a compiled byte transformation.
The instruction set implemented is exactly what `clang -O1` emits for
XOR/RC4/AES-shaped loops — verified against real compiler output
(`crates/vm/tests/fixtures/xor-decrypt-aarch64.o`, and `fixtures/native/` for
the JNI path).

Two mechanisms make JNI work without implementing JNI:

* **Symbol resolution.** `find_export` reads `.dynsym`/`.symtab` for the
  mangled `Java_pkg_Class_method` name, and `Code::from_elf_at` picks the
  executable segment that *contains* it — not the first one, which on a real
  `.so` is `.init` and silently emulates the wrong code.
* **Argument write-back.** A native decryptor typically returns `void` and
  modifies its array argument in place. The Java array is only unencrypted if
  the bytes are copied back from the emulated address space after the call.
  Without that step, the classloader loads ciphertext.

When the emulator stops (`Unsupported`), the report says which instruction and
where. An incomplete native run is a *caveat on a finding*, never silence.

## 6. Budget and determinism

A queue of tens of thousands of samples cannot let one sample monopolise a
worker. `Limits` bounds instructions, wall time, call depth, heap objects,
allocation size, APK bytes read, method count, loop iterations and native
steps. The instruction counter is polled every retired instruction and the
clock every 16k, so the bound is tight without being a timer in the hot path.

Determinism comes from three things: an explicit `seed`, a virtual clock that
advances with execution rather than wall time, and stable iteration order
(`BTreeMap`/explicit sorts) everywhere the order could leak into output. The
test `analysis_is_deterministic` pins this.

## 7. Provenance: why a string is suspicious

A URL that appears as a constant in the APK is weak evidence — it may be
unused. A URL assembled from a decrypted buffer is strong evidence that the
code is alive and doing something the static view cannot see.

`Provenance` is a coarse taint: `Constant`, `Built` (string assembly),
`PackedData` (read from the APK), `Decoded` (crypto/decoding output),
`Network`, `Device`. It flows through heap objects, so a report line can say
"body provenance: built+const" — meaning the request body was constructed at
runtime, not lifted from the file. Findings rank higher when their data is
runtime-derived for exactly this reason.

## 8. Where false positives come from, and how the code avoids them

Ranked by how often they bite:

1. **Benign apps doing scary-looking things.** `getInstalledPackages` is normal
   for a package manager app. So API *presence* is triage, not a finding. A
   finding requires the call to have *happened* during the run, with the
   observed arguments.
2. **Loops inflating the trace.** `record_egress` dedupes by URL and body;
   `Build.*` reads are recorded once per property per run; switch/fill-array
   payloads are not instructions.
3. **Grammar false positives.** `java/lang/ref/Reference` is not `Runtime`
   reflection; the framework dispatch matches on class and method, not a
   substring.
4. **The model filling in defaults.** A method the model does not implement
   returns 0/null and is counted as *unmodelled*; the report's caveat section
   aggregates those counts so a reader knows how much of the run was real.

## 9. Things deliberately left out

* **No full ART compliance.** Verification, JIT, `invoke-custom` (lambdas) and
  `invoke-polymorphic` (method handles) are not implemented. Kotlin-heavy
  samples will stop early with an explicit reason. This is a coverage choice,
  not an oversight: implementing `invoke-custom` correctly means implementing
  `MethodHandle` semantics, and a half-version would produce wrong traces.
* **No real network.** Egress is recorded and never sent. Running attacker
  infrastructure from an analysis box is a policy decision, not a default.
* **No APK signature verification.** It matters for tamper detection, but it
  is not on the path to "what does this code do", and the time is better spent
  on execution.
