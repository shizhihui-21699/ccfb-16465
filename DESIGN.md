# unshroud — design

Goal: given an untrusted Android APK, in a few minutes on one core, recover what it
actually does *after* its packer/loader/anti-emulator gates, and hand an analyst a
short list of concrete malicious call chains with the decrypted evidence attached.

The central choice: **do not pattern-match packers or hard-code decryptors.** Run the
sample's own DEX bytecode in a Rust interpreter with a model of the Android/Java APIs,
inside a believable simulated device. Whatever the sample decrypts and executes, we
execute too; whatever it calls, we see. This generalises across packers because the
packer's own Java stub is the thing we feed our framework model to.

## Pipeline

```
APK --unzip--> classes*.dex (static)  + assets/libs (static triage)
                    |                          |
                    v                          v
             DEX parser (full format)    ELF/JNI scan, entropy triage
                    |
                    v
   +-- scenario runner (personas x virtual-time x sensor profiles) --+
   |        DEX interpreter + Android/Java framework hooks            |
   |        - virtual clock, scheduler (Handler/Timer/Alarm)         |
   |        - dynamic class loading -> parse decrypted DEX in memory |
   |        - reflection, crypto, Base64, String/IO/network models   |
   |        - dynamic taint: sources (IMEI, contacts, SMS, files...) |
   |          -> sinks (HTTP, SMS, exec, native, dexload, file write)|
   |        - call-stack snapshots at every sink; evasion-check log   |
   +-----------------------------------------------------------------+
                    |
                    v
        ranking -> JSON report + analyst markdown + unpacked DEX dumps
```

## Why scenarios

Anti-analysis gates are usually disjunctions of cheap predicates: emulator
fingerprints, wall-clock windows, sensor presence, battery level, installed-package
filters. A single run can only take one branch. The runner executes a small, bounded
set of scenarios (realistic personas, time sweep, sensor movement, "forced-clean" and
"detected" device answers), each with its own step/time slice, then merges findings.
A finding seen in any scenario is reported with the scenario that produced it; a
detection predicate that changed the branch is reported as an evasion check, because
that is itself intelligence.

## Taint model

Taint bits attach to registers, heap fields, arrays and string objects. Framework
"source" hooks (telephony, location, contacts, ...) mint bits; string/crypto/array
operations union them (so a URL built by concatenating IMEI into a string is tainted);
"sink" hooks (HTTP openConnection/socket connect, SmsManager.send*, Runtime.exec,
native calls, file writes, DexClassLoader) record the tainted payload plus the current
interpreter call stack. The result is a path such as:

  `Lcom/x/Main;->onCreate` -> `Lcom/x/b;->a` -> (decrypted) `http://.../gate?i=IMEI` -> `HttpURLConnection.connect`

Taint is dynamic and only as good as the hooks, so findings carry an evidence trail
(decrypted strings, API responses) that an analyst can verify statically.

## Non-goals / honesty

- Native code is not executed. `.so` files are triaged (exports, JNI registration,
  strings, entropy); native calls made by Java are recorded with arguments and are
  reported as "native boundary" findings, not decoded.
- The framework model covers common malware-facing APIs, not all of Android. Unknown
  framework calls return typed defaults and are counted per class/method, so coverage
  gaps are visible in the report instead of silently changing control flow.
- Every sample runs against a hard deadline; partial results are always emitted and
  marked as such.

## What the implementation settled on

Some decisions were made during the build that are worth recording:

- **Host hooks take `&mut dyn Host` separately from the `Vm`.** This lets the
  framework model call *back* into app code — a `Runnable` posted to a `Handler`,
  an `AsyncTask` body, a reflective `Method.invoke` — without two mutable
  borrows of the machine. Memory-safety and reentrancy together are the reason
  this is Rust and not a subprocess.
- **The interpreter owns its register stack and frame pool.** A decryptor that
  calls a helper a million times does not allocate per call.
- **Dynamic images are registered with override priority.** Android's
  `DexClassLoader` is child-first, so the payload's class must beat the shell's
  decoy of the same name. `Registry::add_image(.., priority=true)` expresses
  that, and a unit test pins it.
- **Reflection resolves by shape, not only by exact prototype.** Packer shells
  do `cl.loadClass(x).getMethod(y, z).invoke(..)` and the descriptor recorded at
  lookup time can be approximate; a name + argument-count fallback keeps the
  chain alive.
- **Taint lives on both registers and heap objects.** A `String` from
  `getDeviceId()` carries its label on the object; the register holding the
  reference is usually clean. Sinks consult the union (`eff_taint`), which is why
  an IMEI concatenated into a URL survives `StringBuilder`.
- **Behaviour grouping is by endpoint, not by hit.** The analyst sees one row per
  C2 with a victim-count, not forty `connect()` rows.
- **Honesty is a tested property.** A test asserts that an unmodelled API shows
  up in the report's Coverage section and that an empty result renders as
  "No malicious behaviour was observed" rather than as a clean bill of health.

## Verification

- The interpreter is checked against real `d8` output for arithmetic, control
  flow, exceptions (including nested `catch`), fields, arrays, statics and
  reflection.
- Crypto is checked against FIPS-197 AES, MD5/SHA-256 NIST vectors, and the
  canonical RC4 `Key`/`Plaintext` vector, both at the unit level and through
  Java code running in the VM.
- The unpacking path is exercised by synthetic packed APKs: XOR-in-asset,
  AES-in-asset, payload written to a nested file path, cross-dex calls, and a
  payload that overrides a shell decoy.
- Limits are tested: infinite loops, unbounded recursion, huge allocations, and
  ~3400 mutated DEX/bytecode inputs, none of which panic.
