# unshroud

A Rust tool that takes a suspicious Android APK, **executes its own bytecode**
inside a model of an Android device, follows any code the sample decrypts or
downloads into execution, and reports the concrete call chains that reach
dangerous sinks — in a few seconds per sample, with no real device, emulator, or
network access.

It is built for the case where static analysis stops dead: an app whose real
logic lives in an encrypted asset that a small Java stub decrypts and hands to
`DexClassLoader` at runtime, only after checking the device fingerprint, the
IMEI, and the wall clock.

```
unshroud sample.apk --markdown brief.md --json report.json --dump-dir unpacked/
```

## Why execute instead of pattern-matching packers

There are hundreds of Android packers, and new ones appear constantly. A tool
that recognises `libjiagu.so` or a known stub class only ever handles the shells
it was taught. Instead, unshroud runs the shell's *own* Java code against a
model of the framework: whichever decryption loop the packer uses, it runs; and
the moment the decrypted bytes are handed to `DexClassLoader`, `loadClass`, or a
reflective `Class.forName`, they are parsed as a DEX image, registered with
priority over the shell's decoy classes (matching Android's child-first loading),
and execution continues into the payload.

See [`DESIGN.md`](DESIGN.md) for the full rationale and the taint model.

## What it does

1. **Unpacks and triages the APK.** Zip entries, every `classes*.dex`, native
   libraries (JNI exports, anti-analysis strings), the binary manifest, and
   embedded payloads (raw DEX, nested APKs, Base64-of-DEX, high-entropy blobs).
2. **Runs the sample in a Dalvik interpreter.** Full instruction set, real
   exceptions with `try`/`catch` unwinding, virtual dispatch, static
   initialisers, and a framework model covering crypto (AES/ECB/CBC/CTR,
   RC4, MD5/SHA, HMAC, Base64), string building, I/O, networking
   (`HttpURLConnection`, sockets, OkHttp), reflection, class loaders,
   `Handler`/`Thread.sleep` scheduling, SMS, telephony, location, sensors,
   packages, prefs, and JSON.
3. **Follows decrypted code.** Any DEX produced at runtime is parsed, linked
   across images, executed, and dumped for the analyst.
4. **Sweeps scenarios.** Each sample runs against several simulated devices
   (retail phone, cheap no-SIM "farm" phone), battery states and clock offsets,
   because anti-analysis gates are usually cheap predicates that a single run
   can only satisfy one way.
5. **Tracks taint.** Values from sensitive sources (IMEI, IMSI, location,
   contacts, SMS, clipboard, files) carry labels through strings, crypto,
   arrays and collections to sinks (HTTP, SMS, `exec`, dynamic loads, native
   calls). A finding names the data that reached the sink.
6. **Reports honestly.** Unmodelled framework calls are counted and listed, so
   an empty result is never mistaken for a clean verdict.

## Install and build

```sh
cargo build --release
```

The test suite needs `javac`, `d8` and `android.jar` to compile synthetic
samples; tests skip cleanly when they are absent.

```sh
cargo test            # 45 tests: interpreter, crypto vectors, unpacking, limits
```

## Usage

```
unshroud <APK>                     print the analyst brief and JSON
        --markdown <file>          write the brief to a file
        --json <file>              write the JSON report to a file
        --dump-dir <dir>           write recovered DEX images here
        --timeout-ms <n>           total wall-clock budget (default 240000)
        --step-limit <n>           instructions per scenario (default 12M)
        --max-scenarios <n>        device/time scenarios to run (default 4)
        --fast                     run only the single retail-device scenario
```

### Sample output

```
**Verdict:** high (packed code was unpacked and executed; network exfiltration observed)

### 1. Loads code at runtime (packed payload) (high)
- Sink: `Ldalvik/system/DexClassLoader;-><init>`
- Detail: loader created with paths=[/data/user/0/.../files/p.dex]
- Call chain:
  - `Lcom/example/packed/Shell;->attach(Landroid/content/Context;)V`

### 2. Sends device identifiers to a remote endpoint (high)
- Sink: `GET http://203.0.113.9/gate?d=354918476201935&lat=37.4...`
- Data involved: imei
- Call chain:
  - `Lcom/example/packed/Shell;->attach(Landroid/content/Context;)V`
    - `Lcom/example/payload/Exec;->fire(Landroid/content/Context;)V […/files/p.dex]`

## Recovering a payload for further analysis

`--dump-dir` writes every DEX image the sample produced at runtime. Those files
are ordinary DEX and can be handed to `jadx`, `baksmali`, or another instance of
unshroud. The report records each image's origin (which loader call, which
file path) and SHA-256.

## Safety

The sample is never extracted to a shared directory and is never executed as
native code. Its bytecode runs in an interpreter with:

- bounded instructions, wall-clock, call depth, heap bytes and object count;
- a virtual clock, so a six-hour delay costs milliseconds;
- an in-memory filesystem and a scripted network — **no request leaves the
  machine**;
- `System.exit` and process kills halt the scenario rather than the process;
- every parse is bounds-checked, and a malformed DEX becomes a finding, not a
  crash.

Native libraries are triaged statically (exports, JNI names, suspicious strings)
but their bodies are not executed; calls into them are reported as a native
boundary.

## Architecture

```
src/
  dex/          DEX parser (bounds-checked) and instruction decoder
  vm/
    interp.rs   the Dalvik interpreter, scheduling, exception unwinding
    registry.rs cross-image class/method/field linking with override priority
    heap.rs     strings, byte buffers, arrays and instances; taint-carrying
    env.rs      simulated device: identity, telephony, sensors, clock, network
    android/    the framework model, split by subsystem
      crypto.rs   AES/RC4/hashes/Base64 and key handling
      io.rs       streams, files, zip/jar
      net.rs      URL/HTTP/sockets/OkHttp
      reflect.rs  reflection and class loaders (the unpacking hook)
      system.rs   java.lang/util (strings, collections, JSON, exec)
      ui.rs       android.* (Build, telephony, sensors, intents, SMS, ...)
  apk.rs        APK unpacking, manifest parsing, ELF and payload triage
  scenario.rs   drives entry points and the virtual clock across personas
  analysis/     behaviour grouping, ranking, markdown rendering
```

## Limits

- The framework model covers the APIs malware commonly uses; an exotic API is
  answered with a typed default and listed under **Coverage**.
- Native code is not executed.
- Reflection is followed for normal `getMethod`/`invoke` chains; dynamic proxy
  synthesis is not modelled.
- Results are as complete as the sample's own code paths: a gate the scenarios
  never satisfy will keep a payload dormant, and the report will show the
  probes it made so the analyst can adjust.
