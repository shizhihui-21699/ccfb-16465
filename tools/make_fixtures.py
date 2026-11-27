#!/usr/bin/env python3
"""Build the synthetic APK corpus.

Run from anywhere; paths are resolved relative to this file. Requires javac,
d8, aapt2 and android.jar. The outputs land in fixtures/*.apk and are meant to
be committed, so the Rust test suite does not need the Android toolchain.
"""
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures"
HOME = os.environ.get("HOME", "")
JAVA_HOME = os.environ.get("JAVA_HOME") or "/opt/homebrew/opt/openjdk@21"
BT = Path(os.environ.get("ANDROID_BUILD_TOOLS", "/opt/homebrew/share/android-commandlinetools/build-tools/35.0.0"))
PLATFORM = Path(os.environ.get("ANDROID_JAR", "/opt/homebrew/share/android-commandlinetools/platforms/android-35/android.jar"))
WORK = ROOT / "target" / "fixtures-work"

def run(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd))
    subprocess.run([str(c) for c in cmd], check=True, **kw)

def javac(src: Path, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    files = [str(p) for p in src.rglob("*.java")]
    run([JAVA_HOME + "/bin/javac", "--release", "11", "-nowarn", "-d", out, "-cp", PLATFORM, *files])

def d8(cls: Path, out: Path, extra=()):
    out.mkdir(parents=True, exist_ok=True)
    classes = [str(p) for p in cls.rglob("*.class")]
    run([BT / "d8", "--release", "--min-api", "21", "--lib", PLATFORM, "--output", out, *extra, *classes])

def manifest_bin(manifest: Path, out: Path):
    """Compile the XML manifest to binary AXML via aapt2, then extract it.

    aapt2 can only write a full APK, so we build a throwaway one and pull the
    `AndroidManifest.xml` entry out of it. That keeps our APKs minimal (one DEX
    plus the manifest) which is exactly what the parser under test should face.
    """
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp_apk = out.parent / "manifest-src.apk"
    run([BT / "aapt2", "link", "-o", tmp_apk, "-I", PLATFORM, "--manifest", manifest])
    with zipfile.ZipFile(tmp_apk) as z:
        out.write_bytes(z.read("AndroidManifest.xml"))
    tmp_apk.unlink()

def make_apk(name: str, classes_dex: Path, manifest_bin_path: Path, extra_files=None):
    target = FIX / f"{name}.apk"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(classes_dex, "classes.dex")
        z.write(manifest_bin_path, "AndroidManifest.xml")
        for arc, src in (extra_files or {}).items():
            z.write(src, arc)
    print(f"built {target} ({target.stat().st_size} bytes)")

def main():
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    FIX.mkdir(exist_ok=True)

    # 1. hello: plain Java, no framework surface. Exercises the core loop.
    w = WORK / "hello"
    javac(FIX / "src" / "hello", w / "cls")
    d8(w / "cls", w / "dex")
    manifest_bin(FIX / "manifest" / "hello.xml", w / "AndroidManifest.xml")
    make_apk("hello", w / "dex" / "classes.dex", w / "AndroidManifest.xml")

    # 2. payload: compiled first, then embedded (encrypted) inside the packer.
    w = WORK / "payload"
    javac(FIX / "src" / "payload", w / "cls")
    d8(w / "cls", w / "dex")
    payload_dex = (w / "dex" / "classes.dex").read_bytes()
    key = b"AK7Z"
    blob = bytes(b ^ key[i % len(key)] for i, b in enumerate(payload_dex))
    arr = ",".join(f"(byte)0x{b:02x}" for b in blob)
    loader_src = (FIX / "src" / "packer" / "com/example/packer/Loader.java").read_text()
    loader_src = loader_src.replace("// BLOB_PLACEHOLDER", arr)
    packer_src = WORK / "packer-src"
    shutil.copytree(FIX / "src" / "packer", packer_src)
    (packer_src / "com/example/packer/Loader.java").write_text(loader_src)
    w = WORK / "packer"
    javac(packer_src, w / "cls")
    d8(w / "cls", w / "dex")
    manifest_bin(FIX / "manifest" / "packer.xml", w / "AndroidManifest.xml")
    make_apk("packer", w / "dex" / "classes.dex", w / "AndroidManifest.xml")

    # 3. evasive: uses android.os.Build and java.io.File probes.
    w = WORK / "evasive"
    javac(FIX / "src" / "evasive", w / "cls")
    d8(w / "cls", w / "dex")
    manifest_bin(FIX / "manifest" / "evasive.xml", w / "AndroidManifest.xml")
    make_apk("evasive", w / "dex" / "classes.dex", w / "AndroidManifest.xml")

if __name__ == "__main__":
    main()
