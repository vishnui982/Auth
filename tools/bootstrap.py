"""Install checksum-pinned OPA/Lean locally, then check proofs and build the kernel."""
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def main():
    platform_key = (platform.system(), platform.machine())
    choices = {
        ("Darwin", "x86_64"): ("opa_darwin_amd64", "lean-4.33.1-darwin"),
        ("Darwin", "arm64"): ("opa_darwin_arm64", "lean-4.33.1-darwin_aarch64"),
        ("Linux", "x86_64"): ("opa_linux_amd64_static", "lean-4.33.1-linux"),
        ("Linux", "aarch64"): ("opa_linux_arm64_static", "lean-4.33.1-linux_aarch64"),
    }
    if platform_key not in choices:
        raise SystemExit(f"Unsupported platform: {platform_key}. Use a supported Linux environment.")
    opa_name, lean_name = choices[platform_key]
    pins = json.loads((ROOT / "tools/releases.json").read_text())
    cache = ROOT / "tmp/toolchains"
    cache.mkdir(parents=True, exist_ok=True)
    bindir = ROOT / "tools/bin"
    bindir.mkdir(exist_ok=True)
    for name in (opa_name, lean_name + ".tar.zst"):
        pin = pins[name]
        if not pin["digest"] or not pin["digest"].startswith("sha256:"):
            raise SystemExit("Missing release checksum")
        path = cache / name
        # Reuse the archive downloaded during initial development.
        legacy = ROOT / "tmp/lean.tar.zst"
        if not path.exists() and name == "lean-4.33.1-darwin.tar.zst" and legacy.exists():
            shutil.copyfile(legacy, path)
        if not path.exists():
            print(f"Downloading {name}", flush=True)
            urllib.request.urlretrieve(pin["url"], path.with_suffix(path.suffix + ".partial"))
            path.with_suffix(path.suffix + ".partial").rename(path)
        if sha(path) != pin["digest"]:
            raise SystemExit(f"Checksum mismatch: {path}")
        if name == opa_name:
            shutil.copyfile(path, bindir / "opa")
            (bindir / "opa").chmod(0o755)
        else:
            print("Extracting verified Lean toolchain", flush=True)
            subprocess.run(["tar", "--zstd", "-xf", str(path), "-C", str(ROOT / "tools")], check=True)
    for name in ("lean", "lake"):
        link = bindir / name
        if link.is_symlink():
            link.unlink()
        if not link.exists():
            link.symlink_to(Path("..") / lean_name / "bin" / name)
    subprocess.run([str(bindir / "lake"), "build"], cwd=ROOT / "proof", check=True)
    checked = subprocess.run([str(bindir / "lake"), "env", "lean", "Check.lean"],
                             cwd=ROOT / "proof", check=True, capture_output=True, text=True)
    print(checked.stdout)
    if "sorryAx" in checked.stdout:
        raise SystemExit("Unproved assumption in proof artifact")
    print("OPA and checked Lean kernel are ready.")


if __name__ == "__main__":
    main()
