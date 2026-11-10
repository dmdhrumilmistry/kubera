#!/usr/bin/env python3
"""Render the package manager manifests for one kubera release.

Reads the templates under packaging/templates/ (Homebrew, Scoop, winget,
AUR), fills in the version and the SHA-256 of each release archive, and
writes the result to --out. The checksums come from the release's own
`<archive>.sha256` files in --assets; when the archive itself is there too
(always, with --require-archives) it is hashed and must match, so a
manifest can never point at bytes other than the published ones.

    python3 -I scripts/render-packages.py --version 0.2.0 \\
        --assets dist/ --out packaging/ [--require-archives] [--tarball x.tar.gz]

Placeholders: @VERSION@, @SHA256:<target>@ (lowercase hex) and
@SHA256UPPER:<target>@ (uppercase, winget's convention).
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import sys
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER = re.compile(r"@(VERSION|SHA256|SHA256UPPER)(?::([A-Za-z0-9_.-]+))?@")
LEFTOVER = re.compile(r"@(VERSION|SHA256[A-Z]*)[^@\s]*@")


def fail(msg: str) -> None:
    print(f"render-packages: error: {msg}", file=sys.stderr)
    sys.exit(1)


def asset_name(target: str) -> str:
    ext = "zip" if "windows" in target else "tar.gz"
    return f"kubera-{target}.{ext}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def published_sum(assets: Path, target: str, require_archive: bool) -> str:
    name = asset_name(target)
    sum_file = assets / f"{name}.sha256"
    if not sum_file.is_file():
        fail(f"missing {sum_file}")
    # `<hex>  <name>`; Windows writes CRLF line endings.
    fields = sum_file.read_text(encoding="ascii", errors="strict").split()
    if not fields or not HEX64.match(fields[0].lower()):
        fail(f"{sum_file} does not start with a SHA-256")
    if len(fields) > 1 and fields[1].lstrip("*") != name:
        fail(f"{sum_file} names {fields[1]}, expected {name}")
    expected = fields[0].lower()
    archive = assets / name
    if archive.is_file():
        actual = sha256_file(archive)
        if actual != expected:
            fail(f"{name}: sha256 {actual} does not match {sum_file.name} ({expected})")
    elif require_archive:
        fail(f"missing {archive}")
    return expected


def render(text: str, version: str, sums: dict[str, str], source: Path) -> str:
    def sub(m: re.Match[str]) -> str:
        kind, target = m.group(1), m.group(2)
        if kind == "VERSION":
            return version
        if target is None or target not in sums:
            fail(f"{source}: unknown target in {m.group(0)}")
        return sums[target].upper() if kind == "SHA256UPPER" else sums[target]

    out = PLACEHOLDER.sub(sub, text)
    left = LEFTOVER.search(out)
    if left:
        fail(f"{source}: unresolved placeholder {left.group(0)}")
    return out


def targets_in(templates: Path) -> set[str]:
    found: set[str] = set()
    for path in templates.rglob("*"):
        if path.is_file():
            for m in PLACEHOLDER.finditer(path.read_text(encoding="utf-8")):
                if m.group(2):
                    found.add(m.group(2))
    return found


def write_tarball(out: Path, files: list[Path], tarball: Path, version: str) -> None:
    """A reproducible tar.gz of the rendered tree (fixed order, owner, mtime)."""
    buf = io.BytesIO()
    prefix = f"kubera-packaging-v{version}"
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(files):
            data = path.read_bytes()
            info = tarfile.TarInfo(f"{prefix}/{path.relative_to(out).as_posix()}")
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    with tarball.open("wb") as f:
        with gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0) as gz:
            gz.write(buf.getvalue())


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", required=True, help="release version, e.g. 0.2.0")
    ap.add_argument("--assets", required=True, type=Path, help="directory with the release's .sha256 files (and archives)")
    ap.add_argument("--out", required=True, type=Path, help="output directory")
    ap.add_argument("--templates", type=Path, default=REPO_ROOT / "packaging" / "templates")
    ap.add_argument("--require-archives", action="store_true", help="hash the archives themselves, not only the .sha256 files")
    ap.add_argument("--tarball", type=Path, help="also write the rendered tree to this .tar.gz")
    args = ap.parse_args()

    version = args.version.removeprefix("v")
    if not VERSION_RE.match(version):
        fail(f"not a release version: {args.version}")
    if not args.templates.is_dir():
        fail(f"no templates directory {args.templates}")

    sums = {
        t: published_sum(args.assets, t, args.require_archives)
        for t in sorted(targets_in(args.templates))
    }

    written: list[Path] = []
    for src in sorted(p for p in args.templates.rglob("*") if p.is_file()):
        rel = src.relative_to(args.templates)
        dest = args.out / rel
        text = render(src.read_text(encoding="utf-8"), version, sums, rel)
        if dest.suffix == ".json":
            json.loads(text)  # Scoop rejects invalid JSON; fail here instead.
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8", newline="\n")
        written.append(dest)
        print(f"rendered {dest}")

    if args.tarball:
        write_tarball(args.out, written, args.tarball, version)
        print(f"wrote {args.tarball}")


if __name__ == "__main__":
    main()
