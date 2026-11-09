#!/usr/bin/env python3
"""Reproducible benchmark for kubera (and, when installed, trufflehog/gitleaks).

    python3 scripts/bench.py --fs DIR --git REPO [--out results.md]

Measures, per tool and corpus: wall time, peak memory (max RSS of the child)
and findings. Also builds a *planted* corpus of realistic fake secrets plus
decoys (documentation examples, placeholders, hashes, UUIDs) to count
detections and false positives. Every tool runs without verification so no
network is involved and results are comparable.

Competitors are optional: any of `trufflehog` / `gitleaks` found on PATH is
benchmarked with equivalent no-verification flags.
"""

import argparse
import json
import os
import random
import shutil
import string
import subprocess
import tempfile
import time

AN = string.ascii_letters + string.digits
HEX = "0123456789abcdef"


def rnd(alpha, n, rng):
    return "".join(rng.choice(alpha) for _ in range(n))


def planted_corpus(root, rng):
    """Write fake secrets (prefixes split so this file is never token-shaped)."""
    P = lambda *parts: "".join(parts)  # noqa: E731
    secrets = {
        "aws.env": (
            P("aws_access_key_id = AK", "IA", rnd("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16, rng))
            + "\n"
            + P("aws_secret_access_key = ", rnd(AN + "/+", 40, rng))
        ),
        "github.env": P("GITHUB_TOKEN=gh", "p_", rnd(AN, 36, rng)),
        "gitlab.yml": P("token: glp", "at-", rnd(AN, 20, rng)),
        "slack.sh": P("SLACK=xox", "b-", rnd("0123456789", 12, rng), "-", rnd("0123456789", 13, rng), "-", rnd(AN, 24, rng)),
        "stripe.py": P("stripe.api_key = 'sk_", "live_", rnd(AN, 32, rng), "'"),
        "npmrc": P("//registry.npmjs.org/:_authToken=np", "m_", rnd(AN, 36, rng)),
        "sendgrid.env": P("SENDGRID=S", "G.", rnd(AN, 22, rng), ".", rnd(AN, 43, rng)),
        "openai.env": P("OPENAI_API_KEY=sk-", "proj-", rnd(AN, 40, rng), "T3Blbk", "FJ", rnd(AN, 40, rng)),
        "anthropic.env": P("ANTHROPIC_API_KEY=sk-ant-", "api03-", rnd(AN, 93, rng), "AA"),
        "hf.env": P("HF_TOKEN=h", "f_", rnd(string.ascii_letters, 34, rng)),
        "do.env": P("DO_TOKEN=do", "p_v1_", rnd(HEX, 64, rng)),
        "pypirc": P("password = py", "pi-AgEIcHlwaS5vcmc", rnd(AN, 80, rng)),
        "shopify.env": P("SHOP=acme.myshopify.com\nTOKEN=sh", "pat_", rnd(HEX, 32, rng)),
        "linear.env": P("LINEAR=lin", "_api_", rnd(AN, 40, rng)),
        "postman.env": P("POSTMAN=PM", "AK-", rnd(HEX, 24, rng), "-", rnd(HEX, 34, rng)),
        "databricks.env": P("DATABRICKS_TOKEN=da", "pi", rnd(HEX, 32, rng)),
        "key.pem": P("-----BEGIN ", "RSA PRIVATE KEY-----\n", "\n".join(rnd(AN + "+/", 64, rng) for _ in range(6)), "\n-----END RSA PRIVATE KEY-----"),
    }
    decoys = {
        "doc-aws.md": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "placeholders.env": "GITHUB_TOKEN=${GITHUB_TOKEN}\nSTRIPE_KEY=<your-stripe-key>\nSLACK=xoxb-your-token-here\nNPM_TOKEN=npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "hashes.txt": "\n".join(rnd(HEX, 64, rng) for _ in range(20)) + "\n" + "\n".join(rnd(HEX, 40, rng) for _ in range(20)),
        "uuids.txt": "\n".join(f"{rnd(HEX,8,rng)}-{rnd(HEX,4,rng)}-{rnd(HEX,4,rng)}-{rnd(HEX,4,rng)}-{rnd(HEX,12,rng)}" for _ in range(20)),
        "base64.txt": "\n".join(rnd(AN + "+/", 76, rng) for _ in range(20)),
        "tests.py": "def test_token():\n    assert parse('ghp_short') is None\n    password = 'hunter2'\n",
        "lockfile.json": json.dumps({"integrity": "sha512-" + rnd(AN + "+/", 86, rng) + "==", "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz"}),
    }
    os.makedirs(os.path.join(root, "secrets"))
    os.makedirs(os.path.join(root, "decoys"))
    for n, c in secrets.items():
        open(os.path.join(root, "secrets", n), "w").write(c + "\n")
    for n, c in decoys.items():
        open(os.path.join(root, "decoys", n), "w").write(c + "\n")
    return len(secrets)


class Result:
    def __init__(self, stdout):
        self.stdout = stdout


def run(cmd):
    """Run `cmd`; return (result, seconds, peak RSS MiB) for that child only."""
    with tempfile.TemporaryFile("w+") as out:
        t0 = time.perf_counter()
        p = subprocess.Popen(cmd, stdout=out, stderr=subprocess.DEVNULL)
        _, _, usage = os.wait4(p.pid, 0)
        dt = time.perf_counter() - t0
        p.returncode = 0
        out.seek(0)
        return Result(out.read()), dt, usage.ru_maxrss / 1024.0  # KiB -> MiB


def tools(kubera):
    t = {
        "kubera": {
            "fs": lambda d: [kubera, "scan", "fs", d, "-f", "jsonl"],
            "git": lambda r: [kubera, "scan", "git", r, "-f", "jsonl"],
            "count": lambda out: sum(1 for l in out.splitlines() if l.strip().startswith("{")),
            "paths": lambda out: [json.loads(l)["location"].get("path", "") for l in out.splitlines() if l.strip().startswith("{")],
        }
    }
    if shutil.which("trufflehog"):
        t["trufflehog"] = {
            "fs": lambda d: ["trufflehog", "filesystem", d, "--no-verification", "--json", "--no-update"],
            "git": lambda r: ["trufflehog", "git", f"file://{os.path.abspath(r)}", "--no-verification", "--json", "--no-update"],
            "count": lambda out: sum(1 for l in out.splitlines() if '"DetectorName"' in l),
            "paths": lambda out: [
                json.dumps(json.loads(l).get("SourceMetadata", {}))
                for l in out.splitlines()
                if '"DetectorName"' in l
            ],
        }
    if shutil.which("gitleaks"):
        def gl(mode, target):
            rep = tempfile.mktemp(suffix=".json")
            cmd = ["gitleaks", mode, target, "--report-format", "json", "--report-path", rep, "--exit-code", "0", "--no-banner"]
            return cmd, rep

        t["gitleaks"] = {"fs": lambda d: gl("dir", d), "git": lambda r: gl("git", r)}
    return t


def count_gitleaks(rep):
    try:
        data = json.load(open(rep))
        return len(data), [f.get("File", "") for f in data]
    except Exception:
        return 0, []


def bench(name, spec, kind, target, rows, runs=1):
    """Warm-up once, then report the median of `runs` timed runs."""
    samples = []
    for i in range(runs + (1 if runs > 1 else 0)):
        built = spec[kind](target)
        cmd, rep = (built if isinstance(built, tuple) else (built, None))
        p, dt, mib = run(cmd)
        if runs > 1 and i == 0:
            continue  # warm-up: populate the page cache
        samples.append((dt, mib))
    dt = sorted(s[0] for s in samples)[len(samples) // 2]
    mib = max(s[1] for s in samples)
    if rep:
        n, paths = count_gitleaks(rep)
    else:
        n, paths = spec["count"](p.stdout), spec["paths"](p.stdout)
    rows.append((name, kind, target, dt, mib, n))
    return paths


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kubera", default="target/release/kubera")
    ap.add_argument("--fs", action="append", default=[])
    ap.add_argument("--git", action="append", default=[])
    ap.add_argument("--out")
    ap.add_argument("--runs", type=int, default=5, help="timed runs per scenario (median reported)")
    a = ap.parse_args()
    rng = random.Random(1109)
    rows = []
    ts = tools(a.kubera)

    planted = tempfile.mkdtemp(prefix="kubera-planted-")
    n_planted = planted_corpus(planted, rng)
    accuracy = []
    for name, spec in ts.items():
        paths = bench(name, spec, "fs", planted, [])
        hit = {os.path.basename(p) for p in paths if "/secrets/" in p or "secrets" in p}
        fp = sum(1 for p in paths if "decoys" in p)
        accuracy.append((name, len(hit), n_planted, fp))

    for name, spec in ts.items():
        for d in a.fs:
            bench(name, spec, "fs", d, rows, a.runs)
        for r in a.git:
            bench(name, spec, "git", r, rows, a.runs)

    # Incremental re-scans (kubera --state): full history once, then again
    # with nothing new, as a CI job or scheduled mass scan would.
    incremental = []
    for r in a.git:
        st = tempfile.mktemp(suffix=".json")
        base = [a.kubera, "scan", "git", r, "-f", "jsonl", "--state", st, "--state-policy", "always"]
        _, full, _ = run(base)
        again = sorted(run(base)[1] for _ in range(max(a.runs, 1)))[max(a.runs, 1) // 2]
        incremental.append((os.path.basename(r.rstrip("/")), full, again))
        os.unlink(st)

    out = ["| Tool | Corpus | Time | Peak memory | Findings |", "|---|---|---:|---:|---:|"]
    for name, kind, target, dt, mib, n in rows:
        out.append(f"| {name} | {kind}: `{os.path.basename(target.rstrip('/'))}` | {dt:.2f} s | {mib:.0f} MiB | {n} |")
    if incremental:
        out += ["", "| Repository | Full history scan | Re-scan, no new commits (`--state`) | Speedup |", "|---|---:|---:|---:|"]
        for name, full, again in incremental:
            out.append(f"| `{name}` | {full:.2f} s | {again:.3f} s | {full / max(again, 1e-6):.0f}x |")
    out += ["", "| Tool | Planted secrets found | Decoy false positives |", "|---|---:|---:|"]
    for name, hit, total, fp in accuracy:
        out.append(f"| {name} | {hit}/{total} | {fp} |")
    text = "\n".join(out)
    print(text)
    if a.out:
        open(a.out, "w").write(text + "\n")
    shutil.rmtree(planted, ignore_errors=True)


if __name__ == "__main__":
    main()
