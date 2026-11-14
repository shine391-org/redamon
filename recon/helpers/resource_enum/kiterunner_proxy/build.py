#!/usr/bin/env python3
"""Build a proxy-capable Kiterunner from the pinned v1.0.2 release.

The upstream release rejects ``--proxy`` and its fasthttp clients have no
dialer hook. This script copies the release, applies a minimal source patch to
the two client constructors, adds the CLI flag, and writes a reproducible
binary. It does not vendor the upstream tree; the release is fetched at build
time and the local patch stays in this directory.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

RELEASE = "https://github.com/assetnote/kiterunner/archive/refs/tags/v1.0.2.tar.gz"
LOCAL = Path(__file__).resolve().parent
PATCH_PKG = LOCAL / "kiterunner_patch" / "pkg" / "http"
PATCH_CMD = LOCAL / "kiterunner_patch" / "cmd" / "kiterunner"


def download(url: str, dest: Path) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "RedAmon/1.0"})
    with urllib.request.urlopen(req, timeout=60) as response:
        payload = response.read()
    if len(payload) < 1024:
        raise RuntimeError("release archive too small")
    digest = hashlib.sha256(payload).hexdigest()
    dest.write_bytes(payload)
    return digest


def apply_patch(root: Path) -> None:
    client = root / "pkg" / "http" / "client.go"
    text = client.read_text()
    old = '''func NewHTTPClient(host string, tls bool) *HTTPClient {
\treturn &HTTPClient{
\t\tAddr:      host,
\t\tIsTLS:     tls,
\t\tTLSConfig: defaultTLSConfig,
\t}
}'''
    new = '''func NewHTTPClient(host string, tls bool) *HTTPClient {
\tc := &HTTPClient{Addr: host, IsTLS: tls, TLSConfig: defaultTLSConfig}
\tif proxyURL != "" {
\t\tif dialer, err := newProxyDialer(proxyURL, tls); err == nil {
\t\t\tc.Dial = dialer.Dial
\t\t}
\t}
\treturn c
}

var proxyURL string

func SetProxyURL(v string) { proxyURL = v }'''
    if old not in text:
        raise RuntimeError("upstream NewHTTPClient shape changed; patch must be reviewed")
    text = text.replace(old, new)
    old_backup = '''\t\tc.backupClient = &BackupClient{
\t\t\tReadTimeout:              c.Timeout,
\t\t\tWriteTimeout:             c.Timeout,
\t\t\tTLSConfig:                defaultTLSConfig,
\t\t\tNoDefaultUserAgentHeader: true,
\t\t}'''
    new_backup = old_backup + '''
\t\tif proxyURL != "" {
\t\t\tif dialer, err := newProxyDialer(proxyURL, false); err == nil {
\t\t\t\tc.backupClient.Dial = dialer.Dial
\t\t\t}
\t\t}'''
    if old_backup not in text:
        raise RuntimeError("upstream BackupClient shape changed; patch must be reviewed")
    text = text.replace(old_backup, new_backup)
    client.write_text(text)

    # Export the root command for the local main hook. Upstream keeps it
    # unexported, so the patch adds a narrow accessor rather than rewriting the
    # command tree.
    root_cmd_file = root / "cmd" / "kiterunner" / "cmd" / "root.go"
    root_text = root_cmd_file.read_text()
    if "var RootCmd = rootCmd" not in root_text:
        root_text += "\n\n// RootCmd is exported by the local proxy hook; upstream keeps rootCmd private.\nvar RootCmd = rootCmd\n"
        root_cmd_file.write_text(root_text)

    # The dialer and the CLI hook are local to this patch, not upstream files.
    shutil.copyfile(PATCH_PKG / "dialer.go", root / "pkg" / "http" / "redamon_proxy_dialer.go")
    shutil.copyfile(LOCAL / "kiterunner_patch" / "main.go", root / "cmd" / "kiterunner" / "main.go")


def build(src: Path, out: Path, proxy_env: dict) -> None:
    env = dict(os.environ)
    env.update(proxy_env)
    env.setdefault("GOFLAGS", "-mod=mod")
    subprocess.run(["go", "build", "-o", str(out), "./cmd/kiterunner"], cwd=src, env=env, check=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--release-url", default=RELEASE)
    ap.add_argument("--keep-source", action="store_true")
    args = ap.parse_args()
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kr-build-") as td:
        td = Path(td)
        archive = td / "v1.0.2.tar.gz"
        digest = download(args.release_url, archive)
        with tarfile.open(archive, "r:gz") as tar:
            base = td / "extract"
            base.mkdir()
            for member in tar.getmembers():
                target = (base / member.name).resolve()
                if base.resolve() not in target.parents and target != base.resolve():
                    raise RuntimeError("unsafe archive path")
                tar.extract(member, path=base)
        src = next(p for p in base.iterdir() if p.is_dir())
        apply_patch(src)
        proxy_env = {k: v for k, v in (
            ("HTTPS_PROXY", os.environ.get("HTTPS_PROXY", "")),
            ("HTTP_PROXY", os.environ.get("HTTP_PROXY", "")),
            ("NO_PROXY", os.environ.get("NO_PROXY", "")),
        ) if v}
        build(src, out, proxy_env)
        print(f"kr-capture sha256={hashlib.sha256(out.read_bytes()).hexdigest()}")
        print(f"source sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
