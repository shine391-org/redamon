#!/usr/bin/env python3
"""Build a proxy-capable Kiterunner from the pinned v1.0.2 release.

The upstream release rejects ``--proxy`` and its fasthttp clients have no
dialer hook. This script copies the release, applies a minimal source patch to
the two client constructors plus the redirect loop, adds the CLI flag, and
writes a reproducible binary (``-trimpath``, fixed build directory, pinned
source hash). It does not vendor the upstream tree; the release is fetched at
build time and the local patch stays in this directory.

Supply-chain rules:
  * the default release URL must match RELEASE_SHA256 exactly;
  * ``--release-url`` is an explicit opt-in (``--allow-unpinned-release``) and
    is never silently trusted;
  * every archive is extracted through ``tar_safe.safe_extract_tar``, which
    rejects traversal, absolute paths and escaping symlink/hardlink targets.
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
RELEASE_SHA256 = "d553ed6a063b1a65bc72060be137b89d7c48f4da6ebf4fe46057807a5aa3d069"
LOCAL = Path(__file__).resolve().parent
PATCH_PKG = LOCAL / "kiterunner_patch" / "pkg" / "http"

try:
    from tar_safe import safe_extract_tar
except ImportError:  # direct execution from another cwd
    sys.path.insert(0, str(LOCAL))
    from tar_safe import safe_extract_tar


def download(url: str, dest: Path, expected_sha256: str | None = None) -> str:
    """Fetch ``url`` to ``dest`` and return its sha256.

    When ``expected_sha256`` is given the payload is verified BEFORE it is
    written, so a substituted archive can never reach the build step.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "RedAmon/1.0"})
    with urllib.request.urlopen(req, timeout=60) as response:
        payload = response.read()
    if len(payload) < 1024:
        raise RuntimeError("release archive too small")
    digest = hashlib.sha256(payload).hexdigest()
    if expected_sha256 and digest != expected_sha256:
        raise RuntimeError(
            f"release archive sha256 mismatch: got {digest}, want {expected_sha256}")
    dest.write_bytes(payload)
    return digest


def _require(text: str, old: str, what: str) -> None:
    if old not in text:
        raise RuntimeError(f"upstream {what} shape changed; patch must be reviewed")


def apply_patch(root: Path) -> None:
    client = root / "pkg" / "http" / "client.go"
    text = client.read_text()

    # --- primary HostClient: install the capture dialer ----------------------
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
\t\t// proxyDialFunc never returns nil when a proxy is configured: an
\t\t// invalid URL yields an always-error dial function, so the client
\t\t// cannot fall back to a direct connection carrying X-Redamon-Ctx.
\t\tc.Dial = proxyDialFunc(tls)
\t}
\treturn c
}

var proxyURL string

func SetProxyURL(v string) { proxyURL = v }'''
    _require(text, old, "NewHTTPClient")
    text = text.replace(old, new)

    # --- Config keeps a plaintext and a TLS backup client --------------------
    old = "\tbackupClient *BackupClient\n"
    new = "\tbackupClient    *BackupClient\n\tbackupTLSClient *BackupClient\n"
    _require(text, old, "Config.backupClient field")
    text = text.replace(old, new)

    old = '''func (c *Config) BackupClient() *BackupClient {
\tif c.backupClient == nil {
\t\tc.backupClient = &BackupClient{
\t\t\tReadTimeout:              c.Timeout,
\t\t\tWriteTimeout:             c.Timeout,
\t\t\tTLSConfig:                defaultTLSConfig,
\t\t\tNoDefaultUserAgentHeader: true,
\t\t}
\t}
\treturn c.backupClient
}'''
    new = '''func (c *Config) BackupClient() *BackupClient {
\tif c.backupClient == nil {
\t\tc.backupClient = &BackupClient{
\t\t\tReadTimeout:              c.Timeout,
\t\t\tWriteTimeout:             c.Timeout,
\t\t\tTLSConfig:                defaultTLSConfig,
\t\t\tNoDefaultUserAgentHeader: true,
\t\t}
\t\tif proxyURL != "" {
\t\t\tc.backupClient.Dial = proxyDialFunc(false)
\t\t}
\t}
\treturn c.backupClient
}

// BackupTLSClient is the generic client for redirects whose next hop is
// HTTPS. It uses the CONNECT dialer and lets fasthttp perform the target TLS
// handshake over the raw tunnel; a plain BackupClient would instead send a TLS
// ClientHello straight at the proxy for non-443 ports.
func (c *Config) BackupTLSClient() *BackupClient {
\tif c.backupTLSClient == nil {
\t\tc.backupTLSClient = &BackupClient{
\t\t\tReadTimeout:              c.Timeout,
\t\t\tWriteTimeout:             c.Timeout,
\t\t\tTLSConfig:                defaultTLSConfig,
\t\t\tNoDefaultUserAgentHeader: true,
\t\t}
\t\tif proxyURL != "" {
\t\t\tc.backupTLSClient.Dial = proxyDialFunc(true)
\t\t}
\t}
\treturn c.backupTLSClient
}'''
    _require(text, old, "Config.BackupClient")
    text = text.replace(old, new)

    old = '''func (c *Config) ResetBackupClient() {
\tif c.backupClient != nil {
\t\tc.backupClient.ReadTimeout = c.Timeout
\t\tc.backupClient.WriteTimeout = c.Timeout
\t}
}'''
    new = '''func (c *Config) ResetBackupClient() {
\tif c.backupClient != nil {
\t\tc.backupClient.ReadTimeout = c.Timeout
\t\tc.backupClient.WriteTimeout = c.Timeout
\t}
\tif c.backupTLSClient != nil {
\t\tc.backupTLSClient.ReadTimeout = c.Timeout
\t\tc.backupTLSClient.WriteTimeout = c.Timeout
\t}
}'''
    _require(text, old, "Config.ResetBackupClient")
    text = text.replace(old, new)

    # --- redirect loop: pick the plaintext or TLS backup client per hop ------
    old = '''\t\tif backupClient {
\t\t\tif err = config.BackupClient().Do(fastreq, fastresp); err != nil {
\t\t\t\treturn ret, err
\t\t\t}
\t\t} else {'''
    new = '''\t\tif backupClient {
\t\t\tbc := config.BackupClient()
\t\t\t// A plaintext hop must be sent as an ordinary forward-proxy
\t\t\t// request so the capture proxy can strip X-Redamon-Ctx; a TLS
\t\t\t// hop needs CONNECT. Pick the client from the hop's scheme.
\t\t\tif bytes.Equal(fastreq.URI().Scheme(), bHTTPS) {
\t\t\t\tbc = config.BackupTLSClient()
\t\t\t}
\t\t\tif err = bc.Do(fastreq, fastresp); err != nil {
\t\t\t\treturn ret, err
\t\t\t}
\t\t} else {'''
    _require(text, old, "redirect backup-client branch")
    text = text.replace(old, new)

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
    shutil.copyfile(PATCH_PKG / "dialer_test.go", root / "pkg" / "http" / "redamon_proxy_dialer_test.go")
    shutil.copyfile(LOCAL / "kiterunner_patch" / "main.go", root / "cmd" / "kiterunner" / "main.go")


def build(src: Path, out: Path, proxy_env: dict) -> None:
    env = dict(os.environ)
    env.update(proxy_env)
    # Reproducible output: static pure-Go binary, no absolute source paths.
    env.setdefault("GOFLAGS", "-mod=mod")
    env.setdefault("CGO_ENABLED", "0")
    env.setdefault("GOTOOLCHAIN", "local")
    cmd = ["go", "build", "-trimpath", "-buildvcs=false", "-o", str(out), "./cmd/kiterunner"]
    subprocess.run(cmd, cwd=src, env=env, check=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--release-url", default=RELEASE)
    ap.add_argument("--allow-unpinned-release", action="store_true",
                    help="explicit opt-in to a --release-url that is not the pinned v1.0.2 archive")
    ap.add_argument("--keep-source", metavar="DIR",
                    help="copy the patched source tree to DIR after the build")
    args = ap.parse_args()
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    if args.release_url != RELEASE and not args.allow_unpinned_release:
        raise SystemExit(
            "--release-url points away from the pinned v1.0.2 archive; pass "
            "--allow-unpinned-release to override deliberately")

    # -trimpath makes randomized, race-free build directories reproducible.
    with tempfile.TemporaryDirectory(prefix="kr-build-") as td:
        base = Path(td) / "extract"
        base.mkdir()
        archive = Path(td) / "v1.0.2.tar.gz"
        digest = download(args.release_url, archive, expected_sha256=(
            RELEASE_SHA256 if args.release_url == RELEASE else None))
        with tarfile.open(archive, "r:gz") as tar:
            safe_extract_tar(tar, base)
        src = next(p for p in base.iterdir() if p.is_dir())
        apply_patch(src)
        build(src, out, {})
        print(f"kr-capture sha256={hashlib.sha256(out.read_bytes()).hexdigest()}")
        print(f"source sha256={digest}")
        if args.keep_source:
            dest = Path(args.keep_source).resolve()
            if dest.exists():
                raise RuntimeError("--keep-source destination must not already exist")
            shutil.copytree(src, dest)
            print(f"source kept at {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())