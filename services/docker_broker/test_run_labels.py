"""Every tool container the broker creates carries the run it belongs to (plan 12.4).

The broker is one shared instance, so it cannot tell its callers apart. The recon
container names its run in an `X-Redamon-Run: <kind>:<project>:<run>` header,
which the Docker CLI sends on every call (recon/entrypoint.sh writes it into the
CLI's config.json). The broker stamps it as three labels on each create, and the
orchestrator then stops exactly one run's containers by label instead of every
container whose image name looks like a tool.

Run labels only ever come from the header: a client-supplied label that names
another run is overwritten by a valid header and dropped without one.
"""
import asyncio
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker  # noqa: E402

PROJECT = "cmproj0123456789abc"
RUN = "6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
RUN_LABELS = {"redamon.project_id", "redamon.run_id", "redamon.run_kind"}


def _cfg(labels=None):
    cfg = {"Image": "projectdiscovery/naabu:latest"}
    if labels is not None:
        cfg["Labels"] = dict(labels)
    return cfg


class TestParseRunHeader:
    @pytest.mark.parametrize("kind", ["full_recon", "partial_recon"])
    def test_a_well_formed_header_names_the_run(self, kind):
        assert broker.parse_run_header(f"{kind}:{PROJECT}:{RUN}") == (kind, PROJECT, RUN)

    @pytest.mark.parametrize("value", [
        None, "", "full_recon", f"full_recon:{PROJECT}", f"full_recon:{PROJECT}:{RUN}:extra",
        f"gvm:{PROJECT}:{RUN}",                      # not a recon run kind
        f"full_recon::{RUN}", f"full_recon:{PROJECT}:",
        f"full_recon:{PROJECT}:{RUN}\r\nX-Evil: 1",  # header smuggling
        f"full_recon:../{PROJECT}:{RUN}", f"full_recon:{PROJECT}:run id",
        f"full_recon:{PROJECT}:{'a' * 129}",          # over the per-part bound
        f"full_recon:{PROJECT}:{RUN}\n",              # a trailing newline is not a run id
    ])
    def test_anything_else_is_refused(self, value):
        assert broker.parse_run_header(value) is None


class TestStampRunLabels:
    def test_a_valid_header_adds_the_three_labels(self):
        cfg = broker.stamp_run_labels(broker.mark_owned(_cfg()), f"full_recon:{PROJECT}:{RUN}")
        assert cfg["Labels"] == {
            "redamon.broker-owned": "1",
            "redamon.project_id": PROJECT,
            "redamon.run_id": RUN,
            "redamon.run_kind": "full_recon",
        }

    def test_a_malformed_header_adds_none(self):
        cfg = broker.stamp_run_labels(broker.mark_owned(_cfg()), "full_recon:bad value")
        assert cfg["Labels"] == {"redamon.broker-owned": "1"}

    def test_client_run_labels_are_overwritten_by_the_header(self):
        forged = {"redamon.project_id": "other", "redamon.run_id": "other-run",
                  "redamon.run_kind": "partial_recon", "keep": "me"}
        cfg = broker.stamp_run_labels(_cfg(forged), f"full_recon:{PROJECT}:{RUN}")
        assert cfg["Labels"]["redamon.run_id"] == RUN
        assert cfg["Labels"]["redamon.project_id"] == PROJECT
        assert cfg["Labels"]["redamon.run_kind"] == "full_recon"
        assert cfg["Labels"]["keep"] == "me"

    def test_client_run_labels_without_a_header_are_dropped(self):
        forged = {"redamon.run_id": "other-run", "keep": "me"}
        cfg = broker.stamp_run_labels(_cfg(forged), None)
        assert not RUN_LABELS & set(cfg["Labels"])
        assert cfg["Labels"]["keep"] == "me"

    def test_labels_that_are_not_a_dict_are_replaced(self):
        cfg = broker.stamp_run_labels({"Image": "x", "Labels": ["a=b"]}, f"partial_recon:{PROJECT}:{RUN}")
        assert cfg["Labels"]["redamon.run_kind"] == "partial_recon"


# --- through the broker's own request handling --------------------------------

def _request(path, body_obj, extra_headers=()):
    body = json.dumps(body_obj).encode()
    lines = [f"POST {path} HTTP/1.1", "Host: docker", "Content-Type: application/json",
             f"Content-Length: {len(body)}", *extra_headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


async def _forwarded_create(raw: bytes) -> dict:
    """Send one request through broker.handle_client; return the create body the
    mock daemon received."""
    tmp = tempfile.mkdtemp(prefix="broker-runlbl-")
    upstream_sock, broker_sock = os.path.join(tmp, "up.sock"), os.path.join(tmp, "br.sock")
    received = []

    async def upstream(reader, writer):
        data = await asyncio.wait_for(reader.read(65536), timeout=2)
        received.append(data)
        body = b'{"Id":"deadbeef"}'
        writer.write(b"HTTP/1.1 201 Created\r\nContent-Length: " + str(len(body)).encode()
                     + b"\r\nConnection: close\r\n\r\n" + body)
        await writer.drain()
        writer.close()

    old = broker.UPSTREAM_SOCK
    broker.UPSTREAM_SOCK = upstream_sock
    try:
        up = await asyncio.start_unix_server(upstream, path=upstream_sock)
        br = await asyncio.start_unix_server(broker.handle_client, path=broker_sock)
        async with up, br:
            r, w = await asyncio.open_unix_connection(broker_sock)
            w.write(raw)
            await w.drain()
            await asyncio.wait_for(r.read(), timeout=3)
            w.close()
    finally:
        broker.UPSTREAM_SOCK = old
    [data] = received
    return json.loads(data.split(b"\r\n\r\n", 1)[1])


def test_the_create_the_daemon_receives_carries_the_run():
    raw = _request("/v1.43/containers/create",
                   _cfg({"redamon.run_id": "someone-else"}),
                   [f"X-Redamon-Run: partial_recon:{PROJECT}:{RUN}"])
    labels = asyncio.run(_forwarded_create(raw))["Labels"]
    assert labels["redamon.broker-owned"] == "1"
    assert labels["redamon.run_id"] == RUN
    assert labels["redamon.run_kind"] == "partial_recon"
    assert labels["redamon.project_id"] == PROJECT


def test_a_create_without_the_header_carries_no_run():
    labels = asyncio.run(_forwarded_create(_request("/v1.43/containers/create", _cfg())))["Labels"]
    assert labels == {"redamon.broker-owned": "1"}
