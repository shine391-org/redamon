"""The CypherFix sockets' fixed error text and their readable refusal.

A raw exception never reaches the tab (`cypherfix_errors` explains why); what
does is a fixed sentence, a refusal our own webapp wrote, and a close code and
reason the browser can actually read.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_errors import reject_websocket, safe_error  # noqa: E402


class _Socket:
    def __init__(self):
        self.events = []

    async def accept(self):
        self.events.append(("accept",))

    async def close(self, code=1000, reason=""):
        self.events.append(("close", code, reason))


def test_a_ticket_refusal_is_accepted_then_closed_with_its_reason():
    # Closed before accept, the browser sees 1006 and no reason at all.
    socket = _Socket()
    asyncio.run(reject_websocket(socket, "missing or invalid ticket"))
    assert socket.events == [("accept",), ("close", 1008, "missing or invalid ticket")]


def test_a_cross_site_page_never_gets_a_socket():
    socket = _Socket()
    asyncio.run(reject_websocket(socket, "disallowed origin"))
    assert socket.events == [("close", 1008, "")]


def test_a_webapp_reason_follows_the_fixed_sentence():
    message = safe_error("authorize_failed", reason="A version activation is in progress.")
    assert message == ("The triage run could not be authorised and did not start. "
                       "A version activation is in progress.")


def test_every_publish_refusal_class_has_a_sentence():
    for code in ("publish_refused", "agent_lost", "unknown_run", "stopped"):
        assert "Something went wrong" not in safe_error(code), code


def test_a_remediation_that_could_not_be_loaded_is_not_reported_missing():
    assert safe_error("remediation_not_found", codefix=True) == "Remediation not found"
    assert "could not be loaded" in safe_error("remediation_load_failed", codefix=True)
