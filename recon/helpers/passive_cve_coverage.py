"""What a passive CVE lookup re-checked this run, told to the end-of-run prune.

Shodan, Netlas and CriminalIP answer per IP, from their own crawls. An IP the
run could not ask about brings no news, so its earlier CVEs must survive the
prune; an IP it did ask about prunes normally, which is how a CVE an IP no
longer carries goes away. A lookup that could ask about nothing (a refused
key, a crash, no IP at all) keeps its whole source. A lookup switched off by
configuration notes nothing, so its old findings are pruned.
"""
from __future__ import annotations

from typing import Iterable

from recon.helpers import circuit_breaker
from recon.helpers.finding_sources import PASSIVE_CVE_SOURCES


def note_cve_coverage(provider: str, module: str, queried: Iterable[str] = (),
                      checked: Iterable[str] = (), *, no_input: bool = False,
                      failed: bool = False, reached: bool | None = None,
                      reason: str = "") -> None:
    """Record which of `queried` IPs this lookup could not re-check. Never raises.

    `queried` are the IPs it set out to ask about: those its CDN and
    private-address filter dropped were decided, not skipped. `checked` are
    those whose answer it saw whole, "no data" included. `no_input` means
    there was no IP before that filter either. `reached` says the provider
    answered at all; it defaults to "some IP was checked", and a lookup whose
    every answer was cut short passes True, so its IPs are kept one by one
    rather than the whole source, which would then never be pruned.
    """
    # The provider names its one coverage gap; its other source values (which
    # API answered, older fallbacks) are cut with it.
    aliases = [s for s in PASSIVE_CVE_SOURCES.get(provider, ()) if s != provider]
    queried = {ip for ip in queried if ip}
    checked = set(checked) & queried
    if reached is None:
        reached = bool(checked)
    if failed or no_input or (queried and not reached):
        reason = reason or ("the lookup failed" if failed else "no IP to look up" if no_input
                            else "no IP could be looked up")
        circuit_breaker.note_degraded(module, sources=[provider], aliases=aliases, reason=reason)
        return
    missed = sorted(queried - checked)
    if missed:
        circuit_breaker.note_degraded(
            module, hosts=missed, host_source=provider, aliases=aliases,
            source_only_hosts=True, reason=reason or f"{len(missed)} IP(s) not looked up")
