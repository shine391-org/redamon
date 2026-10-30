"""A confirmation the model meant to record but wrote as an actionable line.

Only an `output_analysis.chain_findings` entry writes a finding, and with
`related_finding_ids` its CONFIRMS edge. A model that writes "Record X as
vulnerability_confirmed" under `actionable_findings` instead keeps a note with
no id and records nothing, silently. The route exposure agent campaign lost
proven leads this way. These lines are surfaced in the next prompt; nothing is
written on the model's behalf, because a guess at its intent is not a proof.
"""

from __future__ import annotations

import re
from typing import List, Optional

_INTENT = re.compile(r"^\s*record\b|\bvulnerability_confirmed\b", re.IGNORECASE)
_MAX_LINES = 5
_MAX_CHARS = 200


def unrecorded_confirmations(analysis) -> Optional[List[str]]:
    """The actionable lines that read as a confirmation to record, when the same
    analysis recorded no chain finding; None when there is nothing to say."""
    if analysis is None or getattr(analysis, "chain_findings", None):
        return None
    lines = [line[:_MAX_CHARS] for line in (getattr(analysis, "actionable_findings", None) or [])
             if isinstance(line, str) and _INTENT.search(line)]
    return lines[:_MAX_LINES] or None


def unrecorded_note(lines: List[str]) -> str:
    """The prompt section shown at the next iteration."""
    quoted = "\n".join(f"- {line}" for line in lines)
    return (
        "\n\n## A confirmation was NOT recorded\n\n"
        "Your last analysis wrote these under `actionable_findings` and recorded no "
        "`chain_findings` entry:\n"
        f"{quoted}\n"
        "That records NOTHING. A confirmation exists only as an "
        "`output_analysis.chain_findings` entry with `finding_type: \"vulnerability_confirmed\"`, "
        "`related_finding_ids: [\"<the exact id>\"]` and `confidence` 80 or more. If the proof is "
        "in hand, put that entry in THIS response.\n"
    )
