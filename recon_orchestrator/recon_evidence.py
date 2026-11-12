"""Load the stdlib-only shared contract without importing scanner dependencies."""
import importlib.util
import os
from pathlib import Path

_source = Path(__file__).resolve().parent.parent / "recon/helpers/chunk_evidence.py"
if not _source.is_file():
    _source = Path(os.environ.get("RECON_PATH", "/app/recon")) / "helpers/chunk_evidence.py"
_spec = importlib.util.spec_from_file_location("_recon_chunk_evidence", _source)
_contract = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_contract)
diagnostics = _contract.diagnostics
continuation_work = _contract.continuation_work
project_revision = _contract.project_revision
identifier = _contract.identifier
EvidenceError = _contract.EvidenceError
