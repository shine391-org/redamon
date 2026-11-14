"""Read shared recon evidence locally without importing scanner dependencies.

Docker mount sources are host paths used for spawning workers. Evidence readers
must instead use the orchestrator's own mounted recon directory.
"""
import importlib.util
from pathlib import Path


def recon_local_path():
    """Resolve the local recon tree in both container and repository layouts."""
    sibling = Path(__file__).resolve().parent.parent / "recon"
    return sibling if sibling.is_dir() else Path("/app/recon")


def recon_output_path():
    return recon_local_path() / "output"


def _load_contract(filename, module_name):
    # Only fixed stdlib-only leaf modules are loaded here. Importing through
    # recon.helpers would execute its scanner-heavy package __init__ first.
    source = recon_local_path() / "helpers" / filename
    spec = importlib.util.spec_from_file_location(module_name, source)
    if spec is None or spec.loader is None:
        raise ImportError("recon evidence reader unavailable")
    contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(contract)
    return contract


_contract = _load_contract("chunk_evidence.py", "_recon_chunk_evidence")
diagnostics = _contract.diagnostics
continuation_work = _contract.continuation_work
project_revision = _contract.project_revision
identifier = _contract.identifier
EvidenceError = _contract.EvidenceError


def read_manifest_in_context(*args, **kwargs):
    # Load lazily so unavailable manifests remain an explicit unknown response
    # in the API rather than preventing the orchestrator from starting.
    reader = _load_contract("planner_manifest.py", "_recon_planner_manifest")
    return reader.read_manifest_in_context(*args, **kwargs)
