"""Process-wide project execution guard shared by full runs and continuation."""
from contextlib import contextmanager
from pathlib import Path
import fcntl
import os


@contextmanager
def execution_lock(base, project):
    from recon.helpers.chunk_evidence import identifier, safe_file
    identifier(project)
    Path(base).mkdir(parents=True, exist_ok=True)
    path = safe_file(base, f".recon_{project}.execution-lock")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("project_execution_busy") from None
        yield
    finally:
        os.close(fd)
