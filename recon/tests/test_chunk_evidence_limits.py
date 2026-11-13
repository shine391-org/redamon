"""Tests for chunk evidence file size limits and boundary behavior."""
import json
import os
from pathlib import Path
import pytest

from recon.helpers.chunk_evidence import (
    MAX_FILE,
    EvidenceError,
    read_json,
)


def test_default_max_file_is_at_least_1gb():
    assert MAX_FILE >= 1024 * 1024 * 1024


def test_read_json_respects_custom_maximum(tmp_path):
    test_file = tmp_path / "test.json"
    test_file.write_text(json.dumps({"key": "value"}))
    # File size is ~16 bytes; if maximum=5, should raise EvidenceError
    with pytest.raises(EvidenceError, match="artifact_unreadable"):
        read_json(test_file, maximum=5)
    # If maximum=50, should succeed
    res = read_json(test_file, maximum=50)
    assert res == {"key": "value"}


def test_read_json_supports_string_path(tmp_path):
    test_file = tmp_path / "str_path.json"
    test_file.write_text(json.dumps({"foo": "bar"}))
    res = read_json(str(test_file))
    assert res == {"foo": "bar"}


def test_read_json_supports_artifacts_over_32mb(tmp_path):
    test_file = tmp_path / "large_artifact.json"
    # Create a dummy valid JSON structure with large padding (> 33MB)
    padding = "x" * (33 * 1024 * 1024)
    data = {"padding": padding, "status": "ok"}
    test_file.write_text(json.dumps(data))
    
    assert test_file.stat().st_size > 32 * 1024 * 1024
    
    # With default MAX_FILE (1GB), reading should succeed completely
    res = read_json(test_file)
    assert res["status"] == "ok"
    assert len(res["padding"]) == 33 * 1024 * 1024
