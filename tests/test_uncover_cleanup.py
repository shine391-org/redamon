"""Uncover owns and cleans its Docker child on every wrapper exit."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys

from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'recon' / 'main_recon_modules'))
import uncover_enrich as u

ROW = {'source': 'fixture', 'ip': '198.51.100.1', 'host': 'fixture.invalid', 'port': 443}


def invoke(tmp_path):
    return u._run_uncover_docker(['fixture.invalid'], ['fixture'], 'unused', 5, str(tmp_path))


def completed(cmd, code=0, stdout='', stderr=''):
    return subprocess.CompletedProcess(cmd, code, stdout, stderr)


def test_unique_name_and_stdout_survive_normal_cleanup(tmp_path):
    calls = []
    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return completed(cmd, stdout=json.dumps(ROW) if cmd[1] == 'run' else '')
    with mock.patch.object(u.subprocess, 'run', side_effect=run):
        assert invoke(tmp_path) == [ROW]
        assert invoke(tmp_path) == [ROW]
    runs = [cmd for cmd, _ in calls if cmd[1] == 'run']
    names = [cmd[cmd.index('--name')+1] for cmd in runs]
    assert len(set(names)) == 2
    assert all(name.startswith('redamon-uncover-') for name in names)
    assert all(cmd.count('--name') == 1 for cmd in runs)
    removals = [cmd for cmd, _ in calls if cmd[1] == 'rm']
    assert removals == [['docker', 'rm', '-f', name] for name in names]
    assert all('--rm' in cmd for cmd in runs)


def test_timeout_cleans_exact_child_and_keeps_only_complete_output(tmp_path):
    (tmp_path/'uncover_output.jsonl').write_text(json.dumps(ROW)+'\n'+ '{"ip":"truncated')
    calls = []
    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        if cmd[1] == 'run':
            raise subprocess.TimeoutExpired(cmd, u.UNCOVER_TIMEOUT)
        return completed(cmd)
    with mock.patch.object(u.subprocess, 'run', side_effect=run):
        assert invoke(tmp_path) == [ROW]
    name = calls[0][0][calls[0][0].index('--name')+1]
    # Upstream kills the timed-out child; our finally also confirms removal.
    # Both must refer to the exact UUID assigned to this invocation.
    assert calls[1][0] == ['docker', 'kill', name]
    assert calls[2][0] == ['docker', 'rm', '-f', name]
    assert calls[0][1]['timeout'] == u.UNCOVER_TIMEOUT
    assert calls[1][1]['timeout'] == 15
    assert calls[2][1]['timeout'] == 10


@pytest.mark.parametrize('error', [RuntimeError('fixture error'), OSError('fixture OS error')])
def test_exception_cleans_child(tmp_path, error):
    calls = []
    def run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[1] == 'run': raise error
        return completed(cmd)
    with mock.patch.object(u.subprocess, 'run', side_effect=run):
        assert invoke(tmp_path) == []
    assert calls[1] == ['docker', 'rm', '-f', calls[0][calls[0].index('--name')+1]]


@pytest.mark.parametrize('error', [KeyboardInterrupt(), SystemExit(15)])
def test_cancellation_cleans_and_still_propagates(tmp_path, error):
    calls = []
    def run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[1] == 'run': raise error
        return completed(cmd)
    with mock.patch.object(u.subprocess, 'run', side_effect=run):
        with pytest.raises(type(error)):
            invoke(tmp_path)
    assert calls[1] == ['docker', 'rm', '-f', calls[0][calls[0].index('--name')+1]]


def test_nonzero_tool_exit_preserves_partial_file_and_cleans(tmp_path):
    (tmp_path/'uncover_output.jsonl').write_text(json.dumps(ROW)+'\n')
    calls = []
    def run(cmd, **kwargs):
        calls.append(cmd)
        return completed(cmd, code=7 if cmd[1] == 'run' else 0)
    with mock.patch.object(u.subprocess, 'run', side_effect=run):
        assert invoke(tmp_path) == [ROW]
    assert calls[-1][1:3] == ['rm', '-f']


def test_missing_docker_still_returns_empty(tmp_path):
    with mock.patch.object(u.subprocess, 'run', side_effect=FileNotFoundError()) as run:
        assert invoke(tmp_path) == []
    assert run.call_count == 2  # initial launch + one cleanup, no missing-CLI retry


def test_cleanup_already_removed_is_success():
    result = completed([], code=1, stderr='Error response from daemon: No such container: fixture')
    with mock.patch.object(u.subprocess, 'run', return_value=result) as run:
        assert u._cleanup_uncover_container('redamon-uncover-fixture') is True
    assert run.call_count == 1


def test_transient_cleanup_failure_retries_exact_name():
    with mock.patch.object(u.subprocess, 'run', side_effect=[
        completed([], code=1, stderr='removal already in progress'), completed([])]) as run, \
         mock.patch.object(u.time, 'sleep'):
        assert u._cleanup_uncover_container('redamon-uncover-fixture') is True
    assert run.call_count == 2
    assert all(c.args[0] == ['docker', 'rm', '-f', 'redamon-uncover-fixture'] for c in run.call_args_list)


@pytest.mark.parametrize('failure', [
    completed([], code=1, stderr='PRIVATE_CANARY_DO_NOT_LOG'),
    subprocess.TimeoutExpired(['docker'], 10),
    OSError('PRIVATE_CANARY_DO_NOT_LOG'),
])
def test_cleanup_failure_is_bounded_and_reported_without_private_stderr(failure):
    output = io.StringIO()
    with mock.patch.object(u.subprocess, 'run') as run, \
         mock.patch.object(u.time, 'sleep'), contextlib.redirect_stdout(output):
        if isinstance(failure, Exception):
            run.side_effect = failure
        else:
            run.return_value = failure
        assert u._cleanup_uncover_container('redamon-uncover-fixture') is False
    assert run.call_count == 3
    assert 'Cleanup not confirmed' in output.getvalue()
    assert 'PRIVATE_CANARY' not in output.getvalue()
