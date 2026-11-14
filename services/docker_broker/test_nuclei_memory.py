"""The optional Nuclei memory cap must not relax other broker boundaries."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest import mock

SOURCE = Path(__file__).with_name('broker.py')
GIB = 1024 ** 3


def load(override='8g'):
    env = {'BROKER_TOOL_MEM_BYTES': '3g', 'BROKER_NUCLEI_MEM_BYTES': override,
           'BROKER_TOOL_PIDS': '512'}
    with mock.patch.dict(os.environ, env):
        spec = importlib.util.spec_from_file_location('isolated_broker_memory', SOURCE)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


class TestNucleiMemoryCeiling(unittest.TestCase):
    def test_shipped_nuclei_gets_eight_gib(self):
        b = load()
        for image in ('projectdiscovery/nuclei:latest',
                      'docker.io/projectdiscovery/nuclei:latest',
                      'index.docker.io/projectdiscovery/nuclei:latest'):
            with self.subTest(image=image):
                cfg = {'Image': image, 'HostConfig': {'NetworkMode': 'none'}}
                self.assertTrue(b.validate_create(cfg)[0])
                b.inject_limits(cfg)
                self.assertEqual(cfg['HostConfig']['Memory'], 8 * GIB)
                self.assertEqual(cfg['HostConfig']['PidsLimit'], 512)

    def test_other_tools_keep_three_gib(self):
        b = load()
        for image in ('projectdiscovery/httpx:latest', 'projectdiscovery/katana:latest',
                      'projectdiscovery/uncover:latest', 'alpine:latest'):
            with self.subTest(image=image):
                cfg = {'Image': image}
                self.assertTrue(b.validate_create(cfg)[0])
                self.assertEqual(b.inject_limits(cfg)['HostConfig']['Memory'], 3 * GIB)

    def test_explicit_lower_nuclei_limit_is_preserved(self):
        b = load()
        cfg = {'Image': 'projectdiscovery/nuclei:latest', 'HostConfig': {'Memory': 2 * GIB}}
        self.assertEqual(b.inject_limits(cfg)['HostConfig']['Memory'], 2 * GIB)

    def test_oversized_nuclei_limit_is_clamped(self):
        b = load()
        cfg = {'Image': 'projectdiscovery/nuclei:latest', 'HostConfig': {'Memory': 64 * GIB}}
        self.assertEqual(b.inject_limits(cfg)['HostConfig']['Memory'], 8 * GIB)

    def test_override_is_optional_and_cannot_disable_cap(self):
        for value in ('', 'garbage', '-1g', '0', '0g'):
            with self.subTest(value=value):
                b = load(value)
                cfg = {'Image': 'projectdiscovery/nuclei:latest'}
                self.assertEqual(b.inject_limits(cfg)['HostConfig']['Memory'], 3 * GIB)

    def test_override_can_be_stricter_than_shared_limit(self):
        b = load('1g')
        self.assertEqual(b.inject_limits({'Image': 'projectdiscovery/nuclei:latest'})
                         ['HostConfig']['Memory'], GIB)

    def test_lookalike_image_does_not_get_override_or_admission(self):
        b = load()
        for image in ('attacker/projectdiscovery/nuclei:latest',
                      'projectdiscovery/nuclei-evil:latest',
                      'evil.example/projectdiscovery/nuclei:latest'):
            with self.subTest(image=image):
                self.assertFalse(b.validate_create({'Image': image})[0])
                self.assertEqual(b.inject_limits({'Image': image})['HostConfig']['Memory'], 3 * GIB)

    def test_privileged_and_host_bind_are_still_denied(self):
        b = load()
        for config in ({'Privileged': True}, {'Binds': ['/:/host:ro']}, {'PidMode': 'host'}):
            with self.subTest(config=config):
                self.assertFalse(b.validate_create({'Image': 'projectdiscovery/nuclei:latest',
                                                   'HostConfig': config})[0])

    def test_non_string_image_does_not_crash_limit_injection(self):
        b = load()
        self.assertEqual(b.inject_limits({'Image': None})['HostConfig']['Memory'], 3 * GIB)


if __name__ == '__main__':
    unittest.main()
