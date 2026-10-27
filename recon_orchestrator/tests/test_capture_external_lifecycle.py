import asyncio
import os
import unittest
from unittest import mock

from container_manager import ContainerManager


class TestExternalCaptureLifecycle(unittest.TestCase):
    def test_external_owner_refuses_both_operations_before_docker_access(self):
        manager = ContainerManager.__new__(ContainerManager)
        manager.client = mock.Mock()
        manager._remove_container_if_exists = mock.Mock()
        with mock.patch.dict(os.environ, {"CAPTURE_LIFECYCLE_OWNER": "external"}):
            for method in (manager.start_capture_proxy, manager.stop_capture_proxy):
                with self.subTest(method=method.__name__):
                    with self.assertRaisesRegex(RuntimeError, "capture_lifecycle_managed_externally"):
                        asyncio.run(method())
        self.assertEqual(manager.client.mock_calls, [])
        manager._remove_container_if_exists.assert_not_called()
