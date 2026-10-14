#!/usr/bin/env python3
"""Read-only service provisioning inventory tests."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from service_provisioning import inspect_service_provisioning


class ServiceProvisioningTests(unittest.TestCase):
    def test_real_release_inventory_is_read_only(self):
        result = inspect_service_provisioning(ROOT)
        self.assertIn("remediation-dispatcher.timer", result["unit_names"])
        self.assertEqual(result["dispatcher_timer_activation"], "FORBIDDEN")
        self.assertEqual(result["actions_performed"], 0)

    def test_embedded_service_activation_rejected(self):
        original_read = Path.read_text
        def injected_read(path, *args, **kwargs):
            value = original_read(path, *args, **kwargs)
            if path.name == "remediation-controller.service":
                return value + "\\nExecStartPost=/usr/bin/systemctl enable remediation-dispatcher.timer\\n"
            return value
        with patch.object(Path, "read_text", injected_read):
            with self.assertRaisesRegex(RuntimeError, "activation command forbidden"):
                inspect_service_provisioning(ROOT)

    def test_missing_timer_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "deployment/systemd"
            path.mkdir(parents=True)
            (path / "example.service").write_text("[Service]\nExecStart=/bin/true\n")
            with self.assertRaises(RuntimeError):
                inspect_service_provisioning(root)


if __name__ == "__main__":
    unittest.main()
