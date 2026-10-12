#!/usr/bin/env python3
"""Controller handoff contract: persisted FTP port overrides caller data."""
from pathlib import Path
import sys
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from remediation.controllers import base


class Connection:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def close(self):
        pass


class Controller(base.BaseController):
    capability = "service_config"


authoritative = {
    "finding_id": 101,
    "engine_source": "nmap_nse",
    "finding_class": "service_misconfiguration",
    "finding_key": "NMAP-NSE:ftp-anon:2121/tcp",
    "engine_metadata": {"script_id": "ftp-anon", "port": 2121, "protocol": "tcp"},
}
request = {
    "finding_id": 101,
    "engine_source": "nmap_nse",
    "finding_class": "service_misconfiguration",
    "finding_key": "NMAP-NSE:ftp-anon:2121/tcp",
    "remediation_action": "disable_vsftpd_anonymous",
    "playbook_name": "service_config.yml",
    "target_host": "192.0.2.20",
    "execution_parameters": {"validated_ftp_port": 9999},
}

for scenario, stored, should_run in [
    ("authoritative override", authoritative, True),
    ("inconsistent persisted key", {**authoritative, "finding_key": "NMAP-NSE:ftp-anon:21/tcp"}, False),
]:
    runner = Mock(side_effect=RuntimeError("controlled stop before remediation"))
    begin = Mock(return_value=99)
    update = Mock()
    with (
        patch.object(base.db, "connect", return_value=Connection()),
        patch.object(base.db, "get_finding", return_value=stored),
        patch.object(base.db, "update_execution_status", update),
        patch.object(base.db, "begin_verification", begin),
        patch.object(base.db, "complete_verification"),
        patch.object(base.db, "reopen_failed"),
        patch.object(base, "run_ansible", runner),
    ):
        if should_run:
            result = Controller().execute_existing(request, 301)
            assert result["success"] is False, result
            assert runner.call_count == 1
            assert runner.call_args.args[2]["validated_ftp_port"] == 2121
            assert runner.call_args.args[2]["remediation_action"] == "disable_vsftpd_anonymous"
            print("PASS: controller overrides caller FTP port with persisted port")
        else:
            try:
                Controller().execute_existing(request, 301)
            except ValueError:
                pass
            else:
                raise AssertionError("Inconsistent persisted finding was accepted")
            runner.assert_not_called()
            update.assert_not_called()
            begin.assert_not_called()
            print("PASS: inconsistent persisted finding blocks Ansible before execution")
