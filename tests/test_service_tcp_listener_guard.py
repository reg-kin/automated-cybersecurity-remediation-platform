#!/usr/bin/env python3
"""Isolated Ansible integration tests for the shared TCP listener guard.

A fake ss executable supplies deterministic socket snapshots. No services
are started, stopped, or modified.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TASK_FILE = ROOT / "ansible/roles/service_config/tasks/validate_tcp_listener.yml"

CASES = [
    ("valid owner", 'LISTEN 0 128 0.0.0.0:2121 0.0.0.0:* users:(("vsftpd",pid=4321,fd=3))', True, 2121, 4321),
    ("wrong port", 'LISTEN 0 128 0.0.0.0:2122 0.0.0.0:* users:(("vsftpd",pid=4321,fd=3))', False, 2121, 4321),
    ("wrong pid", 'LISTEN 0 128 0.0.0.0:2121 0.0.0.0:* users:(("vsftpd",pid=9999,fd=3))', False, 2121, 4321),
    ("wrong process", 'LISTEN 0 128 0.0.0.0:2121 0.0.0.0:* users:(("other",pid=4321,fd=3))', False, 2121, 4321),
    ("missing ownership", 'LISTEN 0 128 0.0.0.0:2121 0.0.0.0:*', False, 2121, 4321),
    ("multiple owners", 'LISTEN 0 128 0.0.0.0:2121 0.0.0.0:* users:(("vsftpd",pid=4321,fd=3),("other",pid=9999,fd=4))', False, 2121, 4321),
    ("different port suffix", 'LISTEN 0 128 0.0.0.0:12121 0.0.0.0:* users:(("vsftpd",pid=4321,fd=3))', False, 2121, 4321),
    ("invalid port", 'LISTEN 0 128 0.0.0.0:2121 0.0.0.0:* users:(("vsftpd",pid=4321,fd=3))', False, 0, 4321),
]


def main():
    with tempfile.TemporaryDirectory(prefix="regis-tcp-guard-") as tmp:
        tmp_path = Path(tmp)
        fake_ss = tmp_path / "ss"
        fake_ss.write_text("#!/bin/sh\nprintf '%s\\n' \"$MOCK_SS_OUTPUT\"\n")
        fake_ss.chmod(0o755)
        playbook = tmp_path / "check.yml"
        playbook.write_text(
            "---\n- hosts: localhost\n  gather_facts: false\n"
            "  tasks:\n    - ansible.builtin.include_tasks: "
            + str(TASK_FILE) + "\n"
        )
        for label, snapshot, expected, port, pid in CASES:
            env = os.environ.copy()
            env["PATH"] = str(tmp_path) + os.pathsep + env["PATH"]
            env["MOCK_SS_OUTPUT"] = snapshot
            proc = subprocess.run(
                ["ansible-playbook", "-i", "localhost,", "-c", "local",
                 str(playbook), "-e", f"validated_service_port={port}",
                 "-e", f"validated_service_pid={pid}",
                 "-e", "validated_service_process=vsftpd"],
                env=env, capture_output=True, text=True, timeout=40,
            )
            passed = proc.returncode == 0
            if passed != expected:
                raise AssertionError(
                    f"{label}: expected {'PASS' if expected else 'FAIL'}; "
                    f"exit={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
                )
            print(f"PASS: {label} {'accepted' if expected else 'rejected'}")


if __name__ == "__main__":
    main()
