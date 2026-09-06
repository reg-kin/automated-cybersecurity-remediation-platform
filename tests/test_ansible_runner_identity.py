#!/usr/bin/env python3

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]

dockerfile_path = ROOT / "ansible-runner" / "Dockerfile"
compose_path = (
    ROOT
    / "deployment"
    / "docker"
    / "n8n-ansible"
    / "docker-compose.yml"
)

dockerfile = dockerfile_path.read_text(encoding="utf-8")
compose = compose_path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Docker image must define and run as a dedicated non-root account.
# ---------------------------------------------------------------------------

if not re.search(
    r"(?s)\buseradd\b.*?\bansible-runner\b",
    dockerfile,
):
    raise AssertionError(
        "Ansible Runner image does not create the dedicated "
        "ansible-runner account"
    )

if not re.search(
    r"(?mi)^\s*USER\s+ansible-runner\s*$",
    dockerfile,
):
    raise AssertionError(
        "Ansible Runner image is not configured to run as ansible-runner"
    )


# ---------------------------------------------------------------------------
# Compose must not override the image back to root.
# ---------------------------------------------------------------------------

if re.search(
    r'(?mi)^\s*user:\s*["\']?(?:root|0(?::0)?)["\']?\s*(?:#.*)?$',
    compose,
):
    raise AssertionError(
        "Ansible Runner Compose service explicitly runs as root"
    )


# ---------------------------------------------------------------------------
# Root's SSH directory must never be mounted into the Runner.
# ---------------------------------------------------------------------------

if "/root/.ssh" in compose:
    raise AssertionError(
        "Ansible Runner still mounts root's SSH directory"
    )


# ---------------------------------------------------------------------------
# The Runner must receive SSH material under its dedicated HOME.
# ---------------------------------------------------------------------------

if "/home/ansible-runner/.ssh" not in compose:
    raise AssertionError(
        "Ansible Runner SSH material is not mounted under "
        "/home/ansible-runner/.ssh"
    )


# ---------------------------------------------------------------------------
# SSH material must be mounted read-only.
# ---------------------------------------------------------------------------

ssh_mount_lines = [
    line.strip()
    for line in compose.splitlines()
    if "/home/ansible-runner/.ssh" in line
]

if not ssh_mount_lines:
    raise AssertionError(
        "Ansible Runner SSH mount is missing"
    )

if not all(
    line.endswith(":ro")
    for line in ssh_mount_lines
):
    raise AssertionError(
        "Ansible Runner SSH material must be mounted read-only"
    )


print(
    "PASS: Ansible Runner uses a dedicated non-root identity "
    "and read-only SSH material"
)
