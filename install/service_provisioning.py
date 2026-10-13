#!/usr/bin/env python3
"""Read-only production service provisioning inventory and safety validation.

No systemd commands, account changes, dependency installs, or file writes.
"""
import os
import re
from pathlib import Path

from install_application import ENVIRONMENT_FILE_TEMPLATES


def inspect_service_provisioning(source):
    source = Path(source).resolve(strict=True)
    unit_dir = source / "deployment/systemd"
    if not unit_dir.is_dir() or unit_dir.is_symlink():
        raise RuntimeError("Missing trusted systemd source directory.")
    units = sorted(p for p in unit_dir.iterdir()
                   if p.suffix in (".service", ".timer"))
    if not units:
        raise RuntimeError("No systemd units found.")
    unit_names = {p.name for p in units}
    service_accounts = set()
    referenced_envs = set()
    for unit in units:
        if unit.is_symlink() or not unit.is_file():
            raise RuntimeError(f"Unsafe systemd unit: {unit}")
        lines = unit.read_text(encoding="utf-8").splitlines()
        for line in lines:
            if line.startswith(("User=", "Group=")):
                service_accounts.add(line.partition("=")[2].strip())
            if line.startswith("EnvironmentFile="):
                value = line.partition("=")[2].strip()
                if not value.startswith("/") or value.startswith("-"):
                    raise RuntimeError(f"Unsupported environment file: {value}")
                referenced_envs.add(value)
            if line.startswith(("ExecStart=", "ExecStartPre=", "ExecStartPost=")):
                command = line.partition("=")[2].strip()
                if not command.startswith("/") or any(
                    token in command for token in (";", "|", "&&", "`", "$(")
                ):
                    raise RuntimeError(f"Unsafe systemd command in {unit.name}")
        if unit.suffix == ".timer":
            target = next((line.partition("=")[2].strip()
                           for line in lines if line.startswith("Unit=")), None)
            if target and target not in unit_names:
                raise RuntimeError(f"Timer references missing unit: {target}")
    missing_templates = sorted(
        name for name, template in ENVIRONMENT_FILE_TEMPLATES.items()
        if not (source / template).is_file()
        or (source / template).is_symlink()
    )
    if missing_templates:
        raise RuntimeError(f"Missing environment templates: {missing_templates}")
    unknown_envs = sorted(referenced_envs - set(ENVIRONMENT_FILE_TEMPLATES))
    if unknown_envs:
        raise RuntimeError(f"Unprovisioned environment references: {unknown_envs}")
    timer = unit_dir / "remediation-dispatcher.timer"
    if not timer.is_file():
        raise RuntimeError("Dispatcher timer missing.")
    return {
        "unit_names": sorted(unit_names),
        "service_accounts": sorted(service_accounts),
        "environment_files": sorted(referenced_envs),
        "dispatcher_timer_activation": "FORBIDDEN",
        "actions_performed": 0,
    }
