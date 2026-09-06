#!/usr/bin/env python3

from pathlib import Path


SYSTEMD_DIR = Path("deployment/systemd")

SERVICE_FILES = (
    "scanner-control.service",
    "ollama-wazuh-enricher.service",
    "deferred-reconciler.service",
    "remediation-controller.service",
)

EXPECTED_USER = "automated-remediation"
EXPECTED_GROUP = "automated-remediation"


def read_service(name):
    path = SYSTEMD_DIR / name

    if not path.is_file():
        raise AssertionError(
            f"Missing systemd service file: {path}"
        )

    return path.read_text(encoding="utf-8")


def directive_values(text, directive):
    values = []

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        prefix = f"{directive}="

        if line.startswith(prefix):
            values.append(line[len(prefix):].strip())

    return values


def main():
    for service_name in SERVICE_FILES:
        text = read_service(service_name)

        users = directive_values(text, "User")
        groups = directive_values(text, "Group")

        if users != [EXPECTED_USER]:
            raise AssertionError(
                f"{service_name}: expected exactly "
                f"User={EXPECTED_USER}, got {users!r}"
            )

        if groups != [EXPECTED_GROUP]:
            raise AssertionError(
                f"{service_name}: expected exactly "
                f"Group={EXPECTED_GROUP}, got {groups!r}"
            )

        if "User=root" in text:
            raise AssertionError(
                f"{service_name}: must not run as root"
            )

    print(
        "PASS: application systemd services use the "
        "dedicated non-root identity"
    )


if __name__ == "__main__":
    main()
