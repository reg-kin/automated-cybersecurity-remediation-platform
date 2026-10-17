#!/usr/bin/env python3
"""Explicit CLI for existing offline five-stage provisioning; never starts services.

This CLI does not create identities, configure secrets, or authorize production
activation. Destinations and the private journal must be prepared by the operator.
"""
import argparse
import json
import sys
from pathlib import Path

from install_application import environment_templates
from provisioning_preflight import preflight_provisioning
from provision_staged_application import provision_staged_application


def main(argv=None):
    parser = argparse.ArgumentParser(description="Preflight or provision an isolated application.")
    parser.add_argument("--application", required=True, help="Absolute staged application path")
    parser.add_argument("--unit-destination", required=True, help="Existing unit destination directory")
    parser.add_argument("--environment-map", required=True,
                        help="JSON object mapping all selected canonical /etc env paths to destinations")
    parser.add_argument("--journal", required=True, help="New journal path in a private directory")
    parser.add_argument("--uid", required=True, type=int, help="Intended service UID")
    parser.add_argument("--gid", required=True, type=int, help="Intended service GID")
    parser.add_argument("--provision", action="store_true", help="Explicitly perform offline provisioning")
    parser.add_argument("--confirm-application", help="Must equal --application to provision")
    parser.add_argument("--native", action="store_true", help="Include native Runner and verification gateway (eight environments, eleven units)")
    args = parser.parse_args(argv)

    try:
        if args.uid < 0 or args.gid < 0:
            raise ValueError("UID and GID must be nonnegative.")
        mapping_path = Path(args.environment_map)
        if mapping_path.is_symlink() or not mapping_path.is_file():
            raise ValueError("Environment map must be a regular non-symlink file.")
        mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
        if (not isinstance(mapping, dict)
                or set(mapping) != set(environment_templates(native=args.native))
                or any(not isinstance(v, str) or not v.startswith("/") for v in mapping.values())):
            raise ValueError("Environment map must contain the selected absolute destination paths.")
        preflight = preflight_provisioning(
            args.application, args.unit_destination, mapping, native=args.native
        )
        print("PASS: Offline preflight:", json.dumps(preflight, sort_keys=True))
        if not args.provision:
            print("INSPECTION ONLY: No files, services or database objects changed.")
            return 0
        if args.confirm_application != args.application:
            parser.error("--confirm-application must exactly equal --application")
        record = provision_staged_application(
            args.journal, args.application, args.unit_destination, mapping,
            uid=args.uid, gid=args.gid, native=args.native
        )
        print("PASS: Offline provisioning journal:", record["state"])
        print("NOT AUTHORIZED: No secrets configured or systemd services activated.")
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Offline provisioning refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
