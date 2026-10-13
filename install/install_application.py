#!/usr/bin/env python3
"""Safety checks for fresh application installation."""

import argparse
import hashlib
import os
import shutil
import stat
from pathlib import Path


DEFAULT_DESTINATION = Path("/opt/automated-remediation")

INSTALL_DIRECTORIES = (
    "ansible",
    "ansible-runner",
    "asset_management",
    "database",
    "deployment",
    "install",
    "integrations",
    "manual_verification",
    "readiness_management",
    "remediation",
    "risk_management",
    "scan_coordination",
    "scan_policy_administration",
    "scanner_orchestrators",
    "schema",
    "verification",
    "worker",
)

INSTALL_FILES = (
    "requirements.txt",
    "LICENSE",
)

EXCLUDED_NAMES = frozenset((
    ".git",
    ".venv",
    ".pytest_cache",
    "__pycache__",
    ".env",
    ".DS_Store",
))


REQUIRED_FILES = (
    "requirements.txt",
    "install/install_database.py",
    "deployment/systemd/remediation-controller.service",
    "deployment/systemd/remediation-dispatcher.service",
    "deployment/systemd/scan-policy-admin-api.service",
)



EXCLUDED_SUFFIXES = frozenset((
    ".pyc",
    ".pyo",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".log",
    ".bak",
    ".tmp",
    ".dump",
    ".sav",
))




ENVIRONMENT_FILE_TEMPLATES = {
    "/etc/readiness-admin-api.env":
        "deployment/systemd/env/readiness-admin-api.env.example",
    "/etc/remediation-controller.env":
        "deployment/systemd/env/remediation-controller.env.example",
    "/etc/remediation-dispatcher.env":
        "deployment/systemd/env/remediation-dispatcher.env.example",
    "/etc/remediation-rq-worker.env":
        "deployment/systemd/env/rq-worker.env.example",
    "/etc/scan-policy-admin-api.env":
        "deployment/systemd/env/scan-policy-admin-api.env.example",
    "/etc/scan-policy-scheduler.env":
        "deployment/systemd/env/scan-policy-scheduler.env.example",
}


def should_exclude(path):
    """Reject generated, sensitive and symbolic-link entries."""
    path = Path(path)

    if path.is_symlink():
        return True

    if any(part in EXCLUDED_NAMES for part in path.parts):
        return True

    if any(part.startswith(".env.") and part != ".env.example"
           for part in path.parts):
        return True

    if path.name.endswith("~"):
        return True

    if path.suffix.lower() in EXCLUDED_SUFFIXES:
        return True

    return False




def copy_regular_file_no_follow(source, target):
    """Copy a regular file without following a source symbolic link."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(source, flags)

    try:
        file_stat = os.fstat(descriptor)

        if not stat.S_ISREG(file_stat.st_mode):
            raise RuntimeError(
                f"Source is not a regular file: {source}"
            )

        with os.fdopen(descriptor, "rb", closefd=False) as input_file:
            with open(target, "xb") as output_file:
                shutil.copyfileobj(input_file, output_file)

    finally:
        os.close(descriptor)



def copy_application_files(source, destination):
    """Copy explicitly selected repository files into a fresh destination."""
    source = Path(source).resolve()
    destination = Path(destination)

    if destination.exists() or destination.is_symlink():
        raise RuntimeError(
            f"Installation destination already exists: {destination}"
        )

    if source == destination.resolve() or source in destination.resolve().parents:
        raise RuntimeError("Destination cannot be inside the source repository.")

    selected_files = []

    for name in INSTALL_FILES:
        candidate = source / name

        if not candidate.is_file() or candidate.is_symlink():
            raise RuntimeError(f"Required installation file missing: {name}")

        selected_files.append(candidate)

    for directory_name in INSTALL_DIRECTORIES:
        directory = source / directory_name

        if not directory.is_dir() or directory.is_symlink():
            raise RuntimeError(
                f"Required installation directory missing: {directory_name}"
            )

        for root, directory_names, file_names in os.walk(
            directory, topdown=True, followlinks=False
        ):
            root_path = Path(root)

            directory_names[:] = [
                name
                for name in directory_names
                if not should_exclude(
                    (root_path / name).relative_to(source)
                )
                and not (root_path / name).is_symlink()
            ]

            for name in file_names:
                candidate = root_path / name
                relative = candidate.relative_to(source)

                if should_exclude(relative) or candidate.is_symlink():
                    continue

                if not candidate.is_file():
                    continue

                if not candidate.resolve().is_relative_to(source):
                    raise RuntimeError(
                        f"File escapes source repository: {relative}"
                    )

                selected_files.append(candidate)

    # The caller must provide an existing, trusted parent directory.
    # Exclusive creation prevents replacing an existing installation.
    destination.mkdir(parents=False, exist_ok=False)

    try:
        for candidate in selected_files:
            relative = candidate.relative_to(source)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            copy_regular_file_no_follow(candidate, target)
    except Exception as error:
        # Preserve partial installation for inspection.
        # Never recursively delete a destination during error handling.
        raise RuntimeError(
            f"Application file installation failed at {destination}; "
            "partial installation preserved for inspection."
        ) from error

    return len(selected_files)





def stage_application_files(source, staging_root):
    """Prepare application files in a private, unprivileged staging area."""
    staging_root = Path(staging_root)

    if not staging_root.is_absolute():
        raise RuntimeError("Staging path must be absolute.")

    if staging_root.exists() or staging_root.is_symlink():
        raise RuntimeError(
            f"Staging destination already exists: {staging_root}"
        )

    staging_root.mkdir(mode=0o700, parents=False, exist_ok=False)

    application = staging_root / "application"

    try:
        count = copy_application_files(source, application)
    except Exception:
        # Preserve staging contents for investigation.
        # Never recursively delete an unexpected filesystem tree.
        raise

    manifest, manifest_count = generate_release_manifest(application)

    if manifest_count != count:
        raise RuntimeError(
            "Staged file count differs from manifest file count."
        )

    verified_count = verify_release_manifest(application, manifest)

    if verified_count != count:
        raise RuntimeError(
            "Staged file count differs from verified file count."
        )

    return application, count



def generate_release_manifest(application):
    """Create a deterministic SHA-256 manifest of staged application files."""
    application = Path(application)

    if application.is_symlink() or not application.is_dir():
        raise RuntimeError("Staged application must be a real directory.")

    entries = []

    for root, directories, files in os.walk(
        application, topdown=True, followlinks=False
    ):
        root_path = Path(root)

        for name in directories:
            directory = root_path / name
            if directory.is_symlink() or not directory.is_dir():
                raise RuntimeError(
                    f"Unsafe staging directory: {directory}"
                )

        for name in files:
            candidate = root_path / name

            if candidate.is_symlink():
                raise RuntimeError(
                    f"Symbolic link in staged application: {candidate}"
                )

            if not candidate.is_file():
                raise RuntimeError(
                    f"Non-regular staged file: {candidate}"
                )

            relative = candidate.relative_to(application)

            if "\\n" in str(relative) or "\\r" in str(relative):
                raise RuntimeError(
                    "Manifest paths cannot contain line breaks."
                )

            digest = hashlib.sha256()

            descriptor = os.open(
                candidate,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            )

            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise RuntimeError(
                        f"Non-regular staged file: {candidate}"
                    )

                with os.fdopen(
                    descriptor, "rb", closefd=False
                ) as input_file:
                    for block in iter(
                        lambda: input_file.read(1024 * 1024), b""
                    ):
                        digest.update(block)
            finally:
                os.close(descriptor)

            entries.append((relative.as_posix(), digest.hexdigest()))

    entries.sort()

    manifest = application.parent / "SHA256SUMS"

    with manifest.open("x", encoding="utf-8", newline="\n") as output:
        for relative, digest in entries:
            output.write(f"{digest}  {relative}\n")

    return manifest, len(entries)


def verify_release_manifest(application, manifest):
    """Verify every staged file against an exact SHA-256 manifest."""
    application = Path(application)
    manifest = Path(manifest)

    if application.is_symlink() or not application.is_dir():
        raise RuntimeError("Application directory is invalid.")

    if manifest.is_symlink() or not manifest.is_file():
        raise RuntimeError("Release manifest is invalid.")

    expected = {}

    with manifest.open("r", encoding="utf-8") as input_file:
        for line in input_file:
            line = line.rstrip("\n")

            if len(line) < 67 or line[64:66] != "  ":
                raise RuntimeError("Malformed release manifest.")

            digest = line[:64]
            relative = line[66:]
            relative_path = Path(relative)

            if (
                len(digest) != 64
                or any(character not in "0123456789abcdef"
                       for character in digest)
                or not relative
                or relative_path.is_absolute()
                or any(part in (".", "..") for part in relative.split("/"))
                or "\\r" in relative
                or "\\\\" in relative
                or relative in expected
            ):
                raise RuntimeError("Invalid release manifest entry.")

            expected[relative] = digest

    actual = {}

    for root, directories, files in os.walk(
        application, topdown=True, followlinks=False
    ):
        root_path = Path(root)

        for name in directories:
            directory = root_path / name

            if directory.is_symlink() or not directory.is_dir():
                raise RuntimeError("Unsafe application directory.")

        for name in files:
            candidate = root_path / name

            if candidate.is_symlink() or not candidate.is_file():
                raise RuntimeError("Unsafe application file.")

            relative = candidate.relative_to(application).as_posix()

            digest = hashlib.sha256()

            descriptor = os.open(
                candidate,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            )

            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise RuntimeError("Non-regular application file.")

                with os.fdopen(
                    descriptor, "rb", closefd=False
                ) as input_file:
                    for block in iter(
                        lambda: input_file.read(1024 * 1024), b""
                    ):
                        digest.update(block)
            finally:
                os.close(descriptor)

            actual[relative] = digest.hexdigest()

    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        unexpected = sorted(set(actual) - set(expected))
        modified = sorted(
            name for name in set(actual) & set(expected)
            if actual[name] != expected[name]
        )

        raise RuntimeError(
            "Release integrity verification failed: "
            f"missing={missing}, "
            f"unexpected={unexpected}, "
            f"modified={modified}"
        )

    return len(actual)

def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(
        description="Validate a fresh application installation target."
    )

    parser.add_argument(
        "--destination",
        default=str(DEFAULT_DESTINATION),
        help="Absolute destination for the fresh installation.",
    )

    parser.add_argument(
        "--confirm-destination",
        required=True,
        help="Repeat the exact installation destination.",
    )

    args = parser.parse_args(argv)

    destination = Path(args.destination).expanduser()

    if not destination.is_absolute():
        parser.error("--destination must be an absolute path.")

    if args.confirm_destination != str(destination):
        parser.error(
            "--confirm-destination must exactly match --destination."
        )

    args.destination = destination
    return args




def validate_systemd_unit_conflicts(source):
    """Reject existing systemd units before installation."""
    unit_directory = Path(source) / "deployment/systemd"

    unit_names = sorted(
        path.name
        for path in unit_directory.iterdir()
        if path.is_file() and path.suffix in (".service", ".timer")
    )

    if not unit_names:
        raise RuntimeError("No systemd units found in installation source.")

    systemd_directories = (
        Path("/etc/systemd/system"),
        Path("/run/systemd/system"),
        Path("/usr/lib/systemd/system"),
        Path("/lib/systemd/system"),
    )

    conflicts = sorted({
        str(directory / name)
        for directory in systemd_directories
        for name in unit_names
        if (directory / name).exists()
        or (directory / name).is_symlink()
    })

    if conflicts:
        raise RuntimeError(
            "Existing systemd units must not be overwritten: "
            + ", ".join(conflicts)
        )

    return len(unit_names)




def validate_api_port_conflicts(source):
    """Reject API ports already occupied by another process."""
    import re
    import socket

    unit_directory = Path(source) / "deployment/systemd"
    bindings = set()

    for unit in sorted(unit_directory.glob("*.service")):
        for line in unit.read_text().splitlines():
            if not line.startswith("ExecStart="):
                continue

            for address, port_text in re.findall(
                r"--bind\s+([0-9.]+):(\d+)",
                line,
            ):
                bindings.add((address, int(port_text)))

    if not bindings:
        raise RuntimeError(
            "No API bind addresses found in systemd manifests."
        )

    conflicts = []

    for address, port in sorted(bindings):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((address, port))
            except OSError as error:
                conflicts.append(
                    f"{address}:{port} ({error})"
                )

    if conflicts:
        raise RuntimeError(
            "API ports already occupied: " + ", ".join(conflicts)
        )

    return len(bindings)




def provision_environment_file(template, destination, uid, gid):
    """Securely create a configuration file without overwriting one."""
    template = Path(template)
    destination = Path(destination)

    source_fd = os.open(
        template,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
    )

    try:
        source_stat = os.fstat(source_fd)

        if not stat.S_ISREG(source_stat.st_mode):
            raise RuntimeError(
                f"Environment template is not a regular file: {template}"
            )

        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )

        try:
            destination_stat = os.fstat(destination_fd)

            with os.fdopen(source_fd, "rb", closefd=False) as input_file:
                with os.fdopen(destination_fd, "wb", closefd=False) as output:
                    shutil.copyfileobj(input_file, output)
                    output.flush()
                    os.fchmod(destination_fd, 0o640)
                    os.fchown(destination_fd, uid, gid)

        except BaseException:
            current = os.stat(destination, follow_symlinks=False)

            if (
                current.st_dev == destination_stat.st_dev
                and current.st_ino == destination_stat.st_ino
            ):
                destination.unlink()

            raise

        finally:
            os.close(destination_fd)

    finally:
        os.close(source_fd)




def validate_environment_file_conflicts():
    """Reject installation when target configuration paths already exist."""
    conflicts = []

    for destination in ENVIRONMENT_FILE_TEMPLATES:
        target = Path(destination)

        if target.exists() or target.is_symlink():
            conflicts.append(str(target))

    if conflicts:
        raise RuntimeError(
            "Existing environment configuration files must not be "
            "overwritten: " + ", ".join(sorted(conflicts))
        )


def validate_installation(args):
    source = Path(__file__).resolve().parent.parent
    destination = args.destination.resolve()

    if destination != DEFAULT_DESTINATION:
        raise RuntimeError(
            "Unsupported installation destination: "
            f"{destination}. Required: {DEFAULT_DESTINATION}"
        )

    if destination == source or source in destination.parents:
        raise RuntimeError(
            "Installation destination cannot be inside the source repository."
        )

    if destination.exists() or destination.is_symlink():
        raise RuntimeError(
            f"Installation destination already exists: {destination}"
        )

    missing = [
        name for name in REQUIRED_FILES
        if not (source / name).is_file()
    ]

    if missing:
        raise RuntimeError(
            f"Required repository files are missing: {missing}"
        )

    validate_environment_file_conflicts()
    validate_systemd_unit_conflicts(source)
    validate_api_port_conflicts(source)

    return source, destination


def main():
    args = parse_arguments()
    source, destination = validate_installation(args)

    print(f"PASS: Source repository: {source}")
    print(f"PASS: Fresh installation destination: {destination}")
    print("PASS: Required repository files are present.")
    print("VALIDATION ONLY: No installation actions performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
