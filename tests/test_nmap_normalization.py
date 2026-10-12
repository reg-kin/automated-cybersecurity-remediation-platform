#!/usr/bin/env python3

"""
Regression test for Nmap/NSE -> Unified Security Finding normalisation.

The test exercises the existing production XML extraction and
normalize_results() functions. It does not execute Nmap and does not
modify production orchestrator behaviour.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = ROOT / "scanner_orchestrators"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "nmap"

sys.path.insert(0, str(SCANNER_DIR))


def import_nmap_orchestrator():
    """
    Import the production orchestrator without allowing its import-time
    RotatingFileHandler setup to write to /var/log.
    """

    with (
        patch("os.makedirs"),
        patch(
            "logging.handlers.RotatingFileHandler",
            return_value=logging.NullHandler(),
        ),
    ):
        import nmap_orchestrator

    return nmap_orchestrator


def load_fixture(name: str) -> str:
    path = FIXTURE_DIR / name

    return path.read_text(
        encoding="utf-8",
    )


def test_ms17_010_normalization() -> None:
    nmap = import_nmap_orchestrator()

    xml_text = load_fixture(
        "ms17_010.xml"
    )

    script_results = nmap.collect_script_results(
        xml_text
    )

    assert len(script_results) == 1

    script_result = script_results[0]

    assert script_result["host"] == "192.0.2.20"
    assert script_result["port"] == "445"
    assert script_result["protocol"] == "tcp"

    assert (
        script_result["script_id"]
        == "smb-vuln-ms17-010"
    )

    assert (
        script_result["service_name"]
        == "microsoft-ds"
    )

    assert (
        script_result["product"]
        == "Microsoft Windows SMB"
    )

    assert script_result["version"] == "1"

    findings = nmap.normalize_results(
        script_results=script_results,
        tenant_code="TEST-TENANT",
        service_tier="STANDARD",
        task_name="Nmap MS17-010 Regression Test",
        requested_target="192.0.2.20",
        scan_mode="specific",
        requested_script="smb-vuln-ms17-010",
        requested_finding_key="CVE-2017-0143",
    )

    assert len(findings) == 1

    payload = findings[0]

    assert payload["tenant_code"] == "TEST-TENANT"

    assert (
        payload["tenant_service_tier"]
        == "STANDARD"
    )

    assert payload["target_host"] == "192.0.2.20"

    assert payload["engine_source"] == "nmap_nse"

    assert (
        payload["finding_category"]
        == "vulnerability"
    )

    assert (
        payload["finding_class"]
        == "network_service_vulnerability"
    )

    assert (
        payload["finding_key"]
        == "CVE-2017-0143"
    )

    assert (
        payload["finding_title"]
        == (
            "CVE-2017-0143 - "
            "Nmap NSE smb-vuln-ms17-010"
        )
    )

    assert payload["lifecycle_status"] == "OPEN"

    assert payload["severity_level"] == "HIGH"
    assert payload["severity_score"] == 7.5

    metadata = payload["engine_metadata"]

    assert (
        metadata["task_name"]
        == "Nmap MS17-010 Regression Test"
    )

    assert metadata["scan_mode"] == "specific"

    assert (
        metadata["script_id"]
        == "smb-vuln-ms17-010"
    )

    assert (
        metadata["requested_script"]
        == "smb-vuln-ms17-010"
    )

    assert metadata["port"] == "445"
    assert metadata["protocol"] == "tcp"
    assert metadata["scanned_port"] == "445/tcp"

    assert (
        metadata["service_name"]
        == "microsoft-ds"
    )

    assert (
        metadata["product"]
        == "Microsoft Windows SMB"
    )

    assert metadata["version"] == "1"

    assert metadata["cves"] == [
        "CVE-2017-0143"
    ]

    assert payload["ai_analysis"] is None



def test_ftp_anonymous_access_normalization() -> None:
    """Regression for actual Nmap 7.98 ftp-anon positive output."""
    nmap = import_nmap_orchestrator()
    output = "Anonymous FTP login allowed (FTP code 230)"
    assert nmap.output_indicates_positive_finding("ftp-anon", output)
    assert nmap.determine_finding_class("ftp-anon", output, "ftp", "21") == "service_misconfiguration"

    xml_text = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="172.24.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp"/>
        <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    results = nmap.collect_script_results(xml_text)
    assert len(results) == 1
    findings = nmap.normalize_results(
        script_results=results,
        tenant_code="TEST-TENANT",
        service_tier="STANDARD",
        task_name="Nmap FTP Anonymous Access Regression Test",
        requested_target="172.24.0.2",
        scan_mode="specific",
        requested_script="ftp-anon",
        requested_finding_key=None,
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["engine_source"] == "nmap_nse"
    assert finding["finding_class"] == "service_misconfiguration"
    assert finding["engine_metadata"]["script_id"] == "ftp-anon"
    assert finding["engine_metadata"]["port"] == "21"

    # Do not classify a script name alone as positive evidence.
    assert not nmap.output_indicates_positive_finding("ftp-anon", "Anonymous FTP login denied")
    assert not nmap.output_indicates_positive_finding("ftp-anon", "530 Login incorrect")


def main() -> int:
    test_ms17_010_normalization()
    test_ftp_anonymous_access_normalization()

    print(
        "PASS: Nmap MS17-010 XML normalises "
        "to the expected Unified Security Finding"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
