#!/usr/bin/env python3
"""Regression tests for Nmap NSE Stage 2 evidence handling."""

import logging
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanner_orchestrators"))

with patch(
    "logging.handlers.RotatingFileHandler",
    return_value=logging.NullHandler(),
):
    import nmap_orchestrator as nmap


METADATA = {
    "script_id": "smb-vuln-ms17-010",
    "port": "445",
}


def verify(xml_text):
    with patch.object(nmap, "run_nmap", return_value=xml_text):
        return nmap.run_verify_mode(
            "192.0.2.20",
            "CVE-2017-0143",
            "network_service_vulnerability",
            METADATA,
            False,
        )


def test_original_vulnerability_remains_present():
    xml_text = (
        ROOT / "tests/fixtures/nmap/ms17_010.xml"
    ).read_text(encoding="utf-8")

    result = verify(xml_text)

    assert result["present"] is True
    assert result["evidence"]["match_count"] == 1


def test_missing_host_evidence_must_fail_closed():
    xml_text = '<nmaprun scanner="nmap"></nmaprun>'

    try:
        verify(xml_text)
    except (RuntimeError, ValueError):
        return

    raise AssertionError(
        "Nmap Stage 2 accepted inconclusive evidence "
        "instead of rejecting the verification"
    )


def test_explicit_not_vulnerable_is_not_positive():
    output = "State: NOT VULNERABLE\\nCVE-2017-0143"

    result = nmap.output_indicates_positive_finding(
        "smb-vuln-ms17-010",
        output,
    )

    assert result is False, (
        "Explicit NOT VULNERABLE evidence was classified as positive"
    )


def test_nse_error_must_fail_closed():
    xml_text = """
    <nmaprun scanner="nmap">
      <host>
        <status state="up"/>
        <address addr="192.0.2.20" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="445">
            <state state="open"/>
            <script id="smb-vuln-ms17-010"
                    output="ERROR: SMB negotiation failed"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    try:
        verify(xml_text)
    except (RuntimeError, ValueError):
        return

    raise AssertionError(
        "Nmap Stage 2 accepted an inconclusive NSE error "
        "as evidence of finding absence"
    )


def test_not_vulnerable_alone_must_fail_closed():
    xml_text = """
    <nmaprun scanner="nmap">
      <host>
        <status state="up"/>
        <address addr="192.0.2.20" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="445">
            <state state="open"/>
            <script id="smb-vuln-ms17-010"
                    output="State: NOT VULNERABLE"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    try:
        verify(xml_text)
    except (RuntimeError, ValueError):
        return

    raise AssertionError(
        "Nmap Stage 2 accepted NOT VULNERABLE without "
        "authoritative evidence of a successful SMB check"
    )


def test_mixed_nse_state_precedence():
    newline = chr(10)

    cases = [
        ("State: NOT VULNERABLE", False),
        ("State: VULNERABLE", True),
        ("State: NOT VULNERABLE" + newline + "State: VULNERABLE", True),
        ("State: VULNERABLE" + newline + "State: NOT VULNERABLE", True),
    ]

    for output, expected in cases:
        actual = nmap.output_indicates_positive_finding(
            "smb-vuln-ms17-010",
            output,
        )
        assert actual is expected, (
            f"Expected {expected}, received {actual}: {output!r}"
        )


if __name__ == "__main__":
    test_mixed_nse_state_precedence()
    print("PASS: mixed NSE state precedence")

    test_original_vulnerability_remains_present()
    print("PASS: original vulnerability remains present")

    test_explicit_not_vulnerable_is_not_positive()
    print("PASS: explicit negative evidence is not positive")

    test_nse_error_must_fail_closed()
    print("PASS: inconclusive NSE errors fail closed")

    test_not_vulnerable_alone_must_fail_closed()
    print("PASS: ambiguous NOT VULNERABLE evidence fails closed")

    test_missing_host_evidence_must_fail_closed()
    print("PASS: missing host evidence fails closed")
