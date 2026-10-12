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


FTP_METADATA = {"script_id": "ftp-anon", "port": "21", "protocol": "tcp"}
FTP_KEY = "NMAP-NSE:ftp-anon:21/tcp"
FTP_XML = """
<nmaprun scanner="nmap"><host><status state="up"/>
<address addr="192.0.2.20" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="21"><state state="open"/>
</port></ports></host></nmaprun>
"""


def verify_ftp(xml_text=FTP_XML, metadata=None, finding_key=FTP_KEY):
    with patch.object(nmap, "run_nmap", return_value=xml_text):
        return nmap.run_verify_mode(
            "192.0.2.20", finding_key, "service_misconfiguration",
            metadata if metadata is not None else FTP_METADATA, False,
        )


def test_ftp_anonymous_login_accepted():
    with patch.object(nmap, "verify_ftp_anonymous_login", return_value=True) as probe:
        result = verify_ftp()
    assert result["present"] is True
    assert result["evidence"]["authentication_result"] == "anonymous_login_accepted"
    probe.assert_called_once_with("192.0.2.20", 21)


def test_ftp_anonymous_login_rejected():
    with patch.object(nmap, "verify_ftp_anonymous_login", return_value=False) as probe:
        result = verify_ftp()
    assert result["present"] is False
    assert result["evidence"]["authentication_result"] == "anonymous_login_rejected_530"
    probe.assert_called_once_with("192.0.2.20", 21)


def test_ftp_inconclusive_fails_closed():
    with patch.object(nmap, "verify_ftp_anonymous_login", side_effect=RuntimeError("timeout")):
        try:
            verify_ftp()
        except RuntimeError:
            return
    raise AssertionError("FTP Stage 2 accepted an inconclusive authentication probe")


def test_ftp_rejects_wrong_key_and_port_range():
    with patch.object(nmap, "verify_ftp_anonymous_login") as probe:
        for metadata, key in [
            (FTP_METADATA, "NMAP-NSE:ftp-anon:22/tcp"),
            ({"script_id": "ftp-anon", "port": "20-21"}, FTP_KEY),
        ]:
            try:
                verify_ftp(metadata=metadata, finding_key=key)
            except (ValueError, RuntimeError):
                continue
            raise AssertionError("FTP Stage 2 accepted invalid finding scope")
        probe.assert_not_called()


def test_ftp_closed_port_fails_closed():
    xml = FTP_XML.replace('state="open"', 'state="closed"')
    with patch.object(nmap, "verify_ftp_anonymous_login") as probe:
        try:
            verify_ftp(xml_text=xml)
        except RuntimeError:
            probe.assert_not_called()
            return
    raise AssertionError("FTP Stage 2 accepted closed port")


def test_ftp_probe_response_handling():
    from ftplib import error_perm
    from unittest.mock import MagicMock
    for response, expected in [("230 Login successful", True), ("530 Login incorrect", False)]:
        ftp = MagicMock()
        ftp.__enter__.return_value = ftp
        ftp.login.return_value = response
        if response.startswith("530"):
            ftp.login.side_effect = error_perm(response)
        with patch.object(nmap.ftplib, "FTP", return_value=ftp):
            assert nmap.verify_ftp_anonymous_login("192.0.2.20", 21) is expected
    for error in [TimeoutError("timed out"), error_perm("550 File unavailable")]:
        ftp = MagicMock()
        ftp.__enter__.return_value = ftp
        ftp.login.side_effect = error
        with patch.object(nmap.ftplib, "FTP", return_value=ftp):
            try:
                nmap.verify_ftp_anonymous_login("192.0.2.20", 21)
            except RuntimeError:
                continue
            raise AssertionError("FTP Stage 2 accepted ambiguous authentication error")


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

    test_ftp_anonymous_login_accepted()
    print("PASS: FTP anonymous login remains enabled")
    test_ftp_anonymous_login_rejected()
    print("PASS: FTP anonymous login explicitly rejected")
    test_ftp_inconclusive_fails_closed()
    print("PASS: FTP inconclusive probe fails closed")
    test_ftp_rejects_wrong_key_and_port_range()
    print("PASS: FTP verification scope validated")
    test_ftp_closed_port_fails_closed()
    print("PASS: FTP closed port fails closed")
    test_ftp_probe_response_handling()
    print("PASS: FTP authentication responses classified")
