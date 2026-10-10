#!/usr/bin/env python3
import logging
import sys
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scanner_orchestrators"))
with patch("logging.handlers.RotatingFileHandler",return_value=logging.NullHandler()):
    import nmap_orchestrator as nmap

def test_script_name_alone_is_not_positive():
    assert not nmap.output_indicates_positive_finding("http-vuln-cve2017-0000","No vulnerabilities found")

def test_negative_state_with_cve_is_not_positive():
    assert not nmap.output_indicates_positive_finding("x","State: NOT VULNERABLE\nCVE-2017-0143")

def test_mixed_states_are_positive():
    assert nmap.output_indicates_positive_finding("x","State: NOT VULNERABLE\nState: VULNERABLE")

def test_reject_multiple_targets():
    with patch.object(nmap.subprocess,"run") as run:
        try:
            nmap.run_nmap("192.0.2.1 192.0.2.2","vuln_only")
        except ValueError:
            pass
        else:
            raise AssertionError("Multiple targets accepted")
        run.assert_not_called()

def test_no_fabricated_cvss():
    assert nmap.severity_from_output("State: VULNERABLE")[1] is None

if __name__=="__main__":
    for name,fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS:",name)
