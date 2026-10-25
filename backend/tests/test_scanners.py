import os
import tempfile
import pytest
from app.scanners.gitleaks_scanner import GitleaksScanner
from app.scanners.semgrep_scanner import SemgrepScanner
from app.scanners.osv_scanner import OSVScanner
from app.models.finding import Severity, Category

@pytest.mark.anyio
async def test_gitleaks_detects_and_redacts():
    scanner = GitleaksScanner()
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a file containing a sensitive AWS test key
        secret_file = os.path.join(tmpdir, "credentials.env")
        raw_key = "AKIA1234567890ABCDEF"
        with open(secret_file, "w") as f:
            f.write(f"AWS_ACCESS_KEY_ID={raw_key}\n")

        findings, status = await scanner.scan(tmpdir)
        assert status.status == "SUCCESS"
        assert len(findings) >= 1
        
        # Verify redaction: RAW key must never be in evidence or title
        f = findings[0]
        assert f.category == Category.SECRETS
        assert raw_key not in (f.evidence or "")
        assert "REDACTED" in (f.evidence or "")

@pytest.mark.anyio
async def test_semgrep_detects_sast_patterns():
    scanner = SemgrepScanner()
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a python script with dangerous shell=True and eval()
        vuln_file = os.path.join(tmpdir, "danger.py")
        with open(vuln_file, "w") as f:
            f.write("import subprocess\nsubprocess.call('ls ' + user_input, shell=True)\nresult = eval(user_input)\n")

        findings, status = await scanner.scan(tmpdir)
        assert status.status == "SUCCESS"
        assert len(findings) >= 1
        assert any(f.category == Category.SAST for f in findings)

@pytest.mark.anyio
async def test_osv_vulnerability_audit():
    scanner = OSVScanner()
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a package.json with known historical vulnerable package
        pkg_file = os.path.join(tmpdir, "package.json")
        with open(pkg_file, "w") as f:
            f.write('{"name": "test-app", "dependencies": {"lodash": "4.17.15"}}\n')

        findings, status = await scanner.scan(tmpdir)
        assert status.status == "SUCCESS"
        # lodash 4.17.15 has multiple known CVEs in OSV
        if len(findings) > 0:
            assert any("lodash" in f.title.lower() for f in findings)
            assert any(f.category == Category.DEPENDENCIES for f in findings)
