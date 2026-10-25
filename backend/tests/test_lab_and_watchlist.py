import pytest
from app.services.test_lab_service import run_test_lab_benchmark, SAFE_FIXTURES

def test_safe_security_test_lab_benchmarking():
    assert len(SAFE_FIXTURES) >= 5

    # Check fixture contents
    sqli_fix = next(f for f in SAFE_FIXTURES if "sqli" in f.expected_rule_id)
    assert sqli_fix.language == "Python"
    assert "user_id" in sqli_fix.vulnerable_code
    assert ":id" in sqli_fix.fixed_code

    # Check negative control fixture
    safe_fix = next(f for f in SAFE_FIXTURES if not f.ground_truth_vulnerable)
    assert safe_fix.expected_severity == "NONE"

    # Execute benchmark
    report = run_test_lab_benchmark()

    assert report.total_fixtures == len(SAFE_FIXTURES)
    assert report.precision_pct >= 90.0
    assert report.recall_pct >= 90.0
    assert report.expected_detections >= 4
    assert report.actual_detections >= 4
    assert report.missed_detections == 0
    assert report.unexpected_detections == 0
    assert "SAFE TEST LAB NOTICE" in report.disclaimer

    # Verify negative control result
    safe_res = next(r for r in report.results if r.fixture_id == safe_fix.id)
    assert safe_res.status == "CORRECT_NEGATIVE"
    assert safe_res.detected is False
    assert safe_res.execution_time_ms > 0

@pytest.mark.asyncio
async def test_live_security_test_lab_real_detection():
    from app.services.test_lab_service import run_live_code_scan

    # Test real command injection
    vuln_code = "import subprocess\ndef ping(ip):\n    subprocess.run(f'ping -c 1 {ip}', shell=True)\n"
    res = await run_live_code_scan(code=vuln_code, language="python")
    assert res.safe is False
    assert res.total_findings >= 1
    assert any("subprocess" in f.rule_id for f in res.findings)
    assert res.execution_time_ms > 0
    assert "Semgrep AST Engine" in res.scanners_run

    # Test clean negative control
    clean_code = "def add(a, b):\n    return a + b\n"
    clean_res = await run_live_code_scan(code=clean_code, language="python")
    assert clean_res.safe is True
    assert clean_res.total_findings == 0

@pytest.mark.asyncio
async def test_benchmark_scan_findings_real():
    from app.services.test_lab_service import benchmark_scan_findings

    mock_scan = {
        "repo_url": "https://github.com/org/repo",
        "findings": [
            {
                "id": "f-1",
                "rule_id": "python.lang.security.insecure-subprocess",
                "category": "SAST",
                "file_path": "server.py",
                "detector_name": "Semgrep",
                "evidence": "subprocess.run(cmd, shell=True)",
            }
        ]
    }
    report = await benchmark_scan_findings(mock_scan)
    assert report.total_findings_evaluated == 1
    assert report.verified_detections == 1
    assert report.precision_pct == 100.0
    assert report.avg_latency_ms >= 0
