import pytest
from fastapi import HTTPException
from app.core.security import parse_and_validate_github_url, is_safe_extract_path

def test_valid_github_urls():
    owner, repo = parse_and_validate_github_url("https://github.com/torvalds/linux")
    assert owner == "torvalds"
    assert repo == "linux"

    owner, repo = parse_and_validate_github_url("https://github.com/facebook/react.git")
    assert owner == "facebook"
    assert repo == "react"

def test_reject_non_github_host():
    with pytest.raises(HTTPException) as exc_info:
        parse_and_validate_github_url("https://gitlab.com/owner/repo")
    assert exc_info.value.status_code == 400
    assert "Unsupported host" in exc_info.value.detail

def test_reject_ssrf_internal_ips():
    with pytest.raises(HTTPException) as exc_info:
        parse_and_validate_github_url("http://127.0.0.1/admin")
    assert exc_info.value.status_code == 400

    with pytest.raises(HTTPException) as exc_info:
        parse_and_validate_github_url("http://169.254.169.254/latest/meta-data")
    assert exc_info.value.status_code == 400

def test_reject_path_traversal_in_url():
    with pytest.raises(HTTPException) as exc_info:
        parse_and_validate_github_url("https://github.com/../../etc/passwd")
    assert exc_info.value.status_code == 400

def test_zip_slip_path_traversal_defense():
    target_dir = "C:\\sandbox\\scan_123"
    safe_file = "C:\\sandbox\\scan_123\\src\\index.js"
    malicious_file = "C:\\sandbox\\etc\\passwd"
    malicious_traversal = "C:\\sandbox\\scan_123\\..\\..\\windows\\system32\\calc.exe"

    assert is_safe_extract_path(target_dir, safe_file) is True
    assert is_safe_extract_path(target_dir, malicious_file) is False
    assert is_safe_extract_path(target_dir, malicious_traversal) is False
