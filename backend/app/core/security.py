import ipaddress
import os
import re
import socket
import subprocess
from typing import Optional
from urllib.parse import urlparse
from fastapi import HTTPException
from app.utils.redaction import redact_text

GITHUB_URL_PATTERN = re.compile(
    r'^(?:https?://)?(?:www\.)?github\.com/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?/?$'
)

SHORTHAND_PATTERN = re.compile(
    r'^([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+)$'
)

DISALLOWED_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254", "metadata.google.internal"
}

PRIVATE_IP_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
]

def is_private_ip(ip_str: str) -> bool:
    """Check if an IP string belongs to any private or link-local range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_IP_NETWORKS)
    except ValueError:
        return True

def parse_and_validate_github_url(url: str) -> tuple[str, str]:
    """
    Validates that a URL is strictly a legitimate GitHub repository URL or valid shorthand (owner/repo).
    Returns (owner, repo).
    Raises HTTPException(400) if invalid or prohibited.
    """
    if not url or not isinstance(url, str):
        raise HTTPException(status_code=400, detail="Repository URL is required.")
    
    url = url.strip()

    # Support owner/repo shorthand
    shorthand_match = SHORTHAND_PATTERN.match(url)
    if shorthand_match:
        owner, repo = shorthand_match.groups()
        if ".." in owner or ".." in repo:
            raise HTTPException(status_code=400, detail="Invalid path traversal sequence in repository identifier.")
        if repo.endswith(".git"):
            repo = repo[:-4]
        return owner, repo

    # Ensure URL has scheme for urlparse if starting with github.com
    if url.startswith("github.com/"):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    if not hostname or hostname not in ("github.com", "www.github.com"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported host '{hostname}'. Only public GitHub.com repositories or 'owner/repo' shorthand are supported."
        )

    if hostname in DISALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="Prohibited target destination.")

    match = GITHUB_URL_PATTERN.match(url)
    if not match:
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub repository URL. Must follow format: https://github.com/owner/repo or owner/repo"
        )

    owner, repo = match.groups()
    if repo.endswith(".git"):
        repo = repo[:-4]
        
    if not re.match(r'^[a-zA-Z0-9_.-]+$', owner) or not re.match(r'^[a-zA-Z0-9_.-]+$', repo):
        raise HTTPException(status_code=400, detail="Invalid characters in repository owner or name.")
        
    if ".." in owner or ".." in repo:
        raise HTTPException(status_code=400, detail="Invalid path traversal sequence in repository identifier.")

    return owner, repo

def is_safe_extract_path(target_dir: str, dest_path: str) -> bool:
    """
    Zip-slip / tarball traversal defense:
    Ensures dest_path resolves strictly within target_dir.
    """
    abs_target = os.path.abspath(target_dir)
    abs_dest = os.path.abspath(dest_path)
    return abs_dest.startswith(abs_target + os.sep) or abs_dest == abs_target

def is_text_file(filepath: str, blocksize: int = 1024) -> bool:
    """Determines whether a file is text (rather than binary/compiled)."""
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(blocksize)
            if b'\x00' in chunk:
                return False
        return True
    except Exception:
        return False

def safe_run_subprocess(
    cmd: list[str],
    cwd: Optional[str] = None,
    timeout: int = 60,
    env: Optional[dict] = None
) -> tuple[int, str, str]:
    """
    Safely executes a subprocess without shell interpolation.
    Enforces timeout, non-shell execution, and automatic credential redaction on stdout/stderr.
    """
    if not isinstance(cmd, list) or not all(isinstance(c, str) for c in cmd):
        raise ValueError("Subprocess command must be a list of strings.")

    try:
        res = subprocess.run(
            cmd,
            cwd=cwd,
            timeout=timeout,
            shell=False,
            capture_output=True,
            text=True,
            env=env
        )
        return (
            res.returncode,
            redact_text(res.stdout or ""),
            redact_text(res.stderr or "")
        )
    except subprocess.TimeoutExpired:
        return (-1, "", f"Command timed out after {timeout} seconds")
    except Exception as e:
        return (-2, "", f"Subprocess execution error: {redact_text(str(e))}")
