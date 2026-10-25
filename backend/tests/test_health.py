import asyncio
from app.main import root
from app.api.health import health_check

def test_root_endpoint():
    data = asyncio.run(root())
    assert data["status"] == "online"
    assert "Stateless" in data["architecture"]

def test_health_check_endpoint():
    data = asyncio.run(health_check())
    assert data["status"] == "healthy"
    assert data["architecture"]["database_installed"] is False
    assert data["architecture"]["database_configured"] is False
    assert "scanners" in data
    assert "gitleaks" in data["scanners"]
    assert "osv" in data["scanners"]
    assert "semgrep" in data["scanners"]
