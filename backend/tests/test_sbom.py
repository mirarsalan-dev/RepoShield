import json
import pytest
from app.models.sbom import SBOMComponent
from app.models.scan import ScanResult, ScanState
from app.utils.sbom_generator import generate_cyclonedx_sbom, generate_spdx_sbom

def test_cyclonedx_sbom_generation():
    scan = ScanResult(
        scan_id="test-sbom-1",
        repo_url="https://github.com/org/app",
        owner="org",
        repo="app",
        branch="main",
        status=ScanState.COMPLETED,
        started_at="2026-10-24T12:00:00Z",
        sbom_components=[
            SBOMComponent(
                name="express",
                version="4.18.2",
                ecosystem="npm",
                purl="pkg:npm/express@4.18.2",
                license="MIT",
                manifest_path="package.json",
                direct=True
            )
        ]
    )

    cdx_str = generate_cyclonedx_sbom(scan)
    data = json.loads(cdx_str)

    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.5"
    assert len(data["components"]) == 1
    assert data["components"][0]["name"] == "express"
    assert data["components"][0]["version"] == "4.18.2"

def test_spdx_sbom_generation():
    scan = ScanResult(
        scan_id="test-sbom-2",
        repo_url="https://github.com/org/app",
        owner="org",
        repo="app",
        branch="main",
        status=ScanState.COMPLETED,
        started_at="2026-10-24T12:00:00Z",
        sbom_components=[
            SBOMComponent(
                name="requests",
                version="2.31.0",
                ecosystem="PyPI",
                purl="pkg:pypi/requests@2.31.0",
                license="Apache-2.0",
                manifest_path="requirements.txt",
                direct=True
            )
        ]
    )

    spdx_str = generate_spdx_sbom(scan)
    data = json.loads(spdx_str)

    assert data["spdxVersion"] == "SPDX-2.3"
    assert len(data["packages"]) == 2 # 1 Root application + 1 component package
    pkg = next(p for p in data["packages"] if p["name"] == "requests")
    assert pkg["versionInfo"] == "2.31.0"
