import json
import uuid
from datetime import datetime, timezone
from app.models.scan import ScanResult

def generate_cyclonedx_sbom(scan: ScanResult) -> str:
    """
    Generates a CycloneDX 1.5 JSON Software Bill of Materials (SBOM).
    """
    serial = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.now(timezone.utc).isoformat()

    components = []
    for c in scan.sbom_components:
        comp_obj = {
            "type": "library",
            "name": c.name,
            "version": c.version,
            "purl": c.purl or f"pkg:generic/{c.name}@{c.version}",
            "scope": "required" if c.direct else "optional",
            "licenses": [
                {
                    "license": {
                        "id": c.license if c.license != "Unknown" else None,
                        "name": c.license
                    }
                }
            ],
            "properties": [
                {"name": "reposhield:ecosystem", "value": c.ecosystem},
                {"name": "reposhield:manifestPath", "value": c.manifest_path},
                {"name": "reposhield:direct", "value": str(c.direct).lower()}
            ]
        }
        components.append(comp_obj)

    # Correlate vulnerabilities with components
    vulnerabilities = []
    for f in scan.findings:
        if f.package_name:
            vuln_obj = {
                "id": f.cve_id or f.ghsa_id or f.rule_id,
                "source": {
                    "name": "OSV / GitHub Security Advisory",
                    "url": f"https://osv.dev/vulnerability/{f.rule_id}"
                },
                "ratings": [
                    {
                        "severity": f.severity.value.lower(),
                        "score": f.cvss_score
                    }
                ] if f.cvss_score else [],
                "description": f.description[:300] if f.description else f.title,
                "recommendation": f.remediation,
                "affects": [
                    {
                        "ref": f"pkg:generic/{f.package_name}@{f.installed_version}" if f.installed_version else f.package_name
                    }
                ]
            }
            vulnerabilities.append(vuln_obj)

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "RepoShield",
                    "name": "RepoShield SBOM Generator",
                    "version": "2.0.0"
                }
            ],
            "component": {
                "type": "application",
                "name": f"{scan.owner}/{scan.repo}",
                "version": scan.commit_sha[:7] if scan.commit_sha else "HEAD"
            }
        },
        "components": components,
        "vulnerabilities": vulnerabilities
    }

    return json.dumps(doc, indent=2)

def generate_spdx_sbom(scan: ScanResult) -> str:
    """
    Generates an SPDX 2.3 JSON Software Bill of Materials (SBOM).
    """
    doc_namespace = f"https://reposhield.dev/spdx/{scan.owner}/{scan.repo}/{uuid.uuid4()}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    packages = []
    relationships = []

    # Root package
    root_spdx_id = "SPDXRef-Application"
    packages.append({
        "SPDXID": root_spdx_id,
        "name": f"{scan.owner}/{scan.repo}",
        "versionInfo": scan.commit_sha[:7] if scan.commit_sha else "HEAD",
        "downloadLocation": f"https://github.com/{scan.owner}/{scan.repo}",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION"
    })

    for idx, c in enumerate(scan.sbom_components, start=1):
        spdx_id = f"SPDXRef-Package-{idx}"
        packages.append({
            "SPDXID": spdx_id,
            "name": c.name,
            "versionInfo": c.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": c.license if c.license != "Unknown" else "NOASSERTION",
            "licenseDeclared": c.license if c.license != "Unknown" else "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": c.purl or f"pkg:generic/{c.name}@{c.version}"
                }
            ]
        })

        relationships.append({
            "spdxElementId": root_spdx_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": spdx_id
        })

    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"RepoShield-SBOM-{scan.owner}-{scan.repo}",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: RepoShield-2.0.0"]
        },
        "packages": packages,
        "relationships": relationships
    }

    return json.dumps(doc, indent=2)
