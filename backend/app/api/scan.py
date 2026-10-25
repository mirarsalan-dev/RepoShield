import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks, Header
from app.core.security import parse_and_validate_github_url
from app.core.memory_store import memory_store
from app.models.scan import ScanRequest, ScanResponse, ScanResult, ScanState
from app.scanners.orchestrator import orchestrator

router = APIRouter(prefix="/api/scan", tags=["Scanning"])

@router.post("", response_model=ScanResponse)
async def start_scan(
    payload: ScanRequest,
    x_github_token: Optional[str] = Header(None, description="Optional GitHub Personal Access Token")
):
    """
    Initiates an ephemeral security scan against a public GitHub repository.
    Enforces SSRF validation, isolated worker execution, and in-memory temporary storage.
    """
    owner, repo = parse_and_validate_github_url(payload.repo_url)
    scan_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()

    # Create initial ephemeral scan result
    scan_result = ScanResult(
        scan_id=scan_id,
        repo_url=f"https://github.com/{owner}/{repo}",
        owner=owner,
        repo=repo,
        branch=payload.branch or "default",
        commit_sha=payload.commit_sha,
        status=ScanState.QUEUED,
        progress=5,
        current_step="Scan queued for isolated worker execution",
        started_at=started_at,
        logs=[f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Scan queued for {owner}/{repo}"]
    )

    await memory_store.save_scan(scan_result)

    # Launch asynchronous background task
    token = payload.github_token or x_github_token
    asyncio.create_task(
        orchestrator.execute_scan(
            scan_id=scan_id,
            repo_url=payload.repo_url,
            branch=payload.branch,
            commit_sha=payload.commit_sha,
            github_token=token,
            enable_secrets=payload.enable_secrets,
            enable_dependencies=payload.enable_dependencies,
            enable_sast=payload.enable_sast,
            enable_infrastructure=payload.enable_infrastructure
        )
    )

    return ScanResponse(
        scan_id=scan_id,
        repo_url=f"https://github.com/{owner}/{repo}",
        status=ScanState.QUEUED,
        message="Security scan initiated in temporary isolated worker."
    )

@router.get("/test-lab/fixtures")
async def get_test_lab_fixtures():
    """
    Returns the curated collection of safe test fixtures for scanner validation.
    """
    from app.services.test_lab_service import SAFE_FIXTURES
    return SAFE_FIXTURES

@router.get("/test-lab/benchmark")
async def run_test_lab():
    """
    Executes the Safe Security Test Lab benchmark against detector rules.
    """
    from app.services.test_lab_service import run_test_lab_benchmark
    return run_test_lab_benchmark()

@router.post("/test-lab/live-test")
async def test_lab_live_test(payload: dict):
    """
    Executes live security detection engines on arbitrary source code snippets.
    Zero dummy data: executes real Gitleaks, Semgrep, and ConfigScanner engines in isolated temporary sandbox.
    """
    from app.services.test_lab_service import run_live_code_scan
    code = payload.get("code", "")
    language = payload.get("language", "python")
    filename = payload.get("filename")
    return await run_live_code_scan(code=code, language=language, filename=filename)

@router.post("/test-lab/benchmark-scan")
async def test_lab_benchmark_scan(payload: dict):
    """
    Executes live detector verification against real findings from a scanned repository.
    Zero dummy data: operates strictly on the user's real repository findings.
    """
    from app.services.test_lab_service import benchmark_scan_findings
    scan_data = payload.get("scan") or payload
    return await benchmark_scan_findings(scan_data)

@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan_status(scan_id: str):
    """
    Returns real-time scan progress, logs, scanner execution coverage, findings, and risk score.
    Returns 404 if scan has expired from ephemeral RAM or is invalid.
    """
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found or expired from in-memory session. Historical scans are stored locally in your browser localStorage."
        )
    return scan

@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """
    Cancels an active scan and purges temporary files.
    """
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    if scan.status in [ScanState.COMPLETED, ScanState.FAILED, ScanState.CANCELLED]:
        return {"message": f"Scan is already in terminal state: {scan.status}"}

    await memory_store.update_scan(
        scan_id,
        status=ScanState.CANCELLED,
        current_step="Scan manually cancelled by user",
        completed_at=datetime.now(timezone.utc).isoformat()
    )
    return {"message": "Scan cancelled successfully."}

@router.get("/{scan_id}/timeline")
async def get_scan_timeline(scan_id: str):
    """
    Returns synthesized incident timeline for an active in-memory scan.
    """
    from app.services.timeline_service import extract_timeline_events
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found in active session.")
    events = extract_timeline_events(scan)
    return {"scan_id": scan_id, "total_events": len(events), "events": events}

@router.post("/timeline")
async def generate_custom_timeline(payload: dict):
    """
    Synthesizes incident timeline for client-provided scan and optional history.
    Enables timeline correlation for historical scans stored in browser localStorage.
    """
    from app.services.timeline_service import extract_timeline_events
    scan_data = payload.get("scan")
    if not scan_data:
        raise HTTPException(status_code=400, detail="Missing 'scan' in payload.")
    scan = ScanResult(**scan_data)
    prior_scans_data = payload.get("prior_scans", [])
    prior_scans = [ScanResult(**s) for s in prior_scans_data]
    reviews = payload.get("review_annotations", {})
    events = extract_timeline_events(scan, prior_scans=prior_scans, review_annotations=reviews)
    return {"scan_id": scan.scan_id, "total_events": len(events), "events": events}

@router.get("/{scan_id}/supply-chain")
async def get_scan_supply_chain(scan_id: str):
    """
    Returns software supply chain integrity analysis for an active in-memory scan.
    """
    from app.services.supply_chain_service import analyze_supply_chain
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found in active session.")
    report = analyze_supply_chain(scan)
    return report

@router.post("/supply-chain")
async def generate_custom_supply_chain(scan: ScanResult):
    """
    Returns software supply chain integrity analysis for a client-provided scan.
    """
    from app.services.supply_chain_service import analyze_supply_chain
    report = analyze_supply_chain(scan)
    return report

@router.get("/{scan_id}/dataflow")
async def get_scan_dataflow(scan_id: str):
    """
    Returns source-to-sink data flow analysis for an active in-memory scan.
    """
    from app.services.dataflow_service import extract_source_sink_flows
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found in active session.")
    return extract_source_sink_flows(scan)

@router.post("/dataflow")
async def generate_custom_dataflow(scan: ScanResult):
    """
    Returns source-to-sink data flow analysis for a client-provided scan.
    """
    from app.services.dataflow_service import extract_source_sink_flows
    return extract_source_sink_flows(scan)

@router.get("/{scan_id}/exploitability")
async def get_scan_exploitability(scan_id: str):
    """
    Returns the Exploitability Evidence Board report for an active in-memory scan.
    """
    from app.services.exploitability_service import build_exploitability_board
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found in active session.")
    return build_exploitability_board(scan)

@router.post("/exploitability")
async def generate_custom_exploitability(scan: ScanResult):
    """
    Returns the Exploitability Evidence Board report for a client-provided scan.
    """
    from app.services.exploitability_service import build_exploitability_board
    return build_exploitability_board(scan)

@router.get("/{scan_id}/container")
async def get_scan_container(scan_id: str):
    """
    Returns container configuration and Dockerfile inspection for an active in-memory scan.
    """
    from app.services.container_inspector_service import inspect_container_security
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found in active session.")
    return inspect_container_security(scan)

@router.post("/container")
async def generate_custom_container(scan: ScanResult):
    """
    Returns container configuration and Dockerfile inspection for a client-provided scan.
    """
    from app.services.container_inspector_service import inspect_container_security
    return inspect_container_security(scan)

@router.get("/{scan_id}/compliance")
async def get_scan_compliance(scan_id: str):
    """
    Returns compliance evidence mappings (OWASP ASVS & NIST SSDF) for an active in-memory scan.
    """
    from app.services.compliance_service import generate_compliance_evidence
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found in active session.")
    return generate_compliance_evidence(scan)

@router.post("/compliance")
async def generate_custom_compliance(scan: ScanResult):
    """
    Returns compliance evidence mappings (OWASP ASVS & NIST SSDF) for a client-provided scan.
    """
    from app.services.compliance_service import generate_compliance_evidence
    return generate_compliance_evidence(scan)
