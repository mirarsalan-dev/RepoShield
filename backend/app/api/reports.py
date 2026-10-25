from fastapi import APIRouter, HTTPException, Response
from app.core.memory_store import memory_store
from app.models.scan import ScanResult
from app.utils.csv_generator import generate_csv_report
from app.utils.pdf_generator import generate_pdf_report
from app.utils.sarif_generator import generate_sarif_report
from app.utils.sbom_generator import generate_cyclonedx_sbom, generate_spdx_sbom
from app.utils.vex_generator import generate_cyclonedx_vex

router = APIRouter(prefix="/api/reports", tags=["Reports"])

@router.get("/{scan_id}/json")
async def export_json_by_id(scan_id: str):
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found in active session. You can export locally saved scans via the Reports page."
        )
    return scan

@router.get("/{scan_id}/csv")
async def export_csv_by_id(scan_id: str):
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found in active session.")
    csv_content = generate_csv_report(scan)
    filename = f"reposhield-{scan.repo}-{scan.scan_id[:8]}.csv"
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/{scan_id}/pdf")
async def export_pdf_by_id(scan_id: str):
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found in active session.")
    pdf_bytes = generate_pdf_report(scan)
    filename = f"reposhield-{scan.repo}-{scan.scan_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/{scan_id}/sarif")
async def export_sarif_by_id(scan_id: str):
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found in active session.")
    sarif_content = generate_sarif_report(scan)
    filename = f"reposhield-{scan.repo}-{scan.scan_id[:8]}.sarif"
    return Response(
        content=sarif_content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/{scan_id}/cyclonedx")
async def export_cyclonedx_by_id(scan_id: str):
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found in active session.")
    sbom_content = generate_cyclonedx_sbom(scan)
    filename = f"reposhield-{scan.repo}-cyclonedx.json"
    return Response(
        content=sbom_content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/{scan_id}/spdx")
async def export_spdx_by_id(scan_id: str):
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found in active session.")
    sbom_content = generate_spdx_sbom(scan)
    filename = f"reposhield-{scan.repo}-spdx.json"
    return Response(
        content=sbom_content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

# Stateless client endpoints (enabling export of client-side localStorage scans)
@router.post("/export/csv")
async def export_custom_csv(scan: ScanResult):
    csv_content = generate_csv_report(scan)
    filename = f"reposhield-{scan.repo}-{scan.scan_id[:8]}.csv"
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.post("/export/pdf")
async def export_custom_pdf(scan: ScanResult):
    pdf_bytes = generate_pdf_report(scan)
    filename = f"reposhield-{scan.repo}-{scan.scan_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.post("/export/sarif")
async def export_custom_sarif(scan: ScanResult):
    sarif_content = generate_sarif_report(scan)
    filename = f"reposhield-{scan.repo}-{scan.scan_id[:8]}.sarif"
    return Response(
        content=sarif_content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.post("/export/cyclonedx")
async def export_custom_cyclonedx(scan: ScanResult):
    sbom_content = generate_cyclonedx_sbom(scan)
    filename = f"reposhield-{scan.repo}-cyclonedx.json"
    return Response(
        content=sbom_content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.post("/export/spdx")
async def export_custom_spdx(scan: ScanResult):
    sbom_content = generate_spdx_sbom(scan)
    filename = f"reposhield-{scan.repo}-spdx.json"
    return Response(
        content=sbom_content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/{scan_id}/vex")
async def export_vex_by_id(scan_id: str):
    scan = await memory_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found in active session.")
    vex_content = generate_cyclonedx_vex(scan)
    filename = f"reposhield-{scan.repo}-cyclonedx-vex.json"
    return Response(
        content=vex_content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.post("/export/vex")
async def export_custom_vex(scan: ScanResult):
    vex_content = generate_cyclonedx_vex(scan)
    filename = f"reposhield-{scan.repo}-cyclonedx-vex.json"
    return Response(
        content=vex_content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

