from datetime import datetime, timezone
from fastapi import APIRouter
from app.config import settings
from app.scanners.orchestrator import orchestrator

router = APIRouter(prefix="/api", tags=["System"])

@router.get("/health")
async def health_check():
    """
    Health check and scanner diagnostics.
    Verifies that the stateless server is operational and scanners are available.
    """
    gitleaks_avail, gitleaks_msg = await orchestrator.gitleaks.is_available()
    osv_avail, osv_msg = await orchestrator.osv.is_available()
    semgrep_avail, semgrep_msg = await orchestrator.semgrep.is_available()

    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "architecture": {
            "persistence": "NONE (Strictly stateless in-memory processing per architectural requirements)",
            "database_installed": False,
            "database_configured": False
        },
        "scanners": {
            "gitleaks": {
                "available": gitleaks_avail,
                "version": orchestrator.gitleaks.tool_version,
                "details": gitleaks_msg
            },
            "osv": {
                "available": osv_avail,
                "version": orchestrator.osv.tool_version,
                "details": osv_msg
            },
            "semgrep": {
                "available": semgrep_avail,
                "version": orchestrator.semgrep.tool_version,
                "details": semgrep_msg
            }
        }
    }
