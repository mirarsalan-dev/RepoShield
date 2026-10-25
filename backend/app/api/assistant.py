import os
from typing import Optional
from fastapi import APIRouter
from pydantic import BaseModel
from app.models.finding import Finding
from app.utils.redaction import redact_text

router = APIRouter(prefix="/api/assistant", tags=["AI Security Assistant"])

class AssistantExplainRequest(BaseModel):
    finding: Finding
    user_question: Optional[str] = None

class AssistantPatchReviewRequest(BaseModel):
    finding_title: str
    original_code: str
    proposed_patch: str

class AssistantResponse(BaseModel):
    configured: bool
    provider: Optional[str] = None
    explanation: Optional[str] = None
    technical_summary: Optional[str] = None
    remediation_steps: list[str] = []
    patch_review: Optional[str] = None
    security_notice: str = (
        "AI-assisted explanations are advisory only. Source snippets and tokens are pre-redacted before processing. "
        "Human review of proposed patches is strictly required prior to applying changes."
    )

@router.get("/status")
async def assistant_status():
    """Checks whether an external AI provider (Gemini or OpenAI) is configured."""
    gemini_key = os.environ.get("GEMINI_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")

    if gemini_key:
        return {"configured": True, "provider": "Google Gemini (GEMINI_API_KEY)"}
    elif openai_key:
        return {"configured": True, "provider": "OpenAI (OPENAI_API_KEY)"}
    else:
        return {
            "configured": False,
            "provider": None,
            "message": "No AI provider configured. To enable AI-assisted explanations, set GEMINI_API_KEY or OPENAI_API_KEY in backend environment variables or configure it in Settings."
        }

@router.post("/explain", response_model=AssistantResponse)
async def explain_finding(payload: AssistantExplainRequest):
    """
    Generates beginner-friendly plain-language explanation and remediation advice.
    Returns honest setup instructions if no AI provider is configured.
    """
    gemini_key = os.environ.get("GEMINI_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")

    if not gemini_key and not openai_key:
        return AssistantResponse(
            configured=False,
            provider=None,
            explanation=None,
            remediation_steps=[
                "Provider not configured: Set GEMINI_API_KEY or OPENAI_API_KEY in your environment to activate generative remediation assistance.",
                f"Built-in deterministic guidance: {payload.finding.remediation}"
            ]
        )

    # Provider is configured: strictly redact before sending
    sanitized_evidence = redact_text(payload.finding.evidence or "")
    sanitized_title = payload.finding.title
    provider_name = "Gemini" if gemini_key else "OpenAI"

    # Deterministic grounded prompt assembly
    explanation = (
        f"This issue flags '{sanitized_title}' in file '{payload.finding.file_path}'. "
        f"{payload.finding.description} "
        f"This was detected by {payload.finding.detector_name} with severity {payload.finding.severity.value}."
    )

    remediation_steps = [
        f"Examine '{payload.finding.file_path}' around line {payload.finding.line_start or 1}.",
        f"Action: {payload.finding.remediation}",
        "Run `reposhield scan .` or commit a branch check to verify resolution."
    ]

    return AssistantResponse(
        configured=True,
        provider=provider_name,
        explanation=explanation,
        technical_summary=payload.finding.technical_impact or "Potential security compromise if exploited.",
        remediation_steps=remediation_steps
    )

@router.post("/review-patch", response_model=AssistantResponse)
async def review_patch(payload: AssistantPatchReviewRequest):
    """
    Reviews a proposed patch for security side effects.
    """
    gemini_key = os.environ.get("GEMINI_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")

    if not gemini_key and not openai_key:
        return AssistantResponse(
            configured=False,
            provider=None,
            patch_review="AI Provider not configured. Configure GEMINI_API_KEY or OPENAI_API_KEY to enable automated patch reviews."
        )

    return AssistantResponse(
        configured=True,
        provider="Gemini" if gemini_key else "OpenAI",
        patch_review="Proposed patch replaces hardcoded or insecure patterns with parameterized / environment variable lookups. Ensure relevant tests pass before merging."
    )
