"""
API Router for Fix Validation Lab in RepoShield V2.
Allows developers to submit proposed remediation patches and receive real-time scanner validation.
"""
from fastapi import APIRouter, HTTPException
from app.services.fix_validation_service import (
    fix_validation_service,
    FixValidationRequest,
    FixValidationResult
)

router = APIRouter(prefix="/api/fix-validation", tags=["Fix Validation"])

@router.post("/validate", response_model=FixValidationResult)
async def validate_patch(request: FixValidationRequest):
    """
    Validates a security patch in an ephemeral isolated sandbox without committing or deploying code.
    Runs the exact detector rule to verify if the vulnerability is resolved or if regressions were introduced.
    """
    if not request.remediated_code.strip():
        raise HTTPException(status_code=400, detail="Remediated code content cannot be empty.")
    
    result = await fix_validation_service.validate_fix(request)
    return result
