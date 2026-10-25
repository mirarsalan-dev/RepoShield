from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Header
import httpx
from app.config import settings
from app.core.security import parse_and_validate_github_url
from app.models.github import (
    RepoValidationRequest,
    RepoValidationResponse,
    RepositoryMetadata,
    BranchInfo
)

router = APIRouter(prefix="/api/github", tags=["GitHub"])

def get_auth_headers(custom_token: Optional[str] = None) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "RepoShield-Security-Scanner/1.0"
    }
    token = custom_token or settings.GITHUB_DEFAULT_TOKEN
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers

@router.post("/validate", response_model=RepoValidationResponse)
async def validate_repo_url(payload: RepoValidationRequest):
    """
    Validates that a submitted repository URL is a valid, supported public GitHub repository.
    Enforces strict SSRF protection and path traversal checks.
    """
    owner, repo = parse_and_validate_github_url(payload.url)
    return RepoValidationResponse(
        valid=True,
        owner=owner,
        repo=repo,
        canonical_url=f"https://github.com/{owner}/{repo}"
    )

@router.get("/repo-info", response_model=RepositoryMetadata)
async def get_repository_info(
    url: str = Query(..., description="GitHub repository URL"),
    x_github_token: Optional[str] = Header(None, description="Optional GitHub Personal Access Token")
):
    """
    Retrieves live public repository metadata using GitHub REST API.
    """
    owner, repo = parse_and_validate_github_url(url)
    headers = get_auth_headers(x_github_token)

    async with httpx.AsyncClient(timeout=10.0) as client:
        # 1. Fetch repo core info
        repo_resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers)
        
        if repo_resp.status_code == 404:
            raise HTTPException(status_code=404, detail=f"Repository '{owner}/{repo}' not found on GitHub or is private.")
        elif repo_resp.status_code == 403:
            remaining = repo_resp.headers.get("x-ratelimit-remaining", "0")
            if remaining == "0":
                raise HTTPException(
                    status_code=429,
                    detail="GitHub API rate limit exceeded for anonymous IP. Please supply a GitHub Personal Access Token in Settings."
                )
            raise HTTPException(status_code=403, detail="Access denied by GitHub API.")
        elif repo_resp.status_code != 200:
            raise HTTPException(status_code=repo_resp.status_code, detail=f"GitHub API error: {repo_resp.text[:100]}")

        repo_data = repo_resp.json()

        # 2. Fetch languages breakdown
        languages = {}
        try:
            lang_resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}/languages", headers=headers)
            if lang_resp.status_code == 200:
                languages = lang_resp.json()
        except Exception:
            pass

        return RepositoryMetadata(
            name=repo_data.get("name", repo),
            owner=repo_data.get("owner", {}).get("login", owner),
            full_name=repo_data.get("full_name", f"{owner}/{repo}"),
            description=repo_data.get("description"),
            default_branch=repo_data.get("default_branch", "main"),
            stars=repo_data.get("stargazers_count", 0),
            forks=repo_data.get("forks_count", 0),
            open_issues=repo_data.get("open_issues_count", 0),
            primary_language=repo_data.get("language"),
            languages=languages,
            last_updated=repo_data.get("updated_at"),
            created_at=repo_data.get("created_at"),
            html_url=repo_data.get("html_url", f"https://github.com/{owner}/{repo}"),
            is_private=repo_data.get("private", False),
            size_kb=repo_data.get("size", 0)
        )

@router.get("/branches", response_model=list[BranchInfo])
async def get_branches(
    url: str = Query(..., description="GitHub repository URL"),
    x_github_token: Optional[str] = Header(None, description="Optional GitHub token")
):
    """
    Lists repository branches for user selection prior to scanning.
    """
    owner, repo = parse_and_validate_github_url(url)
    headers = get_auth_headers(x_github_token)

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/branches?per_page=30",
            headers=headers
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Unable to retrieve branches from GitHub.")

        branches_data = resp.json()
        branches = []
        for b in branches_data:
            branches.append(BranchInfo(
                name=b.get("name", "unknown"),
                commit_sha=b.get("commit", {}).get("sha", ""),
                protected=b.get("protected", False)
            ))
        return branches
