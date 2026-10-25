from typing import Optional
from pydantic import BaseModel, HttpUrl

class RepoValidationRequest(BaseModel):
    url: str

class RepoValidationResponse(BaseModel):
    valid: bool
    owner: str
    repo: str
    canonical_url: str

class BranchInfo(BaseModel):
    name: str
    commit_sha: str
    protected: bool = False

class CommitInfo(BaseModel):
    sha: str
    message: str
    author: str
    date: str

class RepositoryMetadata(BaseModel):
    name: str
    owner: str
    full_name: str
    description: Optional[str] = None
    default_branch: str
    stars: int = 0
    forks: int = 0
    open_issues: int = 0
    primary_language: Optional[str] = None
    languages: dict[str, int] = {}
    last_updated: Optional[str] = None
    created_at: Optional[str] = None
    html_url: str
    is_private: bool = False
    size_kb: int = 0
