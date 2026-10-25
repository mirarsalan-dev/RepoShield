import os
from pydantic import BaseModel, Field

class Settings(BaseModel):
    APP_NAME: str = "RepoShield — GitHub Repository Security Analyzer"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "https://*.vercel.app",
        "*"
    ]
    MAX_SCAN_SIZE_MB: int = int(os.getenv("MAX_SCAN_SIZE_MB", "100"))
    MAX_FILE_SIZE_BYTES: int = int(os.getenv("MAX_FILE_SIZE_BYTES", "10485760")) # 10MB
    MAX_SCAN_TIMEOUT_SECONDS: int = int(os.getenv("MAX_SCAN_TIMEOUT_SECONDS", "180"))
    SCAN_TTL_SECONDS: int = int(os.getenv("SCAN_TTL_SECONDS", "1800")) # 30 mins
    GITHUB_DEFAULT_TOKEN: str | None = os.getenv("GITHUB_TOKEN", None)
    
    # OSV API Endpoint
    OSV_API_URL: str = "https://api.osv.dev/v1/querybatch"
    OSV_QUERY_URL: str = "https://api.osv.dev/v1/query"

settings = Settings()
