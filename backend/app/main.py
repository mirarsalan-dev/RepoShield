from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import settings
from app.api import health, github, scan, reports, policy, assistant, fix_validation, website_security

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="RepoShield — Production-oriented GitHub repository security analyzer for exposed secrets, vulnerable dependencies, and insecure coding patterns. Zero-database architecture."
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(health.router)
app.include_router(github.router)
app.include_router(scan.router)
app.include_router(reports.router)
app.include_router(policy.router)
app.include_router(assistant.router)
app.include_router(fix_validation.router)
app.include_router(website_security.router)

@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "tagline": "Secure Your Code Before You Deploy.",
        "status": "online",
        "docs_url": "/docs",
        "health_url": "/api/health",
        "architecture": "Stateless In-Memory & Client-Side Local Storage (No Database)"
    }

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {str(exc)}"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
