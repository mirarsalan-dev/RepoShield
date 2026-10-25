# RepoShield Dev Launcher (PowerShell)
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " RepoShield — GitHub Repository Security Analyzer" -ForegroundColor White
Write-Host " 'Secure Your Code Before You Deploy.'" -ForegroundColor Yellow
Write-Host " Strict Zero-Database Architecture • In-Memory & LocalStorage" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

$backendPath = Join-Path $PSScriptRoot "backend"
$frontendPath = Join-Path $PSScriptRoot "frontend"
$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

if (!(Test-Path $venvPython)) {
    Write-Host "Creating Python virtual environment in .venv..." -ForegroundColor Yellow
    python -m venv .venv
    & $venvPython -m pip install -r (Join-Path $backendPath "requirements.txt")
}

Write-Host "`nStarting Backend API on http://127.0.0.1:8000..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backendPath'; & '$venvPython' -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

Write-Host "Starting Frontend Web Application on http://localhost:3000..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$frontendPath'; npm run dev"

Write-Host "`nBoth services launched in dedicated terminal windows!" -ForegroundColor Cyan
Write-Host "Access Web Application: http://localhost:3000" -ForegroundColor White
Write-Host "Access API Swagger Docs: http://127.0.0.1:8000/docs`n" -ForegroundColor White
