import sys
import os

# Add backend directory to path so 'app' module imports resolve cleanly
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app.main import app

# Provide both ASGI 'app' and Mangum 'handler' for Vercel Python serverless compatibility
try:
    from mangum import Mangum
    handler = Mangum(app)
except Exception:
    handler = app
