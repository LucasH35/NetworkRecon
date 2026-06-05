"""Point d'entrée FastAPI pour NetworkRecon."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routes import scans, hosts, network, vulnerabilities, mitre, auth_tests, reports, dashboard, sqlmap


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestion du cycle de vie de l'application."""
    # Startup
    yield
    # Shutdown


app = FastAPI(
    title="NetworkRecon API",
    description="API de reconnaissance réseau asynchrone",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(hosts.router, prefix="/api/hosts", tags=["hosts"])
app.include_router(network.router, prefix="/api/network", tags=["network"])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["vulnerabilities"])
app.include_router(mitre.router, prefix="/api/mitre", tags=["mitre"])
app.include_router(auth_tests.router, prefix="/api/auth-tests", tags=["auth-tests"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(sqlmap.router, prefix="/api/sqlmap", tags=["sqlmap"])


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/docs/info")
async def api_info():
    """Informations sur l'API."""
    return {
        "title": "NetworkRecon API",
        "version": "0.1.0",
        "description": "API de reconnaissance réseau asynchrone avec scan de ports, détection de vulnérabilités et mapping MITRE ATT&CK.",
        "endpoints": {
            "scans": "/api/scans",
            "hosts": "/api/hosts",
            "vulnerabilities": "/api/vulnerabilities",
            "mitre": "/api/mitre",
            "auth_tests": "/api/auth-tests",
            "reports": "/api/reports",
            "dashboard": "/api/dashboard",
            "health": "/health",
            "docs": "/docs",
            "redoc": "/redoc",
        },
    }
