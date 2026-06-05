"""Routes API FastAPI."""

from app.routes import scans, hosts, network, vulnerabilities, mitre, auth_tests, reports, dashboard

__all__ = ["scans", "hosts", "network", "vulnerabilities", "mitre", "auth_tests", "reports", "dashboard"]
