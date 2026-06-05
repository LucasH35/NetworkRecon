"""Modèles Pydantic pour MongoDB."""

# Modèles existants
from app.models.host import Host, HostCreate, HostUpdate
from app.models.scan import Scan, ScanCreate, ScanResult, ScanStatus
from app.models.network import NetworkRange, NetworkRangeCreate

# Nouveaux modèles pour NetworkRecon
from app.models.host import (
    PortInfo,
    HostInfo,
    HostResponse,
)
from app.models.scan import (
    ScanTarget,
    ScanConfig,
    Campaign,
    CampaignStatus,
    ScanScanType,
    ScanResultLegacy,
)
from app.models.vulnerability import (
    CVE,
    Vulnerability,
    VulnerabilityScanResult,
    Severity,
)
from app.models.mitre import (
    MitreMapping,
    ServiceToMitre,
)
from app.models.auth_test import (
    AuthTestConfig,
    AuthTestResult,
    AuthCampaign,
    ServiceType,
    AuthCampaignStatus,
)
from app.models.report import (
    ReportSummary,
    Report,
    ExportFormat,
)

__all__ = [
    # Modèles existants
    "Host",
    "HostCreate",
    "HostUpdate",
    "Scan",
    "ScanCreate",
    "ScanResult",
    "ScanStatus",
    "NetworkRange",
    "NetworkRangeCreate",
    # Nouveaux modèles
    "PortInfo",
    "HostInfo",
    "HostResponse",
    "ScanTarget",
    "ScanConfig",
    "Campaign",
    "CampaignStatus",
    "ScanScanType",
    "ScanResultLegacy",
    "CVE",
    "Vulnerability",
    "VulnerabilityScanResult",
    "Severity",
    "MitreMapping",
    "ServiceToMitre",
    "AuthTestConfig",
    "AuthTestResult",
    "AuthCampaign",
    "ServiceType",
    "AuthCampaignStatus",
    "ReportSummary",
    "Report",
    "ExportFormat",
]
