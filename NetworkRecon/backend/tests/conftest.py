"""Fixtures partagées pour les tests d'intégration NetworkRecon.

Fournit :
- Mock MongoDB (mongomock_motor) pour isoler les tests
- Données de test réalistes pour la plage 192.168.2.0/24
- Client FastAPI asynchrone via httpx
- Fonctions utilitaires de peuplement de la base de test

Stratégie de mock MongoDB :
    On patch `get_database` à TOUS les niveaux d'import pour que
    tous les appels retournent notre DB mockée.
"""

import asyncio
from datetime import datetime, timedelta
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.main import app
from app.models.auth_test import (
    AuthTestConfig,
    AuthTestResult,
    ServiceType,
)
from app.models.host import HostInfo, PortInfo, Protocol, PortState
from app.models.report import ExportFormat, Report, ReportSummary
from app.models.scan import (
    Campaign,
    CampaignStatus,
    ScanConfig,
    ScanResult,
    ScanScanType,
    ScanStatus,
    ScanTarget,
)
from app.models.vulnerability import (
    CVE,
    MitreMapping,
    Severity,
    Vulnerability,
    VulnerabilityScanResult,
)


# ---------------------------------------------------------------------------
# Données de test réalistes – plage 192.168.2.0/24
# ---------------------------------------------------------------------------

TEST_HOSTS = [
    {
        "ip_address": "192.168.2.1",
        "hostname": "gateway.local",
        "mac_address": "AA:BB:CC:00:01:01",
        "os_detection": "Linux 5.15 (Ubuntu 22.04)",
        "status": "up",
        "ports": [
            {"number": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.9p1", "banner": "SSH-2.0-OpenSSH_8.9p1"},
            {"number": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "nginx 1.18.0", "banner": "HTTP/1.1 200 OK"},
            {"number": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.18.0", "banner": None},
        ],
        "last_seen": datetime.utcnow(),
        "first_seen": datetime.utcnow() - timedelta(hours=2),
    },
    {
        "ip_address": "192.168.2.10",
        "hostname": "webserver.local",
        "mac_address": "AA:BB:CC:00:02:01",
        "os_detection": "Linux 5.4 (Debian 11)",
        "status": "up",
        "ports": [
            {"number": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.4p1", "banner": "SSH-2.0-OpenSSH_8.4p1"},
            {"number": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.4.51", "banner": "Apache/2.4.51"},
            {"number": 3306, "protocol": "tcp", "state": "open", "service": "mysql", "version": "MySQL 8.0.28", "banner": None},
        ],
        "last_seen": datetime.utcnow(),
        "first_seen": datetime.utcnow() - timedelta(hours=3),
    },
    {
        "ip_address": "192.168.2.50",
        "hostname": "dbserver.local",
        "mac_address": "AA:BB:CC:00:03:01",
        "os_detection": "Windows Server 2019",
        "status": "up",
        "ports": [
            {"number": 3389, "protocol": "tcp", "state": "open", "service": "rdp", "version": "Microsoft Terminal Services", "banner": None},
            {"number": 1433, "protocol": "tcp", "state": "open", "service": "mssql", "version": "Microsoft SQL Server 2019", "banner": None},
            {"number": 445, "protocol": "tcp", "state": "open", "service": "smb", "version": "Windows SMB", "banner": None},
        ],
        "last_seen": datetime.utcnow(),
        "first_seen": datetime.utcnow() - timedelta(hours=1),
    },
    {
        "ip_address": "192.168.2.100",
        "hostname": "printer.local",
        "mac_address": "AA:BB:CC:00:04:01",
        "os_detection": None,
        "status": "up",
        "ports": [
            {"number": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "HP Embedded Web Server", "banner": None},
            {"number": 631, "protocol": "tcp", "state": "open", "service": "ipp", "version": None, "banner": None},
        ],
        "last_seen": datetime.utcnow(),
        "first_seen": datetime.utcnow() - timedelta(hours=5),
    },
    {
        "ip_address": "192.168.2.200",
        "hostname": "nas.local",
        "mac_address": "AA:BB:CC:00:05:01",
        "os_detection": "Linux 4.19 (Synology DSM 7.1)",
        "status": "up",
        "ports": [
            {"number": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 7.4", "banner": "SSH-2.0-OpenSSH_7.4"},
            {"number": 5000, "protocol": "tcp", "state": "open", "service": "http", "version": "Synology DSM", "banner": None},
            {"number": 5001, "protocol": "tcp", "state": "open", "service": "https", "version": "Synology DSM", "banner": None},
            {"number": 21, "protocol": "tcp", "state": "open", "service": "ftp", "version": "vsftpd 3.0.3", "banner": "220 (vsFTPd 3.0.3)"},
        ],
        "last_seen": datetime.utcnow(),
        "first_seen": datetime.utcnow() - timedelta(hours=4),
    },
]

TEST_CVE_DATA = [
    CVE(cve_id="CVE-2023-44487", description="HTTP/2 Rapid Reset Attack", severity=Severity.CRITICAL, cvss_score=7.5, affected_products=["nginx"]),
    CVE(cve_id="CVE-2021-44228", description="Apache Log4j2 - Log4Shell", severity=Severity.CRITICAL, cvss_score=10.0, affected_products=["Apache Log4j"]),
    CVE(cve_id="CVE-2023-0217", description="Injection SQL MySQL", severity=Severity.HIGH, cvss_score=8.1, affected_products=["MySQL 8.0"]),
    CVE(cve_id="CVE-2023-21746", description="Elevation privilege Windows", severity=Severity.HIGH, cvss_score=7.8, affected_products=["Windows Server 2019"]),
    CVE(cve_id="CVE-2022-40684", description="Bypass auth FortiOS", severity=Severity.CRITICAL, cvss_score=9.8, affected_products=["FortiOS"]),
    CVE(cve_id="CVE-2023-38831", description="Execution via ZIP", severity=Severity.MEDIUM, cvss_score=6.5, affected_products=["7-Zip"]),
    CVE(cve_id="CVE-2023-22527", description="Injection Confluence", severity=Severity.CRITICAL, cvss_score=9.8, affected_products=["Confluence"]),
    CVE(cve_id="CVE-2024-3094", description="Backdoor xz Utils", severity=Severity.CRITICAL, cvss_score=10.0, affected_products=["xz Utils"]),
    CVE(cve_id="CVE-2023-46747", description="Bypass auth F5 BIG-IP", severity=Severity.CRITICAL, cvss_score=9.8, affected_products=["F5 BIG-IP"]),
    CVE(cve_id="CVE-2022-30190", description="Follina MSDT", severity=Severity.HIGH, cvss_score=7.8, affected_products=["Windows"]),
]

TEST_MITRE_MAPPINGS = [
    MitreMapping(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1190/"),
    MitreMapping(technique_id="T1021", technique_name="Remote Services", tactic="Lateral Movement", url="https://attack.mitre.org/techniques/T1021/"),
    MitreMapping(technique_id="T1078", technique_name="Valid Accounts", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1078/"),
    MitreMapping(technique_id="T1046", technique_name="Network Service Scanning", tactic="Discovery", url="https://attack.mitre.org/techniques/T1046/"),
    MitreMapping(technique_id="T1059", technique_name="Command and Scripting Interpreter", tactic="Execution", url="https://attack.mitre.org/techniques/T1059/"),
]

TEST_VULNERABILITIES = [
    Vulnerability(host_ip="192.168.2.1", port=443, service="https", cve=TEST_CVE_DATA[0], mitre_mapping=TEST_MITRE_MAPPINGS[0], remediation="Update nginx"),
    Vulnerability(host_ip="192.168.2.10", port=80, service="http", cve=TEST_CVE_DATA[1], mitre_mapping=TEST_MITRE_MAPPINGS[0], remediation="Update Log4j"),
    Vulnerability(host_ip="192.168.2.10", port=3306, service="mysql", cve=TEST_CVE_DATA[2], mitre_mapping=TEST_MITRE_MAPPINGS[1], remediation="Apply Oracle CPU"),
    Vulnerability(host_ip="192.168.2.50", port=3389, service="rdp", cve=TEST_CVE_DATA[3], mitre_mapping=TEST_MITRE_MAPPINGS[0], remediation="Apply MS patches"),
    Vulnerability(host_ip="192.168.2.50", port=445, service="smb", cve=TEST_CVE_DATA[9], mitre_mapping=TEST_MITRE_MAPPINGS[1], remediation="Disable SMBv1"),
    Vulnerability(host_ip="192.168.2.200", port=21, service="ftp", cve=TEST_CVE_DATA[5], mitre_mapping=TEST_MITRE_MAPPINGS[2], remediation="Migrate to SFTP"),
]


# ---------------------------------------------------------------------------
# Patch targets – tous les modules qui importent get_database
# ---------------------------------------------------------------------------

# Modules qui importent get_database directement
_GET_DATABASE_PATCH_TARGETS = [
    "app.routes.scans.get_database",
    "app.routes.hosts.get_database",
    "app.routes.vulnerabilities.get_database",
    "app.routes.mitre.get_database",
    "app.routes.auth_tests.get_database",
    "app.routes.reports.get_database",
    "app.routes.dashboard.get_database",
    "app.services.scan_service.get_database",
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Boucle d'evenements asyncio partagee."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


def _make_mock_get_database(db):
    """Cree une fonction async mockee qui retourne `db`."""
    async def _get_db():
        return db
    return _get_db


@pytest_asyncio.fixture(scope="function")
async def mock_db() -> AsyncGenerator:
    """
    Cree une DB MongoDB moquee et patche get_database partout.
    """
    client = AsyncMongoMockClient()
    db = client["networkrecon"]

    mock_get_db = _make_mock_get_database(db)

    # Patch get_database dans tous les modules qui l'importent
    patches = []
    for target in _GET_DATABASE_PATCH_TARGETS:
        p = patch(target, side_effect=mock_get_db)
        patches.append(p)
        p.start()

    try:
        yield db
    finally:
        for p in patches:
            p.stop()
        client.close()


@pytest_asyncio.fixture(scope="function")
async def populated_db(mock_db) -> AsyncGenerator:
    """Base de donnees pre-peuplee avec des donnees de test realistes."""
    db = mock_db

    for host_data in TEST_HOSTS:
        await db.hosts.insert_one(host_data.copy())

    vuln_scan_doc = {
        "scan_id": "test_scan_001",
        "scan_time": datetime.utcnow(),
        "vulnerabilities": [v.model_dump() for v in TEST_VULNERABILITIES],
        "summary": {
            "total_vulnerabilities": len(TEST_VULNERABILITIES),
            "by_severity": {
                "critical": sum(1 for v in TEST_VULNERABILITIES if v.cve.severity == Severity.CRITICAL),
                "high": sum(1 for v in TEST_VULNERABILITIES if v.cve.severity == Severity.HIGH),
                "medium": sum(1 for v in TEST_VULNERABILITIES if v.cve.severity == Severity.MEDIUM),
                "low": 0,
                "info": 0,
            },
            "affected_hosts": len(set(v.host_ip for v in TEST_VULNERABILITIES)),
        },
    }
    await db.vulnerability_scans.insert_one(vuln_scan_doc)

    # Also insert into archived_vulnerabilities (used by the API routes)
    for v in TEST_VULNERABILITIES:
        vuln_doc = v.model_dump()
        vuln_doc["campaign_id"] = "campaign_001"
        vuln_doc["archived_at"] = datetime.utcnow()
        await db.archived_vulnerabilities.insert_one(vuln_doc)

    campaign_docs = [
        {
            "_id": "campaign_001",
            "name": "Scan reseau principal",
            "description": "Scan complet du reseau interne 192.168.2.0/24",
            "targets": [{"ip_range": "192.168.2.0/24", "authorized": True, "target_list": []}],
            "config": {"scan_type": "full", "ports_range": "1-1024", "timeout": 600, "rate_limit": 1000},
            "results": [],
            "created_at": datetime.utcnow(),
            "status": "completed",
        },
        {
            "_id": "campaign_002",
            "name": "Scan rapide passerelle",
            "description": "Scan rapide de la passerelle",
            "targets": [{"ip_range": "192.168.2.1/32", "authorized": True, "target_list": ["192.168.2.1"]}],
            "config": {"scan_type": "quick", "ports_range": None, "timeout": 300, "rate_limit": 1000},
            "results": [],
            "created_at": datetime.utcnow() - timedelta(hours=1),
            "status": "running",
        },
        {
            "_id": "campaign_003",
            "name": "Scan furtif serveurs",
            "description": "Scan furtif des serveurs critiques",
            "targets": [{"ip_range": "192.168.2.0/24", "authorized": True, "target_list": ["192.168.2.10", "192.168.2.50"]}],
            "config": {"scan_type": "stealth", "ports_range": "22,80,443,3306,3389", "timeout": 600, "rate_limit": 100},
            "results": [],
            "created_at": datetime.utcnow() - timedelta(hours=6),
            "status": "pending",
        },
    ]
    for doc in campaign_docs:
        await db.campaigns.insert_one(doc.copy())

    report_doc = {
        "_id": "report_001",
        "campaign_id": "campaign_001",
        "generated_at": datetime.utcnow(),
        "summary": {
            "total_hosts": 5, "total_services": 14,
            "total_vulnerabilities": len(TEST_VULNERABILITIES),
            "by_severity": {"critical": 4, "high": 2, "medium": 1, "low": 0, "info": 0},
            "scan_duration": 342.5,
        },
        "content": {
            "hosts": [{"ip": h["ip_address"], "hostname": h["hostname"], "services": len(h["ports"]), "vulnerabilities": 0} for h in TEST_HOSTS],
            "top_vulnerabilities": [{"cve_id": v.cve.cve_id, "severity": v.cve.severity.value, "affected_hosts": 1} for v in TEST_VULNERABILITIES[:3]],
            "recommendations": ["Update nginx on 192.168.2.1", "Patch Log4j on 192.168.2.10", "Secure RDP on 192.168.2.50"],
        },
        "export_format": "json",
        "title": "Rapport de scan reseau - Juin 2026",
        "description": "Rapport complet du scan du reseau interne",
        "generated_by": "admin@networkrecon.local",
    }
    await db.reports.insert_one(report_doc.copy())

    auth_campaign_doc = {
        "_id": "auth_campaign_001",
        "name": "Test SSH weak passwords",
        "targets": ["192.168.2.1", "192.168.2.10", "192.168.2.200"],
        "config": {"service_type": "ssh", "credentials_file": "common_passwords.txt", "max_attempts": 10, "delay_between": 1.0},
        "results": [],
        "status": "completed",
        "created_at": datetime.utcnow() - timedelta(hours=2),
        "completed_at": datetime.utcnow() - timedelta(hours=1),
    }
    await db.auth_test_campaigns.insert_one(auth_campaign_doc.copy())

    auth_result_docs = [
        {"host_ip": "192.168.2.1", "port": 22, "service": "ssh", "credential_used": "admin:admin123", "success": True, "timestamp": datetime.utcnow() - timedelta(minutes=30), "error_message": None},
        {"host_ip": "192.168.2.10", "port": 22, "service": "ssh", "credential_used": "root:toor", "success": False, "timestamp": datetime.utcnow() - timedelta(minutes=25), "error_message": "Authentication failed"},
    ]
    for doc in auth_result_docs:
        await db.auth_test_results.insert_one(doc.copy())

    yield db


@pytest_asyncio.fixture(scope="function")
async def client(mock_db) -> AsyncGenerator:
    """Client HTTP asynchrone avec DB moquee."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest_asyncio.fixture(scope="function")
async def populated_client(populated_db) -> AsyncGenerator:
    """Client HTTP avec DB pre-peuplee."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Fixtures de donnees reutilisables
# ---------------------------------------------------------------------------

@pytest.fixture
def valid_scan_payload() -> dict:
    """Payload valide pour la creation d'une campagne de scan."""
    return {
        "name": "Scan test integration",
        "description": "Test de creation de campagne",
        "targets": [{"ip_range": "192.168.2.0/24", "authorized": True, "target_list": []}],
        "config": {"scan_type": "full", "ports_range": "1-1024,8080,8443", "timeout": 600, "rate_limit": 500},
    }


@pytest.fixture
def valid_auth_test_payload() -> dict:
    """Payload valide pour le lancement d'un test d'authentification."""
    return {
        "name": "Test SSH integration",
        "targets": "192.168.2.1,192.168.2.10",
        "service_type": "ssh",
    }


@pytest.fixture
def sample_host_info() -> HostInfo:
    """Retourne un objet HostInfo pour les tests unitaires."""
    return HostInfo(
        ip_address="192.168.2.42",
        hostname="testhost.local",
        mac_address="DD:EE:FF:00:01:01",
        os_detection="Linux 5.15",
        status="up",
        ports=[
            PortInfo(number=22, protocol=Protocol.TCP, state=PortState.OPEN, service="ssh", version="OpenSSH 8.9p1", banner="SSH-2.0-OpenSSH_8.9p1"),
            PortInfo(number=80, protocol=Protocol.TCP, state=PortState.OPEN, service="http", version="nginx 1.18.0", banner="HTTP/1.1 200 OK"),
        ],
    )


@pytest.fixture
def sample_vulnerability() -> Vulnerability:
    """Retourne un objet Vulnerability pour les tests unitaires."""
    return Vulnerability(
        host_ip="192.168.2.42",
        port=80,
        service="http",
        cve=CVE(cve_id="CVE-2023-99999", description="Test vuln", severity=Severity.HIGH, cvss_score=7.5, affected_products=["TestApp"]),
        mitre_mapping=MitreMapping(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1190/"),
        remediation="Apply TestApp 1.1",
    )
