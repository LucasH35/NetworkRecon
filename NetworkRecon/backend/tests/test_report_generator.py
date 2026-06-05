"""Tests pour le module report_generator."""

import asyncio
import csv
import io
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.report import ExportFormat, Report, ReportSummary
from app.models.scan import Campaign, CampaignStatus
from app.services.report_generator import (
    ReportFormatError,
    ReportGenerator,
    ReportGeneratorError,
    CampaignNotFoundError,
    SEVERITY_COLORS,
    SEVERITY_LABELS,
)


# ---------------------------------------------------------------------------
# Helpers : async cursors pour le mocking
# ---------------------------------------------------------------------------


class AsyncIteratorCursor:
    """Simule un cursor MongoDB asynchrone pour les tests."""

    def __init__(self, docs):
        self._docs = list(docs)
        self._index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._index >= len(self._docs):
            raise StopAsyncIteration
        doc = self._docs[self._index]
        self._index += 1
        return doc


# ---------------------------------------------------------------------------
# Données de test
# ---------------------------------------------------------------------------

CAMPAIGN_DOC = {
    "_id": "camp_001",
    "name": "Scan réseau interne",
    "description": "Scan complet du réseau 192.168.1.0/24",
    "targets": [
        {"ip_range": "192.168.1.0/24", "authorized": True}
    ],
    "config": {
        "scan_type": "full",
        "ports_range": "1-1024",
        "timeout": 600,
        "rate_limit": 1000,
    },
    "results": [
        {
            "scan_id": "scan_001",
            "target": "192.168.1.0/24",
            "start_time": "2026-06-01T10:00:00",
            "end_time": "2026-06-01T10:05:00",
            "hosts_found": ["192.168.1.100", "192.168.1.101"],
            "status": "completed",
        }
    ],
    "created_at": datetime(2026, 6, 1, 10, 0, 0),
    "status": "completed",
}

HOSTS_DOCS = [
    {
        "_id": "host_001",
        "ip_address": "192.168.1.100",
        "hostname": "webserver.local",
        "os_detection": "Linux 5.4",
        "status": "up",
        "campaign_id": "camp_001",
        "ports": [
            {"number": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.9"},
            {"number": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache/2.4.41"},
            {"number": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "nginx/1.18"},
        ],
    },
    {
        "_id": "host_002",
        "ip_address": "192.168.1.101",
        "hostname": "dbserver.local",
        "os_detection": "Ubuntu 20.04",
        "status": "up",
        "campaign_id": "camp_001",
        "ports": [
            {"number": 3306, "protocol": "tcp", "state": "open", "service": "mysql", "version": "MySQL 8.0.28"},
            {"number": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.2"},
        ],
    },
]

VULNS_DOCS = [
    {
        "_id": "vscan_001",
        "campaign_id": "camp_001",
        "vulnerabilities": [
            {
                "host_ip": "192.168.1.100",
                "port": 443,
                "service": "https",
                "cve": {
                    "cve_id": "CVE-2014-0160",
                    "description": "Heartbleed",
                    "severity": "high",
                    "cvss_score": 7.5,
                },
                "mitre_mapping": {
                    "technique_id": "T1190",
                    "technique_name": "Exploit Public-Facing Application",
                    "tactic": "Initial Access",
                    "description": "Exploitation d'une application web",
                    "url": "https://attack.mitre.org/techniques/T1190/",
                },
                "remediation": "Mettre à jour OpenSSL vers 1.0.1g ou supérieur",
            },
            {
                "host_ip": "192.168.1.100",
                "port": 80,
                "service": "http",
                "cve": {
                    "cve_id": "CVE-2021-44228",
                    "description": "Log4Shell",
                    "severity": "critical",
                    "cvss_score": 10.0,
                },
                "mitre_mapping": {
                    "technique_id": "T1190",
                    "technique_name": "Exploit Public-Facing Application",
                    "tactic": "Initial Access",
                    "description": "Exploitation d'une application web",
                    "url": "https://attack.mitre.org/techniques/T1190/",
                },
                "remediation": "Mettre à jour Log4j vers la version 2.17.0",
            },
            {
                "host_ip": "192.168.1.101",
                "port": 3306,
                "service": "mysql",
                "cve": {
                    "cve_id": "CVE-2021-2307",
                    "description": "Oracle MySQL – déni de service",
                    "severity": "medium",
                    "cvss_score": 5.3,
                },
                "mitre_mapping": {
                    "technique_id": "T1078.003",
                    "technique_name": "Local Accounts",
                    "tactic": "Initial Access",
                    "description": "Accès aux bases de données via comptes locaux",
                    "url": "https://attack.mitre.org/techniques/T1078/003/",
                },
                "remediation": "Mettre à jour MySQL vers la dernière version stable",
            },
            {
                "host_ip": "192.168.1.101",
                "port": 22,
                "service": "ssh",
                "cve": {
                    "cve_id": "CVE-2020-14145",
                    "description": "OpenSSH – fuite d'information",
                    "severity": "low",
                    "cvss_score": 5.9,
                },
                "mitre_mapping": None,
                "remediation": "Mettre à jour OpenSSH",
            },
        ],
    }
]

AUTH_DOCS = [
    {
        "_id": "auth_001",
        "host_ip": "192.168.1.100",
        "port": 22,
        "service": "ssh",
        "credential_used": "admin:***",
        "success": True,
        "timestamp": "2026-06-01T10:10:00",
        "campaign_id": "camp_001",
    },
    {
        "_id": "auth_002",
        "host_ip": "192.168.1.100",
        "port": 22,
        "service": "ssh",
        "credential_used": "root:***",
        "success": False,
        "error_message": "Auth failed",
        "timestamp": "2026-06-01T10:10:05",
        "campaign_id": "camp_001",
    },
    {
        "_id": "auth_003",
        "host_ip": "192.168.1.101",
        "port": 22,
        "service": "ssh",
        "credential_used": "root:***",
        "success": True,
        "timestamp": "2026-06-01T10:10:10",
        "campaign_id": "camp_001",
    },
]


# ---------------------------------------------------------------------------
# Fixture principale : mock_db avec AsyncMock correctement configuré
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_db():
    """Crée une fausse base de données Motor mockée avec async iterators."""

    class MockCollection:
        """Simule une collection MongoDB."""

        def __init__(self, find_result=None, find_one_result=None,
                     insert_result=None, delete_count=1):
            self._find_result = find_result or []
            self._find_one_result = find_one_result
            self._insert_result = insert_result or "mock_id"
            self._delete_count = delete_count
            self._insert_calls = []
            self._update_calls = []
            self._delete_calls = []

        def find(self, query=None):
            return AsyncIteratorCursor(self._find_result)

        async def find_one(self, query=None):
            return self._find_one_result

        async def insert_one(self, doc):
            self._insert_calls.append(doc)
            return MagicMock(inserted_id=self._insert_result)

        async def update_one(self, query, update, **kwargs):
            self._update_calls.append((query, update, kwargs))

        async def delete_one(self, query):
            self._delete_calls.append(query)
            return MagicMock(deleted_count=self._delete_count)

    # ── Collections ──────────────────────────────────────────────────────
    campaigns_col = MockCollection(
        find_one_result=CAMPAIGN_DOC.copy(),
        insert_result="camp_001",
    )
    hosts_col = MockCollection(find_result=HOSTS_DOCS)
    vulns_col = MockCollection(find_result=VULNS_DOCS)
    auth_col = MockCollection(find_result=AUTH_DOCS)
    reports_col = MockCollection(
        find_one_result=None,
        insert_result="report_001",
    )

    # ── Objet db simulé ──────────────────────────────────────────────────
    class MockDB:
        def __init__(self):
            self.campaigns = campaigns_col
            self.hosts = hosts_col
            self.vulnerability_scans = vulns_col
            self.auth_test_results = auth_col
            self.reports = reports_col

    db = MockDB()
    db._collections = {
        "campaigns": campaigns_col,
        "hosts": hosts_col,
        "vulnerability_scans": vulns_col,
        "auth_test_results": auth_col,
        "reports": reports_col,
    }
    return db


@pytest.fixture
def generator(mock_db):
    """Crée une instance de ReportGenerator avec db mockée."""
    return ReportGenerator(mock_db)


# ---------------------------------------------------------------------------
# Tests : __init__
# ---------------------------------------------------------------------------


class TestInit:
    """Tests pour l'initialisation du ReportGenerator."""

    def test_init_stores_db(self, mock_db):
        gen = ReportGenerator(mock_db)
        assert gen.db is mock_db


# ---------------------------------------------------------------------------
# Tests : build_summary
# ---------------------------------------------------------------------------


class TestBuildSummary:
    """Tests pour la construction du résumé statistique."""

    @pytest.mark.asyncio
    async def test_returns_report_summary(self, generator):
        summary = await generator.build_summary("camp_001")
        assert isinstance(summary, ReportSummary)

    @pytest.mark.asyncio
    async def test_host_count(self, generator):
        summary = await generator.build_summary("camp_001")
        assert summary.total_hosts == 2

    @pytest.mark.asyncio
    async def test_services_count(self, generator):
        summary = await generator.build_summary("camp_001")
        assert summary.total_services == 5

    @pytest.mark.asyncio
    async def test_vulnerability_count(self, generator):
        summary = await generator.build_summary("camp_001")
        assert summary.total_vulnerabilities == 4

    @pytest.mark.asyncio
    async def test_severity_breakdown(self, generator):
        summary = await generator.build_summary("camp_001")
        assert summary.by_severity["critical"] == 1
        assert summary.by_severity["high"] == 1
        assert summary.by_severity["medium"] == 1
        assert summary.by_severity["low"] == 1
        assert summary.by_severity["info"] == 0


# ---------------------------------------------------------------------------
# Tests : get_hosts_summary
# ---------------------------------------------------------------------------


class TestGetHostsSummary:
    """Tests pour le résumé des hôtes."""

    @pytest.mark.asyncio
    async def test_returns_list(self, generator):
        hosts = await generator.get_hosts_summary("camp_001")
        assert isinstance(hosts, list)

    @pytest.mark.asyncio
    async def test_count(self, generator):
        hosts = await generator.get_hosts_summary("camp_001")
        assert len(hosts) == 2

    @pytest.mark.asyncio
    async def test_fields(self, generator):
        hosts = await generator.get_hosts_summary("camp_001")
        for h in hosts:
            assert "ip_address" in h
            assert "hostname" in h
            assert "os_detection" in h
            assert "status" in h
            assert "ports_count" in h
            assert "open_ports" in h

    @pytest.mark.asyncio
    async def test_first_host(self, generator):
        hosts = await generator.get_hosts_summary("camp_001")
        web = next(h for h in hosts if h["ip_address"] == "192.168.1.100")
        assert web["hostname"] == "webserver.local"
        assert web["ports_count"] == 3
        assert 22 in web["open_ports"]
        assert 80 in web["open_ports"]
        assert 443 in web["open_ports"]


# ---------------------------------------------------------------------------
# Tests : get_vulnerabilities_summary
# ---------------------------------------------------------------------------


class TestGetVulnerabilitiesSummary:
    """Tests pour le résumé des vulnérabilités."""

    @pytest.mark.asyncio
    async def test_returns_dict(self, generator):
        vulns = await generator.get_vulnerabilities_summary("camp_001")
        assert isinstance(vulns, dict)

    @pytest.mark.asyncio
    async def test_total(self, generator):
        vulns = await generator.get_vulnerabilities_summary("camp_001")
        assert vulns["total"] == 4

    @pytest.mark.asyncio
    async def test_by_severity(self, generator):
        vulns = await generator.get_vulnerabilities_summary("camp_001")
        assert "by_severity" in vulns
        assert "critical" in vulns["by_severity"]
        assert "high" in vulns["by_severity"]
        assert "medium" in vulns["by_severity"]
        assert "low" in vulns["by_severity"]

    @pytest.mark.asyncio
    async def test_critical_entry(self, generator):
        vulns = await generator.get_vulnerabilities_summary("camp_001")
        critical = vulns["by_severity"]["critical"]["vulnerabilities"]
        assert len(critical) == 1
        assert critical[0]["cve_id"] == "CVE-2021-44228"

    @pytest.mark.asyncio
    async def test_entry_fields(self, generator):
        vulns = await generator.get_vulnerabilities_summary("camp_001")
        for sev_data in vulns["by_severity"].values():
            for v in sev_data.get("vulnerabilities", []):
                assert "cve_id" in v
                assert "description" in v
                assert "host_ip" in v
                assert "service" in v


# ---------------------------------------------------------------------------
# Tests : get_mitre_summary
# ---------------------------------------------------------------------------


class TestGetMitreSummary:
    """Tests pour le résumé MITRE ATT&CK."""

    @pytest.mark.asyncio
    async def test_returns_dict(self, generator):
        mitre = await generator.get_mitre_summary("camp_001")
        assert isinstance(mitre, dict)

    @pytest.mark.asyncio
    async def test_techniques(self, generator):
        mitre = await generator.get_mitre_summary("camp_001")
        assert "techniques" in mitre
        assert "total_techniques" in mitre

    @pytest.mark.asyncio
    async def test_t1190_present(self, generator):
        mitre = await generator.get_mitre_summary("camp_001")
        tech_ids = [t["technique_id"] for t in mitre["techniques"]]
        assert "T1190" in tech_ids

    @pytest.mark.asyncio
    async def test_by_tactic(self, generator):
        mitre = await generator.get_mitre_summary("camp_001")
        assert "by_tactic" in mitre
        assert "Initial Access" in mitre["by_tactic"]

    @pytest.mark.asyncio
    async def test_affected_hosts(self, generator):
        mitre = await generator.get_mitre_summary("camp_001")
        for tech in mitre["techniques"]:
            assert "affected_hosts" in tech
            assert "affected_hosts_count" in tech
            assert isinstance(tech["affected_hosts"], list)


# ---------------------------------------------------------------------------
# Tests : get_auth_summary
# ---------------------------------------------------------------------------


class TestGetAuthSummary:
    """Tests pour le résumé des tests d'authentification."""

    @pytest.mark.asyncio
    async def test_returns_dict(self, generator):
        auth = await generator.get_auth_summary("camp_001")
        assert isinstance(auth, dict)

    @pytest.mark.asyncio
    async def test_totals(self, generator):
        auth = await generator.get_auth_summary("camp_001")
        assert auth["total_tests"] == 3
        assert auth["successes"] == 2
        assert auth["failures"] == 1

    @pytest.mark.asyncio
    async def test_success_rate(self, generator):
        auth = await generator.get_auth_summary("camp_001")
        assert auth["success_rate"] == pytest.approx(66.67, abs=0.01)

    @pytest.mark.asyncio
    async def test_by_service(self, generator):
        auth = await generator.get_auth_summary("camp_001")
        assert "by_service" in auth
        assert "ssh" in auth["by_service"]
        assert auth["by_service"]["ssh"]["total"] == 3


# ---------------------------------------------------------------------------
# Tests : generate_json_report
# ---------------------------------------------------------------------------


class TestGenerateJsonReport:
    """Tests pour la génération de rapports JSON."""

    @pytest.mark.asyncio
    async def test_returns_dict(self, generator):
        report = await generator.generate_json_report("camp_001")
        assert isinstance(report, dict)

    @pytest.mark.asyncio
    async def test_has_required_keys(self, generator):
        report = await generator.generate_json_report("camp_001")
        required_keys = [
            "report_type", "generated_at", "campaign", "summary",
            "hosts", "vulnerabilities", "mitre_attack",
            "authentication_tests", "recommendations",
        ]
        for key in required_keys:
            assert key in report, f"Clé manquante : {key}"

    @pytest.mark.asyncio
    async def test_report_type(self, generator):
        report = await generator.generate_json_report("camp_001")
        assert report["report_type"] == "network_reconnaissance"

    @pytest.mark.asyncio
    async def test_campaign_info(self, generator):
        report = await generator.generate_json_report("camp_001")
        assert report["campaign"]["id"] == "camp_001"
        assert report["campaign"]["name"] == "Scan réseau interne"

    @pytest.mark.asyncio
    async def test_summary(self, generator):
        report = await generator.generate_json_report("camp_001")
        assert report["summary"]["total_hosts"] == 2
        assert report["summary"]["total_services"] == 5

    @pytest.mark.asyncio
    async def test_has_recommendations(self, generator):
        report = await generator.generate_json_report("camp_001")
        assert isinstance(report["recommendations"], list)
        assert len(report["recommendations"]) > 0

    @pytest.mark.asyncio
    async def test_serializable(self, generator):
        report = await generator.generate_json_report("camp_001")
        json_str = json.dumps(report, default=str)
        assert len(json_str) > 0
        parsed = json.loads(json_str)
        assert parsed["report_type"] == "network_reconnaissance"


# ---------------------------------------------------------------------------
# Tests : generate_csv_report
# ---------------------------------------------------------------------------


class TestGenerateCsvReport:
    """Tests pour la génération de rapports CSV."""

    @pytest.mark.asyncio
    async def test_returns_str(self, generator):
        csv_data = await generator.generate_csv_report("camp_001")
        assert isinstance(csv_data, str)

    @pytest.mark.asyncio
    async def test_has_bom(self, generator):
        csv_data = await generator.generate_csv_report("camp_001")
        assert csv_data.startswith("\ufeff")

    @pytest.mark.asyncio
    async def test_has_headers(self, generator):
        csv_data = await generator.generate_csv_report("camp_001")
        assert "HÔTES DÉCOUVERTS" in csv_data
        assert "VULNÉRABILITÉS" in csv_data
        assert "MITRE ATT&CK" in csv_data
        assert "AUTHENTIFICATION" in csv_data

    @pytest.mark.asyncio
    async def test_has_data(self, generator):
        csv_data = await generator.generate_csv_report("camp_001")
        assert "192.168.1.100" in csv_data
        assert "webserver.local" in csv_data
        assert "CVE-2021-44228" in csv_data

    @pytest.mark.asyncio
    async def test_parseable(self, generator):
        csv_data = await generator.generate_csv_report("camp_001")
        csv_clean = csv_data.lstrip("\ufeff")
        reader = csv.reader(io.StringIO(csv_clean), delimiter=";")
        rows = list(reader)
        assert len(rows) > 5


# ---------------------------------------------------------------------------
# Tests : generate_pdf_report (sans reportlab)
# ---------------------------------------------------------------------------


class TestGeneratePdfReport:
    """Tests pour la génération de rapports PDF."""

    @pytest.mark.asyncio
    async def test_missing_reportlab_raises_error(self, generator):
        """Sans reportlab, une erreur explicite devrait être levée."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "reportlab":
                raise ImportError("No module named 'reportlab'")
            return original_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=mock_import):
            with pytest.raises(ReportGeneratorError, match="reportlab"):
                await generator.generate_pdf_report("camp_001")


# ---------------------------------------------------------------------------
# Tests : generate_report
# ---------------------------------------------------------------------------


class TestGenerateReport:
    """Tests pour la génération du rapport principal."""

    @pytest.mark.asyncio
    async def test_returns_report(self, generator):
        report = await generator.generate_report("camp_001")
        assert isinstance(report, Report)

    @pytest.mark.asyncio
    async def test_campaign_id(self, generator):
        report = await generator.generate_report("camp_001")
        assert report.campaign_id == "camp_001"

    @pytest.mark.asyncio
    async def test_has_summary(self, generator):
        report = await generator.generate_report("camp_001")
        assert isinstance(report.summary, ReportSummary)

    @pytest.mark.asyncio
    async def test_json_format(self, generator):
        report = await generator.generate_report("camp_001", "json")
        assert report.export_format == ExportFormat.JSON
        assert "report_type" in report.content

    @pytest.mark.asyncio
    async def test_csv_format(self, generator):
        report = await generator.generate_report("camp_001", "csv")
        assert report.export_format == ExportFormat.CSV
        assert "csv_content" in report.content

    @pytest.mark.asyncio
    async def test_pdf_format(self, generator):
        """Le format PDF devrait lever une erreur si reportlab n'est pas installé."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "reportlab":
                raise ImportError("No module named 'reportlab'")
            return original_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=mock_import):
            with pytest.raises(ReportGeneratorError, match="reportlab"):
                await generator.generate_report("camp_001", "pdf")

    @pytest.mark.asyncio
    async def test_invalid_format(self, generator):
        with pytest.raises(ReportFormatError):
            await generator.generate_report("camp_001", "invalid")

    @pytest.mark.asyncio
    async def test_stores_in_db(self, generator, mock_db):
        await generator.generate_report("camp_001", "json")
        reports_col = mock_db._collections["reports"]
        assert len(reports_col._insert_calls) > 0

    @pytest.mark.asyncio
    async def test_title(self, generator):
        report = await generator.generate_report("camp_001")
        assert report.title is not None
        assert "Scan réseau interne" in report.title


# ---------------------------------------------------------------------------
# Tests : store_report
# ---------------------------------------------------------------------------


class TestStoreReport:
    """Tests pour le stockage des rapports."""

    @pytest.mark.asyncio
    async def test_returns_id(self, generator, mock_db):
        report = Report(
            campaign_id="camp_001",
            summary=ReportSummary(),
            content={"test": True},
        )
        report_id = await generator.store_report(report)
        assert report_id == "report_001"

    @pytest.mark.asyncio
    async def test_calls_insert(self, generator, mock_db):
        report = Report(
            campaign_id="camp_001",
            summary=ReportSummary(),
            content={},
        )
        await generator.store_report(report)
        reports_col = mock_db._collections["reports"]
        assert len(reports_col._insert_calls) == 1


# ---------------------------------------------------------------------------
# Tests : list_reports
# ---------------------------------------------------------------------------


class TestListReports:
    """Tests pour la liste des rapports."""

    @pytest.mark.asyncio
    async def test_returns_list(self, generator):
        reports = await generator.list_reports("camp_001")
        assert isinstance(reports, list)

    @pytest.mark.asyncio
    async def test_empty_by_default(self, generator):
        reports = await generator.list_reports("camp_001")
        assert len(reports) == 0


# ---------------------------------------------------------------------------
# Tests : export_report
# ---------------------------------------------------------------------------


class TestExportReport:
    """Tests pour l'export de rapports."""

    @pytest.mark.asyncio
    async def test_not_found(self, generator):
        with pytest.raises(ReportGeneratorError, match="introuvable"):
            await generator.export_report("nonexistent", "json")


# ---------------------------------------------------------------------------
# Tests : get_report / delete_report
# ---------------------------------------------------------------------------


class TestGetDeleteReport:
    """Tests pour la récupération et suppression de rapports."""

    @pytest.mark.asyncio
    async def test_get_report_not_found(self, generator):
        result = await generator.get_report("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_report(self, generator):
        result = await generator.delete_report("report_001")
        assert result is True


# ---------------------------------------------------------------------------
# Tests : _generate_recommendations
# ---------------------------------------------------------------------------


class TestGenerateRecommendations:
    """Tests pour la génération de recommandations."""

    def test_critical_vulns_recommendation(self, generator):
        summary = ReportSummary(
            total_hosts=1, total_services=5, total_vulnerabilities=3,
            by_severity={"critical": 2, "high": 0, "medium": 1, "low": 0, "info": 0},
        )
        vulns = {"by_severity": {"critical": {"vulnerabilities": [
            {"cve_id": "CVE-2021-44228", "remediation": "Update Log4j"}
        ]}}}
        auth = {"total_tests": 0, "successes": 0, "failures": 0, "success_rate": 0}
        recs = generator._generate_recommendations(summary, vulns, auth)
        assert any("URGENT" in r for r in recs)

    def test_auth_success_recommendation(self, generator):
        summary = ReportSummary(total_hosts=1, total_services=2, total_vulnerabilities=0)
        vulns = {"by_severity": {}}
        auth = {"total_tests": 5, "successes": 3, "failures": 2, "success_rate": 60.0}
        recs = generator._generate_recommendations(summary, vulns, auth)
        assert any("authentification réussi" in r for r in recs)

    def test_no_recommendations_clean(self, generator):
        summary = ReportSummary(total_hosts=1, total_services=2, total_vulnerabilities=0)
        vulns = {"by_severity": {}}
        auth = {"total_tests": 5, "successes": 0, "failures": 5, "success_rate": 0}
        recs = generator._generate_recommendations(summary, vulns, auth)
        assert len(recs) >= 1


# ---------------------------------------------------------------------------
# Tests : constantes et utilitaires
# ---------------------------------------------------------------------------


class TestConstants:
    """Tests pour les constantes du module."""

    def test_severity_colors_has_all_levels(self):
        for sev in ["critical", "high", "medium", "low", "info"]:
            assert sev in SEVERITY_COLORS

    def test_severity_labels_has_all_levels(self):
        for sev in ["critical", "high", "medium", "low", "info"]:
            assert sev in SEVERITY_LABELS

    def test_severity_colors_are_hex(self):
        for color in SEVERITY_COLORS.values():
            assert color.startswith("#")
            assert len(color) == 7


# ---------------------------------------------------------------------------
# Tests : intégration
# ---------------------------------------------------------------------------


class TestIntegration:
    """Tests d'intégration end-to-end."""

    @pytest.mark.asyncio
    async def test_full_workflow_json(self, generator, mock_db):
        report = await generator.generate_report("camp_001", "json")
        assert isinstance(report, Report)
        assert report.campaign_id == "camp_001"
        reports_col = mock_db._collections["reports"]
        assert len(reports_col._insert_calls) > 0
        assert "summary" in report.content
        assert report.content["summary"]["total_hosts"] == 2

    @pytest.mark.asyncio
    async def test_full_workflow_csv(self, generator):
        report = await generator.generate_report("camp_001", "csv")
        assert isinstance(report, Report)
        assert "csv_content" in report.content
        csv_content = report.content["csv_content"]
        assert csv_content.startswith("\ufeff")
        assert "192.168.1.100" in csv_content

    @pytest.mark.asyncio
    async def test_all_summaries_consistent(self, generator):
        summary = await generator.build_summary("camp_001")
        hosts = await generator.get_hosts_summary("camp_001")
        vulns = await generator.get_vulnerabilities_summary("camp_001")
        mitre = await generator.get_mitre_summary("camp_001")
        auth = await generator.get_auth_summary("camp_001")

        assert summary.total_hosts == len(hosts)
        assert summary.total_vulnerabilities == vulns["total"]
        assert mitre["total_techniques"] >= 1
        assert auth["total_tests"] == 3
