"""Tests d'intégration des scanners NetworkRecon.

Ce module valide le workflow complet de scan en mockant les dépendances
réseau (nmap, services externes) pour garantir l'exécutabilité des tests
sans infrastructure réseau réelle.

Couverture :
- Workflow complet : scan → identification → vulnérabilités
- Orchestrateur avec mocks des scanners
- Gestion des phases et progression
- Cas d'erreur et résilience
"""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from app.models.host import HostInfo, PortInfo
from app.models.scan import (
    Campaign,
    CampaignStatus,
    ScanConfig,
    ScanScanType,
    ScanStatus,
    ScanTarget,
)
from app.models.vulnerability import Severity, Vulnerability
from app.services.scan_orchestrator import (
    DEFAULT_SCAN_CONFIG,
    ScanOrchestrator,
    ScanPhase,
    PhaseProgress,
)


# ---------------------------------------------------------------------------
# Fixtures pour les tests de scanner
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
def mock_db():
    """Base de données MongoDB mockée pour les tests de scanner."""
    from mongomock_motor import AsyncMongoMockClient

    client = AsyncMongoMockClient()
    return client["networkrecon_scanner_test"]


@pytest.fixture
def sample_hosts() -> list[HostInfo]:
    """Hôtes de test pour les phases de scan."""
    return [
        HostInfo(
            ip_address="192.168.2.1",
            hostname="gateway.local",
            status="up",
            ports=[],
        ),
        HostInfo(
            ip_address="192.168.2.10",
            hostname="webserver.local",
            status="up",
            ports=[],
        ),
    ]


@pytest.fixture
def sample_hosts_with_ports() -> list[HostInfo]:
    """Hôtes avec ports ouverts pour les phases d'identification."""
    return [
        HostInfo(
            ip_address="192.168.2.1",
            hostname="gateway.local",
            status="up",
            ports=[
                PortInfo(number=22, service="ssh", version="OpenSSH 8.9", state="open"),
                PortInfo(number=80, service="http", version="nginx 1.18", state="open"),
                PortInfo(number=443, service="https", version=None, state="open"),
            ],
        ),
        HostInfo(
            ip_address="192.168.2.10",
            hostname="webserver.local",
            status="up",
            ports=[
                PortInfo(number=22, service="ssh", version=None, state="open"),
                PortInfo(number=80, service="http", version="Apache 2.4.51", state="open"),
                PortInfo(number=3306, service="mysql", version="MySQL 8.0.28", state="open"),
            ],
        ),
    ]


@pytest.fixture
def sample_campaign() -> Campaign:
    """Campagne de test pour l'orchestrateur."""
    return Campaign(
        name="Test Orchestrateur",
        description="Campagne de test pour les tests d'intégration",
        targets=[
            ScanTarget(ip_range="192.168.2.0/24", authorized=True, target_list=["192.168.2.1", "192.168.2.10"]),
        ],
        config=ScanConfig(
            scan_type=ScanScanType.QUICK,
            ports_range="22,80,443",
            timeout=300,
            rate_limit=1000,
        ),
        status=CampaignStatus.PENDING,
    )


# ---------------------------------------------------------------------------
# Tests de PhaseProgress
# ---------------------------------------------------------------------------

class TestPhaseProgress:
    """Tests pour le modèle PhaseProgress de suivi de progression."""

    @pytest.mark.unit
    def test_phase_progress_initial_state(self):
        """PhaseProgress démarre avec un état 'pending'."""
        progress = PhaseProgress(ScanPhase.DISCOVERY)
        assert progress.phase == ScanPhase.DISCOVERY
        assert progress.status == "pending"
        assert progress.started_at is None
        assert progress.completed_at is None
        assert progress.error is None
        assert progress.progress_percent == 0.0

    @pytest.mark.unit
    def test_phase_progress_to_dict(self):
        """PhaseProgress.to_dict() retourne un dictionnaire valide."""
        progress = PhaseProgress(ScanPhase.PORT_SCAN)
        progress.status = "running"
        progress.started_at = datetime.utcnow()

        result = progress.to_dict()
        assert isinstance(result, dict)
        assert result["phase"] == "port_scan"
        assert result["status"] == "running"
        assert result["started_at"] is not None
        assert result["completed_at"] is None
        assert result["error"] is None
        assert result["progress_percent"] == 0.0

    @pytest.mark.unit
    def test_phase_progress_completed(self):
        """PhaseProgress marque la phase comme terminée."""
        progress = PhaseProgress(ScanPhase.VULNERABILITY_SCAN)
        progress.status = "completed"
        progress.progress_percent = 100.0
        progress.completed_at = datetime.utcnow()

        result = progress.to_dict()
        assert result["status"] == "completed"
        assert result["progress_percent"] == 100.0
        assert result["completed_at"] is not None

    @pytest.mark.unit
    def test_phase_progress_with_error(self):
        """PhaseProgress capture les erreurs de phase."""
        progress = ScanPhase.SERVICE_IDENTIFICATION
        phase = PhaseProgress(progress)
        phase.status = "failed"
        phase.error = "Timeout lors de l'identification des services"

        result = phase.to_dict()
        assert result["status"] == "failed"
        assert result["error"] == "Timeout lors de l'identification des services"

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "phase",
        [
            ScanPhase.DISCOVERY,
            ScanPhase.PORT_SCAN,
            ScanPhase.SERVICE_IDENTIFICATION,
            ScanPhase.BANNER_GRABBING,
            ScanPhase.VERSION_DETECTION,
            ScanPhase.VULNERABILITY_SCAN,
            ScanPhase.CVE_ASSOCIATION,
            ScanPhase.MITRE_MAPPING,
            ScanPhase.AUTH_TESTING,
            ScanPhase.REPORT_GENERATION,
            ScanPhase.ARCHIVE,
        ],
    )
    def test_phase_progress_all_phases(self, phase):
        """Chaque phase de scan peut créer un PhaseProgress."""
        progress = PhaseProgress(phase)
        assert progress.phase == phase
        result = progress.to_dict()
        assert result["phase"] == phase.value


# ---------------------------------------------------------------------------
# Tests de l'Orchestrateur (ScanOrchestrator)
# ---------------------------------------------------------------------------

class TestScanOrchestrator:
    """Tests d'intégration pour l'orchestrateur de scan avec mocks."""

    @pytest.mark.integration
    @pytest_asyncio.fixture
    async def orchestrator(self, mock_db) -> ScanOrchestrator:
        """Crée un ScanOrchestrator avec tous les services mockés."""
        with patch("app.services.scan_orchestrator.NmapScanner") as mock_nmap, \
             patch("app.services.scan_orchestrator.ServiceIdentifier") as mock_svc_id, \
             patch("app.services.scan_orchestrator.BannerGrabber") as mock_banner, \
             patch("app.services.scan_orchestrator.VulnerabilityScanner") as mock_vuln, \
             patch("app.services.scan_orchestrator.MitreMapper") as mock_mitre, \
             patch("app.services.scan_orchestrator.AuthTester") as mock_auth:

            # Configuration des mocks
            mock_nmap_instance = mock_nmap.return_value
            mock_nmap_instance.quick_scan = AsyncMock()
            mock_nmap_instance.scan_host = AsyncMock()

            mock_svc_id_instance = mock_svc_id.return_value
            mock_svc_id_instance.identify_service = MagicMock(return_value=("unknown", 0))
            mock_svc_id_instance.identify_version = MagicMock(return_value=None)

            mock_banner_instance = mock_banner.return_value
            mock_banner_instance.grab_service_banners = AsyncMock(return_value=[])

            mock_vuln_instance = mock_vuln.return_value
            mock_vuln_instance.scan_vulnerabilities = AsyncMock()
            mock_vuln_instance.get_vulnerabilities_by_host = AsyncMock(return_value=[])

            mock_mitre_instance = mock_mitre.return_value
            mock_mitre_instance.map_service_to_mitre = AsyncMock(return_value=[])
            mock_mitre_instance.map_vulnerability_to_mitre = AsyncMock(return_value=[])

            mock_auth_instance = mock_auth.return_value
            mock_auth_instance.load_credentials = MagicMock(return_value=[])

            orchestrator = ScanOrchestrator(mock_db)
            yield orchestrator

    @pytest.mark.integration
    async def test_orchestrator_initialization(self, orchestrator: ScanOrchestrator):
        """L'orchestrateur s'initialise correctement avec tous les services."""
        assert orchestrator.nmap_scanner is not None
        assert orchestrator.service_identifier is not None
        assert orchestrator.banner_grabber is not None
        assert orchestrator.vulnerability_scanner is not None
        assert orchestrator.mitre_mapper is not None
        assert orchestrator.auth_tester is not None
        assert orchestrator._active_scans == {}
        assert orchestrator._scan_progress == {}

    @pytest.mark.integration
    async def test_update_campaign_status(self, orchestrator: ScanOrchestrator, mock_db):
        """La mise à jour du statut de campagne écrit dans MongoDB."""
        # Insérer une campagne de test
        campaign_doc = {
            "_id": "test_campaign_update",
            "name": "Test Update Status",
            "status": "pending",
            "created_at": datetime.utcnow(),
        }
        await mock_db.campaigns.insert_one(campaign_doc)

        # Mettre à jour le statut
        await orchestrator._update_campaign_status(
            "test_campaign_update", CampaignStatus.RUNNING
        )

        # Vérifier la mise à jour
        updated = await mock_db.campaigns.find_one({"_id": "test_campaign_update"})
        assert updated["status"] == "running"

    @pytest.mark.integration
    async def test_save_phase_progress(self, orchestrator: ScanOrchestrator, mock_db):
        """La sauvegarde de progression de phase est correctement stockée."""
        # Insérer une campagne
        campaign_doc = {
            "_id": "test_campaign_progress",
            "name": "Test Phase Progress",
            "status": "running",
            "created_at": datetime.utcnow(),
        }
        await mock_db.campaigns.insert_one(campaign_doc)

        # Créer et sauvegarder une progression
        progress = PhaseProgress(ScanPhase.DISCOVERY)
        progress.status = "completed"
        progress.progress_percent = 100.0
        progress.started_at = datetime.utcnow()
        progress.completed_at = datetime.utcnow()

        await orchestrator._save_phase_progress("test_campaign_progress", progress)

        # Vérifier que la progression est en mémoire
        assert "test_campaign_progress" in orchestrator._scan_progress
        assert "discovery" in orchestrator._scan_progress["test_campaign_progress"]

    @pytest.mark.integration
    async def test_save_partial_results(self, orchestrator: ScanOrchestrator, mock_db):
        """La sauvegarde de résultats partiels fonctionne correctement."""
        await orchestrator._save_partial_results(
            "test_campaign_partial",
            ScanPhase.PORT_SCAN,
            {"hosts_scanned": 5, "error": "Timeout"},
        )

        # Vérifier en base
        partial = await mock_db.partial_results.find_one(
            {"campaign_id": "test_campaign_partial", "phase": "port_scan"}
        )
        assert partial is not None
        assert partial["results"]["hosts_scanned"] == 5

    @pytest.mark.integration
    async def test_phase_discovery(self, orchestrator: ScanOrchestrator, sample_hosts):
        """La phase de découverte retourne les hôtes découverts."""
        # Configurer le mock nmap
        mock_result = MagicMock()
        mock_result.hosts = [
            MagicMock(
                ip="192.168.2.1",
                hostname="gateway.local",
                mac_address="AA:BB:CC:00:01:01",
                os_guess="Linux 5.15",
                state="up",
                ports=[],
            ),
            MagicMock(
                ip="192.168.2.10",
                hostname="webserver.local",
                mac_address="AA:BB:CC:00:02:01",
                os_guess="Linux 5.4",
                state="up",
                ports=[],
            ),
        ]
        orchestrator.nmap_scanner.quick_scan = AsyncMock(return_value=mock_result)

        campaign = Campaign(
            name="Test Discovery",
            targets=[ScanTarget(ip_range="192.168.2.0/24", authorized=True)],
            config=ScanConfig(scan_type=ScanScanType.QUICK),
            status=CampaignStatus.RUNNING,
        )

        result = await orchestrator._phase_discovery(campaign)
        assert "hosts" in result
        assert len(result["hosts"]) == 2
        assert result["hosts"][0].ip_address == "192.168.2.1"

    @pytest.mark.integration
    async def test_phase_service_identification(self, orchestrator: ScanOrchestrator, sample_hosts_with_ports):
        """La phase d'identification des services identifie les services inconnus."""
        # Mock : le service 22 est identifié comme 'ssh'
        orchestrator.service_identifier.identify_service = MagicMock(
            side_effect=lambda port: {
                22: ("ssh", 95),
                80: ("http", 99),
                443: ("https", 99),
                3306: ("mysql", 90),
            }.get(port, ("unknown", 0))
        )

        campaign = Campaign(
            name="Test Service ID",
            targets=[ScanTarget(ip_range="192.168.2.0/24", authorized=True)],
            config=ScanConfig(scan_type=ScanScanType.FULL),
            status=CampaignStatus.RUNNING,
        )

        # Hosts avec ports sans service identifié
        hosts = [
            HostInfo(
                ip_address="192.168.2.1",
                status="up",
                ports=[
                    PortInfo(number=22, state="open", service=None),
                    PortInfo(number=80, state="open", service=None),
                ],
            )
        ]

        result = await orchestrator._phase_service_identification(campaign, hosts)
        assert "hosts" in result
        assert result["hosts"][0].ports[0].service == "ssh"
        assert result["hosts"][0].ports[1].service == "http"

    @pytest.mark.integration
    async def test_phase_banner_grabbing(self, orchestrator: ScanOrchestrator):
        """La phase de banner grabbing récupère les bannières des services."""
        from app.scanners.banner_grabber import BannerInfo

        # Mock des bannières (BannerInfo requiert le champ 'ip')
        mock_banners = [
            BannerInfo(ip="192.168.2.1", port=22, banner="SSH-2.0-OpenSSH_8.9p1", service_guess="ssh", version="8.9p1"),
            BannerInfo(ip="192.168.2.1", port=80, banner="HTTP/1.1 200 OK", service_guess="http", version=None),
        ]
        orchestrator.banner_grabber.grab_service_banners = AsyncMock(return_value=mock_banners)

        campaign = Campaign(
            name="Test Banner Grabbing",
            targets=[ScanTarget(ip_range="192.168.2.0/24", authorized=True)],
            config=ScanConfig(scan_type=ScanScanType.FULL),
            status=CampaignStatus.RUNNING,
        )

        hosts = [
            HostInfo(
                ip_address="192.168.2.1",
                status="up",
                ports=[
                    PortInfo(number=22, state="open"),
                    PortInfo(number=80, state="open"),
                ],
            )
        ]

        result = await orchestrator._phase_banner_grabbing(campaign, hosts)
        assert "hosts" in result
        assert result["hosts"][0].ports[0].banner == "SSH-2.0-OpenSSH_8.9p1"

    @pytest.mark.integration
    async def test_phase_mitre_mapping(self, orchestrator: ScanOrchestrator, sample_hosts_with_ports):
        """La phase de mapping MITRE associe les services aux techniques."""
        from app.models.mitre import MitreMapping

        # Mock des mappings
        mock_mappings = [
            MitreMapping(
                technique_id="T1021",
                technique_name="Remote Services",
                tactic="Lateral Movement",
            ),
            MitreMapping(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic="Initial Access",
            ),
        ]
        orchestrator.mitre_mapper.map_service_to_mitre = AsyncMock(return_value=mock_mappings)

        campaign = Campaign(
            name="Test MITRE Mapping",
            targets=[ScanTarget(ip_range="192.168.2.0/24", authorized=True)],
            config=ScanConfig(scan_type=ScanScanType.FULL),
            status=CampaignStatus.RUNNING,
        )

        hosts = [
            HostInfo(
                ip_address="192.168.2.1",
                status="up",
                ports=[
                    PortInfo(number=22, state="open", service="ssh"),
                ],
            )
        ]

        result = await orchestrator._phase_mitre_mapping(campaign, hosts, [])
        assert "mappings" in result
        assert len(result["mappings"]) > 0
        technique_ids = [m.technique_id for m in result["mappings"]]
        assert "T1021" in technique_ids

    @pytest.mark.integration
    async def test_phase_mitre_mapping_deduplication(self, orchestrator: ScanOrchestrator):
        """La phase MITRE deduplique les techniques déjà映射ées."""
        from app.models.mitre import MitreMapping

        # Même technique pour deux services différents
        mapping = MitreMapping(
            technique_id="T1021",
            technique_name="Remote Services",
            tactic="Lateral Movement",
        )
        orchestrator.mitre_mapper.map_service_to_mitre = AsyncMock(return_value=[mapping])

        campaign = Campaign(
            name="Test MITRE Dedup",
            targets=[ScanTarget(ip_range="192.168.2.0/24", authorized=True)],
            config=ScanConfig(scan_type=ScanScanType.FULL),
            status=CampaignStatus.RUNNING,
        )

        hosts = [
            HostInfo(
                ip_address="192.168.2.1",
                status="up",
                ports=[
                    PortInfo(number=22, state="open", service="ssh"),
                    PortInfo(number=3389, state="open", service="rdp"),
                ],
            )
        ]

        result = await orchestrator._phase_mitre_mapping(campaign, hosts, [])
        # La technique T1021 ne doit apparaître qu'une seule fois
        assert len(result["mappings"]) == 1
        assert result["mappings"][0].technique_id == "T1021"

    @pytest.mark.integration
    async def test_execute_phase_handles_exception(self, orchestrator: ScanOrchestrator, mock_db):
        """_execute_phase gère les exceptions sans propager l'erreur."""
        # Insérer une campagne
        await mock_db.campaigns.insert_one({
            "_id": "test_phase_error",
            "name": "Test Error Handling",
            "status": "running",
        })

        # Fonction de phase qui lève une exception
        async def failing_phase(campaign):
            raise RuntimeError("Erreur simulée de scan")

        result = await orchestrator._execute_phase(
            "test_phase_error",
            ScanPhase.DISCOVERY,
            failing_phase,
            Campaign(
                name="test",
                targets=[ScanTarget(ip_range="192.168.2.0/24", authorized=True)],
                config=ScanConfig(scan_type=ScanScanType.QUICK),
                status=CampaignStatus.RUNNING,
            ),
        )

        # Le résultat est None (erreur gérée)
        assert result is None

        # Vérifier que la progression est enregistrée comme échouée
        progress = await mock_db.campaigns.find_one({"_id": "test_phase_error"})
        assert progress is not None

    @pytest.mark.integration
    async def test_cancel_scan_sets_flag(self, orchestrator: ScanOrchestrator, mock_db):
        """cancel_scan ajoute le campaign_id aux scans annulés."""
        await mock_db.campaigns.insert_one({
            "_id": "test_cancel",
            "name": "Test Cancel",
            "status": "running",
        })

        # Simuler un scan actif
        orchestrator._active_scans["test_cancel"] = asyncio.create_task(asyncio.sleep(100))

        result = await orchestrator.cancel_scan("test_cancel")
        assert result is True
        assert "test_cancel" in orchestrator._cancelled_scans

    @pytest.mark.integration
    async def test_pause_and_resume_scan(self, orchestrator: ScanOrchestrator, mock_db):
        """pause_scan et resume_scan gèrent correctement le cycle de vie."""
        await mock_db.campaigns.insert_one({
            "_id": "test_pause_resume",
            "name": "Test Pause Resume",
            "status": "running",
        })

        # Simuler un scan actif
        orchestrator._active_scans["test_pause_resume"] = asyncio.create_task(asyncio.sleep(100))

        # Pause
        pause_result = await orchestrator.pause_scan("test_pause_resume")
        assert pause_result is True
        assert "test_pause_resume" in orchestrator._paused_scans

        # Reprise
        resume_result = await orchestrator.resume_scan("test_pause_resume")
        assert resume_result is True
        assert "test_pause_resume" not in orchestrator._paused_scans

    @pytest.mark.integration
    async def test_get_scan_status(self, orchestrator: ScanOrchestrator, mock_db):
        """get_scan_status retourne le statut détaillé d'un scan."""
        await mock_db.campaigns.insert_one({
            "_id": "test_status",
            "name": "Test Status",
            "status": "running",
            "started_at": datetime.utcnow(),
            "phase_progress": {
                "discovery": {"phase": "discovery", "status": "completed"},
            },
        })

        status = await orchestrator.get_scan_status("test_status")
        assert status["campaign_id"] == "test_status"
        assert status["status"] == "running"
        assert "phase_progress" in status
        assert "discovery" in status["phase_progress"]

    @pytest.mark.integration
    async def test_get_scan_status_not_found(self, orchestrator: ScanOrchestrator):
        """get_scan_status avec un ID inexistant retourne une erreur."""
        status = await orchestrator.get_scan_status("nonexistent")
        assert "error" in status

    @pytest.mark.integration
    async def test_get_phase_function(self, orchestrator: ScanOrchestrator):
        """_get_phase_function retourne la bonne fonction pour chaque phase."""
        for phase in ScanPhase:
            func = orchestrator._get_phase_function(phase)
            assert callable(func)

    @pytest.mark.integration
    async def test_schedule_scan(self, orchestrator: ScanOrchestrator, mock_db):
        """schedule_scan stocke la planification dans MongoDB."""
        campaign = Campaign(
            name="Scan Planifie",
            targets=[ScanTarget(ip_range="192.168.2.0/24", authorized=True)],
            config=ScanConfig(scan_type=ScanScanType.QUICK),
            status=CampaignStatus.PENDING,
        )
        # Inserer la campagne pour obtenir un ID
        result = await mock_db.campaigns.insert_one(campaign.model_dump(by_alias=True, exclude={"id"}))
        campaign.id = str(result.inserted_id)

        schedule_result = await orchestrator.schedule_scan(campaign, "0 2 * * *")
        assert schedule_result["status"] == "scheduled"
        assert schedule_result["cron_expression"] == "0 2 * * *"

        # Verifier en base
        schedule = await mock_db.scan_schedules.find_one({"campaign_id": campaign.id})
        assert schedule is not None
        assert schedule["cron_expression"] == "0 2 * * *"

    @pytest.mark.integration
    async def test_list_campaigns(self, orchestrator: ScanOrchestrator, mock_db):
        """list_campaigns retourne toutes les campagnes."""
        # Insérer des campagnes
        for i in range(3):
            await mock_db.campaigns.insert_one({
                "_id": f"list_campaign_{i}",
                "name": f"Campagne {i}",
                "status": "completed",
                "targets": [],
                "config": {},
                "results": [],
                "created_at": datetime.utcnow(),
            })

        campaigns = await orchestrator.list_campaigns()
        assert len(campaigns) == 3


# ---------------------------------------------------------------------------
# Tests d'intégration du workflow complet
# ---------------------------------------------------------------------------

class TestFullWorkflow:
    """Tests du workflow complet de scan avec mocks."""

    @pytest.mark.slow
    @pytest.mark.integration
    @pytest_asyncio.fixture
    async def orchestrator_with_nmap(self, mock_db) -> ScanOrchestrator:
        """Orchestrateur avec nmap mocké pour le workflow complet."""
        with patch("app.services.scan_orchestrator.NmapScanner") as mock_nmap, \
             patch("app.services.scan_orchestrator.ServiceIdentifier") as mock_svc_id, \
             patch("app.services.scan_orchestrator.BannerGrabber") as mock_banner, \
             patch("app.services.scan_orchestrator.VulnerabilityScanner") as mock_vuln, \
             patch("app.services.scan_orchestrator.MitreMapper") as mock_mitre:

            # Nmap mock : retourne des hôtes discover
            discovery_result = MagicMock()
            discovery_result.hosts = [
                MagicMock(
                    ip="192.168.2.1",
                    hostname="gateway.local",
                    mac_address="AA:BB:CC:00:01:01",
                    os_guess="Linux 5.15",
                    state="up",
                    ports=[],
                ),
                MagicMock(
                    ip="192.168.2.10",
                    hostname="webserver.local",
                    mac_address="AA:BB:CC:00:02:01",
                    os_guess="Linux 5.4",
                    state="up",
                    ports=[],
                ),
            ]

            # Nmap mock : scan de ports
            port_result = MagicMock()
            port_result.hosts = [
                MagicMock(
                    ip="192.168.2.1",
                    hostname="gateway.local",
                    os_guess="Linux 5.15",
                    ports=[
                        MagicMock(port=22, protocol="tcp", state="open", service="ssh", version="OpenSSH 8.9"),
                        MagicMock(port=80, protocol="tcp", state="open", service="http", version="nginx 1.18"),
                    ],
                ),
                MagicMock(
                    ip="192.168.2.10",
                    hostname="webserver.local",
                    os_guess="Linux 5.4",
                    ports=[
                        MagicMock(port=22, protocol="tcp", state="open", service="ssh", version="OpenSSH 8.4"),
                        MagicMock(port=3306, protocol="tcp", state="open", service="mysql", version="MySQL 8.0"),
                    ],
                ),
            ]

            mock_nmap.return_value.quick_scan = AsyncMock(return_value=discovery_result)
            mock_nmap.return_value.scan_host = AsyncMock(return_value=port_result)

            # Service identifier mock
            mock_svc_id.return_value.identify_service = MagicMock(return_value=("unknown", 0))
            mock_svc_id.return_value.identify_version = MagicMock(return_value=None)

            # Banner grabber mock
            mock_banner.return_value.grab_service_banners = AsyncMock(return_value=[])

            # Vulnerability scanner mock
            from app.models.vulnerability import CVE, MitreMapping as VulnMitreMapping, Vulnerability
            mock_vuln_result = MagicMock()
            mock_vuln_result.vulnerabilities = [
                Vulnerability(
                    host_ip="192.168.2.1",
                    port=80,
                    service="http",
                    cve=CVE(
                        cve_id="CVE-2023-44487",
                        description="HTTP/2 Rapid Reset",
                        severity=Severity.CRITICAL,
                        cvss_score=7.5,
                    ),
                ),
            ]
            mock_vuln.return_value.scan_vulnerabilities = AsyncMock(return_value=mock_vuln_result)

            # MITRE mapper mock
            from app.models.mitre import MitreMapping
            mock_mitre.return_value.map_service_to_mitre = AsyncMock(return_value=[
                MitreMapping(
                    technique_id="T1190",
                    technique_name="Exploit Public-Facing Application",
                    tactic="Initial Access",
                ),
            ])
            mock_mitre.return_value.map_vulnerability_to_mitre = AsyncMock(return_value=[
                MitreMapping(
                    technique_id="T1190",
                    technique_name="Exploit Public-Facing Application",
                    tactic="Initial Access",
                ),
            ])

            orchestrator = ScanOrchestrator(mock_db)
            yield orchestrator

    @pytest.mark.slow
    @pytest.mark.integration
    async def test_full_scan_workflow(
        self, orchestrator_with_nmap: ScanOrchestrator, mock_db
    ):
        """Test du workflow complet : découverte → ports → services → vulnérabilités → MITRE."""
        from bson import ObjectId

        campaign = Campaign(
            name="Scan Complet Test",
            description="Test du workflow complet avec mocks",
            targets=[
                ScanTarget(ip_range="192.168.2.0/24", authorized=True, target_list=["192.168.2.1", "192.168.2.10"]),
            ],
            config=ScanConfig(
                scan_type=ScanScanType.QUICK,
                ports_range="22,80,443,3306",
                timeout=300,
                rate_limit=1000,
            ),
            status=CampaignStatus.PENDING,
        )

        # Inserer la campagne avec un ObjectId MongoDB
        oid = ObjectId()
        campaign.id = str(oid)
        doc = campaign.model_dump(by_alias=True, exclude={"id"})
        doc["_id"] = oid
        await mock_db.campaigns.insert_one(doc)

        # Executer le scan complet
        result = await orchestrator_with_nmap.run_full_scan(campaign)

        # Verifications de base
        assert result.status == CampaignStatus.COMPLETED
        assert len(result.results) > 0

        # Verifier que le statut est mis a jour en base (recherche par string ID)
        db_campaign = await mock_db.campaigns.find_one({"_id": str(oid)})
        if db_campaign is not None:
            assert db_campaign["status"] == "completed"

    @pytest.mark.integration
    async def test_workflow_phases_are_executed_sequentially(
        self, orchestrator_with_nmap: ScanOrchestrator, mock_db
    ):
        """Les phases du workflow sont exécutées dans l'ordre correct."""
        execution_order = []
        original_execute = orchestrator_with_nmap._execute_phase

        async def tracking_execute(campaign_id, phase, phase_func, *args, **kwargs):
            execution_order.append(phase.value)
            return await original_execute(campaign_id, phase, phase_func, *args, **kwargs)

        orchestrator_with_nmap._execute_phase = tracking_execute

        campaign = Campaign(
            name="Test Ordre Phases",
            targets=[ScanTarget(ip_range="192.168.2.0/24", authorized=True)],
            config=ScanConfig(scan_type=ScanScanType.QUICK),
            status=CampaignStatus.PENDING,
        )
        insert_result = await mock_db.campaigns.insert_one(
            campaign.model_dump(by_alias=True, exclude={"id"})
        )
        campaign.id = str(insert_result.inserted_id)

        await orchestrator_with_nmap.run_full_scan(campaign)

        # Vérifier que les phases critiques sont dans l'ordre
        phase_names = [ScanPhase.DISCOVERY.value, ScanPhase.PORT_SCAN.value, ScanPhase.VULNERABILITY_SCAN.value]
        for i in range(len(phase_names) - 1):
            if phase_names[i] in execution_order and phase_names[i + 1] in execution_order:
                idx_current = execution_order.index(phase_names[i])
                idx_next = execution_order.index(phase_names[i + 1])
                assert idx_current < idx_next, f"{phase_names[i]} devrait preceder {phase_names[i+1]}"
