"""Orchestrateur de workflow automatisé pour NetworkRecon.

Ce module implémente l'orchestrateur principal qui coordonne l'ensemble des phases
de scan réseau de manière asynchrone et résiliente. Il gère :

- Le workflow complet de scan (découverte → ports → services → vulnérabilités → rapports)
- La gestion du cycle de vie des campagnes (création, exécution, pause, reprise, annulation)
- Le suivi de progression en temps réel via MongoDB
- La planification de scans via des expressions cron
- La sauvegarde des résultats partiels en cas d'échec
- Le logging structuré et les callbacks de notification

Architecture :
    ScanOrchestrator → [NmapScanner, ServiceIdentifier, BannerGrabber,
                       VulnerabilityScanner, MitreMapper, AuthTester, ReportGenerator]

Conformité :
    - Async/await avec asyncio.gather() pour la parallélisation
    - Motor pour l'interaction asynchrone avec MongoDB
    - Gestion des erreurs par phase (résilience)
    - Stockage des résultats partiels
"""

import asyncio
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.auth_test import AuthCampaign, AuthTestConfig, ServiceType
from app.models.host import HostInfo, PortInfo
from app.models.mitre import MitreMapping
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
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityScanResult
from app.scanners.banner_grabber import BannerGrabber
from app.scanners.nmap_scanner import NmapScanner
from app.scanners.service_identifier import ServiceIdentifier
from app.services.auth_tester import AuthTester
from app.services.mitre_mapper import MitreMapper
from app.services.vulnerability_scanner import VulnerabilityScanner

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums pour les phases de scan
# ---------------------------------------------------------------------------

class ScanPhase(str, Enum):
    """Phases du workflow de scan."""
    DISCOVERY = "discovery"
    PORT_SCAN = "port_scan"
    SERVICE_IDENTIFICATION = "service_identification"
    BANNER_GRABBING = "banner_grabbing"
    VERSION_DETECTION = "version_detection"
    VULNERABILITY_SCAN = "vulnerability_scan"
    CVE_ASSOCIATION = "cve_association"
    MITRE_MAPPING = "mitre_mapping"
    AUTH_TESTING = "auth_testing"
    REPORT_GENERATION = "report_generation"
    ARCHIVE = "archive"


# ---------------------------------------------------------------------------
# Configuration par défaut
# ---------------------------------------------------------------------------

DEFAULT_SCAN_CONFIG = {
    "scan_type": ScanScanType.QUICK,
    "ports_range": None,  # top 1000 ports par défaut
    "timeout": 300,
    "rate_limit": 1000,
    "auth_tests_enabled": False,
    "report_formats": [ExportFormat.JSON, ExportFormat.PDF],
    "default_target": "192.168.2.0/24",
}


# ---------------------------------------------------------------------------
# Modèle pour le statut de progression
# ---------------------------------------------------------------------------

class PhaseProgress:
    """Suivi de progression d'une phase de scan."""

    def __init__(self, phase: ScanPhase):
        self.phase = phase
        self.status: str = "pending"
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error: Optional[str] = None
        self.progress_percent: float = 0.0
        self.details: dict[str, Any] = {}

    def to_dict(self) -> dict[str, Any]:
        """Convertit en dictionnaire pour MongoDB."""
        return {
            "phase": self.phase.value,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
            "progress_percent": self.progress_percent,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Classe principale : ScanOrchestrator
# ---------------------------------------------------------------------------

class ScanOrchestrator:
    """
    Orchestrateur de workflow automatisé pour les scans réseau.

    Coordonne l'ensemble des phases de scan de manière asynchrone et résiliente.
    Chaque phase est exécutée indépendamment avec gestion des erreurs.
    Les résultats partiels sont sauvegardés en cas d'échec.

    Attributes:
        db: Instance Motor de la base de données MongoDB
        nmap_scanner: Scanner réseau basé sur nmap
        service_identifier: Identificateur de services
        banner_grabber: Récupérateur de bannières
        vulnerability_scanner: Scanner de vulnérabilités
        mitre_mapper: Mapper MITRE ATT&CK
        auth_tester: Testeur d'authentification
        _active_scans: Dictionnaire des scans actifs (campaign_id → Task)
        _scan_progress: Suivi de progression des scans actifs
    """

    def __init__(self, db: AsyncIOMotorDatabase):
        """
        Initialise l'orchestrateur avec tous les services nécessaires.

        Args:
            db: Instance Motor de la base de données MongoDB
        """
        self.db = db

        # Initialisation des services
        self.nmap_scanner = NmapScanner()
        self.service_identifier = ServiceIdentifier()
        self.banner_grabber = BannerGrabber(default_timeout=3.0)
        self.vulnerability_scanner = VulnerabilityScanner(db)
        self.mitre_mapper = MitreMapper()
        self.auth_tester = AuthTester(db)

        # État interne
        self._active_scans: dict[str, asyncio.Task] = {}
        self._scan_progress: dict[str, dict[str, PhaseProgress]] = {}
        self._paused_scans: set[str] = set()
        self._cancelled_scans: set[str] = set()

        logger.info("ScanOrchestrator initialisé avec succès")

    # ------------------------------------------------------------------
    # Utilitaires internes
    # ------------------------------------------------------------------

    async def _update_campaign_status(
        self,
        campaign_id: str,
        status: CampaignStatus,
        extra_fields: Optional[dict[str, Any]] = None,
    ) -> None:
        """Met à jour le statut d'une campagne dans MongoDB."""
        update_doc: dict[str, Any] = {
            "status": status.value,
            "updated_at": datetime.utcnow(),
        }
        if extra_fields:
            update_doc.update(extra_fields)

        await self.db["campaigns"].update_one(
            {"_id": campaign_id},
            {"$set": update_doc},
        )
        logger.debug(
            "Campagne %s → statut %s", campaign_id, status.value
        )

    async def _save_phase_progress(
        self,
        campaign_id: str,
        phase: PhaseProgress,
    ) -> None:
        """Sauvegarde la progression d'une phase dans MongoDB."""
        if campaign_id not in self._scan_progress:
            self._scan_progress[campaign_id] = {}

        self._scan_progress[campaign_id][phase.phase.value] = phase

        # Mise à jour en base
        await self.db["campaigns"].update_one(
            {"_id": campaign_id},
            {
                "$set": {
                    f"phase_progress.{phase.phase.value}": phase.to_dict(),
                    "updated_at": datetime.utcnow(),
                }
            },
        )

    async def _save_partial_results(
        self,
        campaign_id: str,
        phase: ScanPhase,
        results: dict[str, Any],
    ) -> None:
        """Sauvegarde les résultats partiels en cas d'erreur ou d'interruption."""
        await self.db["partial_results"].update_one(
            {
                "campaign_id": campaign_id,
                "phase": phase.value,
            },
            {
                "$set": {
                    "campaign_id": campaign_id,
                    "phase": phase.value,
                    "results": results,
                    "saved_at": datetime.utcnow(),
                }
            },
            upsert=True,
        )
        logger.info(
            "Résultats partiels sauvegardés pour campagne=%s, phase=%s",
            campaign_id,
            phase.value,
        )

    # ------------------------------------------------------------------
    # Workflow principal
    # ------------------------------------------------------------------

    async def run_full_scan(self, campaign: Campaign) -> Campaign:
        """
        Exécute le workflow complet de scan pour une campagne.

        Le workflow comprend 11 phases séquentielles :
        1. Découverte réseau (nmap_scanner.scan_range)
        2. Scan des ports (nmap_scanner avec ports configurés)
        3. Identification des services (service_identifier)
        4. Banner grabbing (banner_grabber)
        5. Détection des versions (service_identifier)
        6. Recherche des vulnérabilités (vulnerability_scanner)
        7. Association des CVE (vulnerability_scanner)
        8. Mapping MITRE ATT&CK (mitre_mapper)
        9. Tests d'authentification autorisés (auth_tester) — si configuré
        10. Génération des rapports (report_generator)
        11. Archivage des résultats

        Args:
            campaign: Campagne à exécuter

        Returns:
            Campaign: Campagne mise à jour avec les résultats

        Raises:
            ValueError: Si la campagne n'est pas autorisée
        """
        campaign_id = campaign.id or "unknown"

        logger.info(
            "Démarrage du scan complet pour la campagne '%s' (id=%s)",
            campaign.name,
            campaign_id,
        )

        # Mise à jour du statut
        await self._update_campaign_status(
            campaign_id,
            CampaignStatus.RUNNING,
            {"started_at": datetime.utcnow()},
        )

        # Initialisation du suivi de progression
        self._scan_progress[campaign_id] = {}
        for phase in ScanPhase:
            self._scan_progress[campaign_id][phase.value] = PhaseProgress(phase)

        all_hosts: list[HostInfo] = []
        all_vulnerabilities: list[Vulnerability] = []
        all_mitre_mappings: list[MitreMapping] = []
        auth_results: list = []
        phase_errors: list[dict[str, Any]] = []

        try:
            # Phase 1: Découverte réseau
            discovery_result = await self._execute_phase(
                campaign_id,
                ScanPhase.DISCOVERY,
                self._phase_discovery,
                campaign,
            )
            if discovery_result and "hosts" in discovery_result:
                all_hosts = discovery_result["hosts"]
                logger.info(
                    "Découverte terminée : %d hôtes trouvés", len(all_hosts)
                )

            # Phase 2: Scan des ports
            port_scan_result = await self._execute_phase(
                campaign_id,
                ScanPhase.PORT_SCAN,
                self._phase_port_scan,
                campaign,
                all_hosts,
            )
            if port_scan_result and "hosts" in port_scan_result:
                all_hosts = port_scan_result["hosts"]

            # Phase 3: Identification des services
            service_result = await self._execute_phase(
                campaign_id,
                ScanPhase.SERVICE_IDENTIFICATION,
                self._phase_service_identification,
                campaign,
                all_hosts,
            )
            if service_result and "hosts" in service_result:
                all_hosts = service_result["hosts"]

            # Phase 4: Banner grabbing
            banner_result = await self._execute_phase(
                campaign_id,
                ScanPhase.BANNER_GRABBING,
                self._phase_banner_grabbing,
                campaign,
                all_hosts,
            )
            if banner_result and "hosts" in banner_result:
                all_hosts = banner_result["hosts"]

            # Phase 5: Détection des versions
            version_result = await self._execute_phase(
                campaign_id,
                ScanPhase.VERSION_DETECTION,
                self._phase_version_detection,
                campaign,
                all_hosts,
            )
            if version_result and "hosts" in version_result:
                all_hosts = version_result["hosts"]

            # Phase 5b: Enregistrement des hôtes dans MongoDB AVANT le scan CVE
            # Indispensable car _phase_vulnerability_scan vérifie authorized:true
            if all_hosts:
                for h in all_hosts:
                    host_doc = {
                        "ip_address": h.ip_address,
                        "hostname": h.hostname,
                        "mac_address": h.mac_address,
                        "os_detection": h.os_detection,
                        "status": h.status,
                        "ports": [p.model_dump() for p in h.ports],
                        "authorized": True,
                        "last_seen": datetime.utcnow(),
                        "first_seen": datetime.utcnow(),
                    }
                    await self.db["hosts"].update_one(
                        {"ip_address": h.ip_address},
                        {"$set": host_doc},
                        upsert=True,
                    )
                logger.info(
                    "Hôtes enregistrés dans MongoDB (authorized=True) : %d",
                    len(all_hosts),
                )

            # Phase 6: Recherche des vulnérabilités
            vuln_result = await self._execute_phase(
                campaign_id,
                ScanPhase.VULNERABILITY_SCAN,
                self._phase_vulnerability_scan,
                campaign,
                all_hosts,
            )
            if vuln_result and "vulnerabilities" in vuln_result:
                all_vulnerabilities = vuln_result["vulnerabilities"]

            # Phase 7: Association des CVE
            cve_result = await self._execute_phase(
                campaign_id,
                ScanPhase.CVE_ASSOCIATION,
                self._phase_cve_association,
                campaign,
                all_vulnerabilities,
            )
            if cve_result and "vulnerabilities" in cve_result:
                all_vulnerabilities = cve_result["vulnerabilities"]

            # Phase 8: Mapping MITRE ATT&CK
            mitre_result = await self._execute_phase(
                campaign_id,
                ScanPhase.MITRE_MAPPING,
                self._phase_mitre_mapping,
                campaign,
                all_hosts,
                all_vulnerabilities,
            )
            if mitre_result and "mappings" in mitre_result:
                all_mitre_mappings = mitre_result["mappings"]

            # Phase 9: Tests d'authentification (si configuré)
            auth_config = campaign.config
            if hasattr(auth_config, "auth_tests_enabled") and auth_config.auth_tests_enabled:
                auth_result = await self._execute_phase(
                    campaign_id,
                    ScanPhase.AUTH_TESTING,
                    self._phase_auth_testing,
                    campaign,
                    all_hosts,
                )
                if auth_result and "results" in auth_result:
                    auth_results = auth_result["results"]

            # Phase 10: Génération des rapports
            report_result = await self._execute_phase(
                campaign_id,
                ScanPhase.REPORT_GENERATION,
                self._phase_report_generation,
                campaign,
                all_hosts,
                all_vulnerabilities,
                all_mitre_mappings,
                auth_results,
            )

            # Phase 11: Archivage
            await self._execute_phase(
                campaign_id,
                ScanPhase.ARCHIVE,
                self._phase_archive,
                campaign,
                all_hosts,
                all_vulnerabilities,
                all_mitre_mappings,
            )

            # Mise à jour finale
            campaign.status = CampaignStatus.COMPLETED
            campaign.results = [
                ScanResult(
                    scan_id=campaign_id,
                    target=target.ip_range,
                    start_time=campaign.created_at,
                    end_time=datetime.utcnow(),
                    hosts_found=[
                        {
                            "ip_address": h.ip_address,
                            "hostname": h.hostname or "",
                            "os_detection": h.os_detection or "",
                            "status": h.status or "up",
                            "ports": [
                                {
                                    "number": p.number,
                                    "protocol": p.protocol,
                                    "state": p.state,
                                    "service": p.service or "",
                                    "version": p.version or "",
                                }
                                for p in h.ports
                            ],
                        }
                        for h in all_hosts
                    ],
                    status=ScanStatus.COMPLETED,
                )
                for target in campaign.targets
            ]

            await self._update_campaign_status(
                campaign_id,
                CampaignStatus.COMPLETED,
                {
                    "completed_at": datetime.utcnow(),
                    "results": [r.model_dump() for r in campaign.results],
                    "phase_progress": {
                        k: v.to_dict()
                        for k, v in self._scan_progress.get(campaign_id, {}).items()
                    },
                },
            )

            logger.info(
                "Scan complet terminé pour la campagne '%s'. "
                "%d hôtes, %d vulnérabilités, %d mappings MITRE.",
                campaign.name,
                len(all_hosts),
                len(all_vulnerabilities),
                len(all_mitre_mappings),
            )

        except Exception as e:
            logger.error(
                "Erreur fatale lors du scan de la campagne '%s': %s",
                campaign.name,
                str(e),
                exc_info=True,
            )

            campaign.status = CampaignStatus.FAILED
            await self._update_campaign_status(
                campaign_id,
                CampaignStatus.FAILED,
                {
                    "error_message": str(e),
                    "failed_at": datetime.utcnow(),
                    "phase_progress": {
                        k: v.to_dict()
                        for k, v in self._scan_progress.get(campaign_id, {}).items()
                    },
                },
            )

        finally:
            # Nettoyage
            self._active_scans.pop(campaign_id, None)
            self._scan_progress.pop(campaign_id, None)

        return campaign

    # ------------------------------------------------------------------
    # Exécution de phases avec gestion des erreurs
    # ------------------------------------------------------------------

    async def _execute_phase(
        self,
        campaign_id: str,
        phase: ScanPhase,
        phase_func: Callable,
        *args: Any,
        **kwargs: Any,
    ) -> Optional[dict[str, Any]]:
        """
        Exécute une phase de scan avec gestion des erreurs et progression.

        Args:
            campaign_id: Identifiant de la campagne
            phase: Phase à exécuter
            phase_func: Fonction à appeler pour la phase
            *args, **kwargs: Arguments pour la fonction

        Returns:
            Résultat de la phase ou None en cas d'erreur
        """
        phase_progress = self._scan_progress.get(campaign_id, {}).get(
            phase.value, PhaseProgress(phase)
        )

        # Vérification si le scan est annulé
        if campaign_id in self._cancelled_scans:
            logger.info("Scan annulé, phase %s ignorée", phase.value)
            return None

        # Attente si le scan est en pause
        while campaign_id in self._paused_scans:
            await asyncio.sleep(1)
            if campaign_id in self._cancelled_scans:
                return None

        # Démarrage de la phase
        phase_progress.status = "running"
        phase_progress.started_at = datetime.utcnow()
        await self._save_phase_progress(campaign_id, phase_progress)

        logger.info(
            "Phase '%s' démarrée pour la campagne %s",
            phase.value,
            campaign_id,
        )

        try:
            # Exécution de la phase
            if asyncio.iscoroutinefunction(phase_func):
                result = await phase_func(*args, **kwargs)
            else:
                result = phase_func(*args, **kwargs)

            # Phase terminée avec succès
            phase_progress.status = "completed"
            phase_progress.completed_at = datetime.utcnow()
            phase_progress.progress_percent = 100.0
            await self._save_phase_progress(campaign_id, phase_progress)

            logger.info(
                "Phase '%s' terminée avec succès pour la campagne %s",
                phase.value,
                campaign_id,
            )

            return result

        except Exception as e:
            # Gestion d'erreur de phase
            phase_progress.status = "failed"
            phase_progress.completed_at = datetime.utcnow()
            phase_progress.error = str(e)
            await self._save_phase_progress(campaign_id, phase_progress)

            # Sauvegarde des résultats partiels
            await self._save_partial_results(
                campaign_id,
                phase,
                {"error": str(e), "phase": phase.value},
            )

            logger.error(
                "Erreur lors de la phase '%s' pour la campagne %s: %s",
                phase.value,
                campaign_id,
                str(e),
                exc_info=True,
            )

            # Ne pas lever l'exception pour permettre la continuité
            return None

    # ------------------------------------------------------------------
    # Implémentations des phases
    # ------------------------------------------------------------------

    async def _phase_discovery(
        self, campaign: Campaign
    ) -> dict[str, Any]:
        """Phase 1: Découverte réseau via nmap."""
        logger.info("Phase 1: Découverte réseau")

        all_hosts: list[HostInfo] = []

        for target in campaign.targets:
            try:
                # Scan de découverte rapide
                result = await self.nmap_scanner.quick_scan(target.ip_range)

                # Conversion des résultats
                for nmap_host in result.hosts:
                    host_info = HostInfo(
                        ip_address=nmap_host.ip,
                        hostname=nmap_host.hostname,
                        mac_address=nmap_host.mac_address,
                        os_detection=nmap_host.os_guess,
                        status=nmap_host.state,
                        ports=[
                            PortInfo(
                                number=p.port,
                                protocol=p.protocol,
                                state=p.state,
                                service=p.service,
                                version=p.version,
                                banner=None,
                            )
                            for p in nmap_host.ports
                        ],
                    )
                    all_hosts.append(host_info)

                logger.info(
                    "Cible %s: %d hôtes découverts",
                    target.ip_range,
                    len(result.hosts),
                )

            except Exception as e:
                logger.error(
                    "Erreur lors de la découverte pour %s: %s",
                    target.ip_range,
                    str(e),
                )
                continue

        return {"hosts": all_hosts}

    async def _phase_port_scan(
        self,
        campaign: Campaign,
        hosts: list[HostInfo],
    ) -> dict[str, Any]:
        """Phase 2: Scan des ports détaillé."""
        logger.info("Phase 2: Scan des ports")

        if not hosts:
            logger.warning("Aucun hôte à scanner")
            return {"hosts": hosts}

        scan_type = campaign.config.scan_type
        ports_range = campaign.config.ports_range

        # Détermination des arguments nmap
        # Ajout de -O -sV pour détecter l'OS et le hostname à chaque scan
        if scan_type == ScanScanType.QUICK:
            nmap_args = "-sT --top-ports 1000 -T4 -O -sV"
        elif scan_type == ScanScanType.STEALTH:
            nmap_args = "-sS -T2 --top-ports 100 -O -sV"
        else:  # FULL
            nmap_args = "-sV -sC -O"

        updated_hosts: list[HostInfo] = []

        # Parallélisation du scan des hôtes
        async def scan_host(host: HostInfo) -> HostInfo:
            try:
                result = await self.nmap_scanner.scan_host(
                    host.ip_address,
                    ports=ports_range,
                    scan_type=nmap_args,
                )

                # Mise à jour des ports
                if result.hosts:
                    scanned_host = result.hosts[0]
                    host.ports = [
                        PortInfo(
                            number=p.port,
                            protocol=p.protocol,
                            state=p.state,
                            service=p.service,
                            version=p.version,
                            banner=None,
                        )
                        for p in scanned_host.ports
                    ]
                    if scanned_host.os_guess:
                        host.os_detection = scanned_host.os_guess
                    # Mettre à jour le hostname si nmap a résolu un nom
                    if scanned_host.hostname:
                        host.hostname = scanned_host.hostname

                return host

            except Exception as e:
                logger.error(
                    "Erreur scan port pour %s: %s",
                    host.ip_address,
                    str(e),
                )
                return host

        # Exécution parallèle avec limite de concurrence
        semaphore = asyncio.Semaphore(10)

        async def limited_scan(host: HostInfo) -> HostInfo:
            async with semaphore:
                return await scan_host(host)

        tasks = [limited_scan(host) for host in hosts]
        updated_hosts = await asyncio.gather(*tasks, return_exceptions=False)

        # Filtrage des résultats invalides
        valid_hosts = [h for h in updated_hosts if isinstance(h, HostInfo)]

        logger.info("Scan des ports terminé : %d hôtes mis à jour", len(valid_hosts))

        return {"hosts": valid_hosts}

    async def _phase_service_identification(
        self,
        campaign: Campaign,
        hosts: list[HostInfo],
    ) -> dict[str, Any]:
        """Phase 3: Identification des services."""
        logger.info("Phase 3: Identification des services")

        for host in hosts:
            for port_info in host.ports:
                if port_info.state == "open" and not port_info.service:
                    # Identification basée sur le port
                    service, confidence = self.service_identifier.identify_service(
                        port_info.number
                    )
                    if service != "unknown":
                        port_info.service = service

        logger.info("Identification des services terminée")

        return {"hosts": hosts}

    async def _phase_banner_grabbing(
        self,
        campaign: Campaign,
        hosts: list[HostInfo],
    ) -> dict[str, Any]:
        """Phase 4: Récupération des bannières."""
        logger.info("Phase 4: Banner grabbing")

        async def grab_host_banners(host: HostInfo) -> HostInfo:
            open_ports = [
                p.number for p in host.ports if p.state == "open"
            ]

            if not open_ports:
                return host

            try:
                banners = await self.banner_grabber.grab_service_banners(
                    host.ip_address,
                    open_ports,
                    concurrency=5,
                )

                # Association des bannières aux ports
                banner_map = {b.port: b for b in banners}
                for port_info in host.ports:
                    if port_info.number in banner_map:
                        banner_info = banner_map[port_info.number]
                        if banner_info.banner:
                            port_info.banner = banner_info.banner
                            if banner_info.service_guess and not port_info.service:
                                port_info.service = banner_info.service_guess
                            if banner_info.version:
                                port_info.version = banner_info.version

            except Exception as e:
                logger.error(
                    "Erreur banner grabbing pour %s: %s",
                    host.ip_address,
                    str(e),
                )

            return host

        # Exécution parallèle
        tasks = [grab_host_banners(host) for host in hosts]
        updated_hosts = await asyncio.gather(*tasks, return_exceptions=False)

        valid_hosts = [h for h in updated_hosts if isinstance(h, HostInfo)]

        logger.info("Banner grabbing terminé : %d hôtes traités", len(valid_hosts))

        return {"hosts": valid_hosts}

    async def _phase_version_detection(
        self,
        campaign: Campaign,
        hosts: list[HostInfo],
    ) -> dict[str, Any]:
        """Phase 5: Détection des versions."""
        logger.info("Phase 5: Détection des versions")

        for host in hosts:
            for port_info in host.ports:
                if port_info.state == "open" and port_info.banner:
                    # Extraction de la version depuis la bannière
                    version = self.service_identifier.identify_version(
                        port_info.banner
                    )
                    if version and not port_info.version:
                        port_info.version = version

        logger.info("Détection des versions terminée")

        return {"hosts": hosts}

    async def _phase_vulnerability_scan(
        self,
        campaign: Campaign,
        hosts: list[HostInfo],
    ) -> dict[str, Any]:
        """Phase 6: Scan de vulnérabilités."""
        logger.info("Phase 6: Scan de vulnérabilités")

        if not hosts:
            return {"vulnerabilities": []}

        try:
            vuln_result = await self.vulnerability_scanner.scan_vulnerabilities(
                hosts
            )
            logger.info(
                "Scan de vulnérabilités terminé : %d vulnérabilités trouvées",
                len(vuln_result.vulnerabilities),
            )
            return {"vulnerabilities": vuln_result.vulnerabilities}

        except Exception as e:
            logger.error("Erreur scan vulnérabilités: %s", str(e))
            return {"vulnerabilities": []}

    async def _phase_cve_association(
        self,
        campaign: Campaign,
        vulnerabilities: list[Vulnerability],
    ) -> dict[str, Any]:
        """Phase 7: Association des CVE."""
        logger.info("Phase 7: Association des CVE")

        # Les CVE sont déjà associées lors du scan de vulnérabilités
        # Cette phase peut enrichir les données si nécessaire
        enriched_vulns: list[Vulnerability] = []

        for vuln in vulnerabilities:
            # Vérification que la CVE est valide
            if vuln.cve and vuln.cve.cve_id:
                enriched_vulns.append(vuln)

        logger.info(
            "Association des CVE terminée : %d vulnérabilités validées",
            len(enriched_vulns),
        )

        return {"vulnerabilities": enriched_vulns}

    async def _phase_mitre_mapping(
        self,
        campaign: Campaign,
        hosts: list[HostInfo],
        vulnerabilities: list[Vulnerability],
    ) -> dict[str, Any]:
        """Phase 8: Mapping MITRE ATT&CK."""
        logger.info("Phase 8: Mapping MITRE ATT&CK")

        all_mappings: list[MitreMapping] = []
        seen_techniques: set[str] = set()

        # Mapping des services
        for host in hosts:
            for port_info in host.ports:
                if port_info.service and port_info.state == "open":
                    try:
                        service_mappings = await self.mitre_mapper.map_service_to_mitre(
                            port_info.service,
                            port_info.version or "",
                        )
                        for mapping in service_mappings:
                            if mapping.technique_id not in seen_techniques:
                                all_mappings.append(mapping)
                                seen_techniques.add(mapping.technique_id)
                    except Exception as e:
                        logger.error(
                            "Erreur mapping MITRE pour %s/%s: %s",
                            host.ip_address,
                            port_info.service,
                            str(e),
                        )

        # Mapping des CVE
        for vuln in vulnerabilities:
            if vuln.cve:
                try:
                    cve_mappings = await self.mitre_mapper.map_vulnerability_to_mitre(
                        vuln.cve
                    )
                    for mapping in cve_mappings:
                        if mapping.technique_id not in seen_techniques:
                            all_mappings.append(mapping)
                            seen_techniques.add(mapping.technique_id)
                except Exception as e:
                    logger.error(
                        "Erreur mapping MITRE pour CVE %s: %s",
                        vuln.cve.cve_id,
                        str(e),
                    )

        logger.info(
            "Mapping MITRE terminé : %d techniques uniques",
            len(all_mappings),
        )

        return {"mappings": all_mappings}

    async def _phase_auth_testing(
        self,
        campaign: Campaign,
        hosts: list[HostInfo],
    ) -> dict[str, Any]:
        """Phase 9: Tests d'authentification autorisés."""
        logger.info("Phase 9: Tests d'authentification")

        all_results: list = []

        # Détermination du type de service à tester
        auth_config = getattr(campaign.config, "auth_config", None)
        if not auth_config:
            logger.info("Aucun test d'authentification configuré")
            return {"results": []}

        # Chargement des credentials si disponibles
        credentials_file = getattr(auth_config, "credentials_file", None)
        if not credentials_file:
            logger.warning("Aucun fichier de credentials spécifié")
            return {"results": []}

        try:
            credentials = self.auth_tester.load_credentials(credentials_file)
        except Exception as e:
            logger.error("Erreur chargement credentials: %s", str(e))
            return {"results": []}

        # Test de chaque hôte
        for host in hosts:
            for port_info in host.ports:
                if port_info.state != "open":
                    continue

                # Détermination du type de service
                service_type = None
                if port_info.service:
                    service_lower = port_info.service.lower()
                    if service_lower in ("ssh", "openssh"):
                        service_type = ServiceType.SSH
                    elif service_lower in ("ftp", "vsftpd", "proftpd"):
                        service_type = ServiceType.FTP
                    elif service_lower in ("smb", "microsoft-ds", "netbios-ssn"):
                        service_type = ServiceType.SMB
                    elif service_lower in ("rdp", "ms-wbt-server"):
                        service_type = ServiceType.RDP

                if service_type:
                    try:
                        results = await self.auth_tester.test_service(
                            ip=host.ip_address,
                            port=port_info.number,
                            service_type=service_type,
                            credentials=credentials,
                            config=auth_config,
                        )
                        all_results.extend(results)
                    except Exception as e:
                        logger.error(
                            "Erreur test auth %s:%d: %s",
                            host.ip_address,
                            port_info.number,
                            str(e),
                        )

        logger.info(
            "Tests d'authentification terminés : %d résultats",
            len(all_results),
        )

        return {"results": all_results}

    async def _phase_report_generation(
        self,
        campaign: Campaign,
        hosts: list[HostInfo],
        vulnerabilities: list[Vulnerability],
        mitre_mappings: list[MitreMapping],
        auth_results: list,
    ) -> dict[str, Any]:
        """Phase 10: Génération des rapports."""
        logger.info("Phase 10: Génération des rapports")

        # Construction du résumé
        severity_counts = {s.value: 0 for s in Severity}
        for vuln in vulnerabilities:
            if vuln.cve:
                severity_counts[vuln.cve.severity.value] = (
                    severity_counts.get(vuln.cve.severity.value, 0) + 1
                )

        summary = ReportSummary(
            total_hosts=len(hosts),
            total_services=sum(
                len([p for p in h.ports if p.state == "open"]) for h in hosts
            ),
            total_vulnerabilities=len(vulnerabilities),
            by_severity=severity_counts,
            scan_duration=None,
        )

        # Construction du contenu du rapport
        content = {
            "hosts": [
                {
                    "ip": h.ip_address,
                    "hostname": h.hostname,
                    "os": h.os_detection,
                    "ports": len([p for p in h.ports if p.state == "open"]),
                    "vulnerabilities": sum(
                        1
                        for v in vulnerabilities
                        if v.host_ip == h.ip_address
                    ),
                }
                for h in hosts
            ],
            "top_vulnerabilities": [
                {
                    "cve_id": v.cve.cve_id,
                    "severity": v.cve.severity.value,
                    "cvss_score": v.cve.cvss_score,
                    "affected_hosts": len(
                        [
                            vh
                            for vh in vulnerabilities
                            if vh.cve.cve_id == v.cve.cve_id
                        ]
                    ),
                }
                for v in sorted(
                    vulnerabilities,
                    key=lambda x: x.cve.cvss_score or 0,
                    reverse=True,
                )[:20]
            ],
            "mitre_techniques": [
                {
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic,
                }
                for m in mitre_mappings[:50]
            ],
            "auth_results_summary": {
                "total_tests": len(auth_results),
                "successful": sum(1 for r in auth_results if r.success),
                "failed": sum(1 for r in auth_results if not r.success),
            },
        }

        # Création du rapport
        report = Report(
            campaign_id=campaign.id or "unknown",
            summary=summary,
            content=content,
            export_format=ExportFormat.JSON,
            title=f"Rapport de scan - {campaign.name}",
            description=f"Rapport complet du scan du réseau pour la campagne {campaign.name}",
            generated_by="scan_orchestrator",
        )

        # Stockage du rapport
        report_doc = report.model_dump()
        report_doc["_id"] = f"report_{campaign.id}"
        await self.db["reports"].update_one(
            {"_id": report_doc["_id"]},
            {"$set": report_doc},
            upsert=True,
        )

        logger.info("Rapport généré et stocké pour la campagne %s", campaign.id)

        return {"report": report}

    async def _phase_archive(
        self,
        campaign: Campaign,
        hosts: list[HostInfo],
        vulnerabilities: list[Vulnerability],
        mitre_mappings: list[MitreMapping],
    ) -> dict[str, Any]:
        """Phase 11: Archivage des résultats."""
        logger.info("Phase 11: Archivage des résultats")

        campaign_id = campaign.id or "unknown"

        # Archivage des hôtes
        if hosts:
            host_docs = [
                {
                    "ip_address": h.ip_address,
                    "hostname": h.hostname,
                    "mac_address": h.mac_address,
                    "os_detection": h.os_detection,
                    "status": h.status,
                    "ports": [p.model_dump() for p in h.ports],
                    "authorized": True,
                    "campaign_id": campaign_id,
                    "last_seen": datetime.utcnow(),
                    "first_seen": datetime.utcnow(),
                }
                for h in hosts
            ]
            # Upsert dans la collection hosts (pour la page "Hôtes découverts")
            for doc in host_docs:
                await self.db["hosts"].update_one(
                    {"ip_address": doc["ip_address"]},
                    {"$set": doc},
                    upsert=True,
                )
            # Archivage dans archived_hosts (historique par campagne)
            await self.db["archived_hosts"].insert_many(host_docs)

        # Archivage des vulnérabilités
        if vulnerabilities:
            vuln_docs = [
                {
                    **v.model_dump(),
                    "campaign_id": campaign_id,
                    "archived_at": datetime.utcnow(),
                }
                for v in vulnerabilities
            ]
            await self.db["archived_vulnerabilities"].insert_many(vuln_docs)

        # Archivage des mappings MITRE
        if mitre_mappings:
            mitre_docs = [
                {
                    **m.model_dump(),
                    "campaign_id": campaign_id,
                    "archived_at": datetime.utcnow(),
                }
                for m in mitre_mappings
            ]
            await self.db["archived_mitre_mappings"].insert_many(mitre_docs)

        logger.info(
            "Archivage terminé : %d hôtes, %d vulnérabilités, %d mappings",
            len(hosts),
            len(vulnerabilities),
            len(mitre_mappings),
        )

        return {"archived": True}

    # ------------------------------------------------------------------
    # Gestion du cycle de vie des scans
    # ------------------------------------------------------------------

    async def run_scan_phase(
        self, phase: str, campaign: Campaign
    ) -> dict[str, Any]:
        """
        Exécute une phase spécifique de scan.

        Args:
            phase: Nom de la phase à exécuter
            campaign: Campagne concernée

        Returns:
            Résultat de la phase

        Raises:
            ValueError: Si la phase n'est pas reconnue
        """
        phase_enum = ScanPhase(phase)
        campaign_id = campaign.id or "unknown"

        # Initialisation du suivi
        if campaign_id not in self._scan_progress:
            self._scan_progress[campaign_id] = {}

        phase_progress = PhaseProgress(phase_enum)
        self._scan_progress[campaign_id][phase.value] = phase_progress

        # Exécution de la phase
        result = await self._execute_phase(
            campaign_id,
            phase_enum,
            self._get_phase_function(phase_enum),
            campaign,
        )

        return result or {}

    def _get_phase_function(self, phase: ScanPhase) -> Callable:
        """Retourne la fonction correspondant à une phase."""
        phase_functions = {
            ScanPhase.DISCOVERY: self._phase_discovery,
            ScanPhase.PORT_SCAN: self._phase_port_scan,
            ScanPhase.SERVICE_IDENTIFICATION: self._phase_service_identification,
            ScanPhase.BANNER_GRABBING: self._phase_banner_grabbing,
            ScanPhase.VERSION_DETECTION: self._phase_version_detection,
            ScanPhase.VULNERABILITY_SCAN: self._phase_vulnerability_scan,
            ScanPhase.CVE_ASSOCIATION: self._phase_cve_association,
            ScanPhase.MITRE_MAPPING: self._phase_mitre_mapping,
            ScanPhase.AUTH_TESTING: self._phase_auth_testing,
            ScanPhase.REPORT_GENERATION: self._phase_report_generation,
            ScanPhase.ARCHIVE: self._phase_archive,
        }
        return phase_functions.get(phase, lambda *a, **kw: {})

    async def get_scan_status(self, campaign_id: str) -> dict[str, Any]:
        """
        Retourne le statut en temps réel d'un scan.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            Dictionnaire avec le statut détaillé
        """
        # Récupération depuis MongoDB
        campaign_doc = await self.db["campaigns"].find_one(
            {"_id": campaign_id}
        )

        if not campaign_doc:
            return {"error": "Campagne non trouvée"}

        # Récupération de la progression des phases
        phase_progress = campaign_doc.get("phase_progress", {})

        return {
            "campaign_id": campaign_id,
            "status": campaign_doc.get("status", "unknown"),
            "name": campaign_doc.get("name"),
            "started_at": campaign_doc.get("started_at"),
            "completed_at": campaign_doc.get("completed_at"),
            "error_message": campaign_doc.get("error_message"),
            "phase_progress": phase_progress,
            "is_paused": campaign_id in self._paused_scans,
            "is_cancelled": campaign_id in self._cancelled_scans,
        }

    async def pause_scan(self, campaign_id: str) -> bool:
        """
        Met en pause un scan en cours.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            True si la pause a réussi, False sinon
        """
        if campaign_id not in self._active_scans:
            logger.warning(
                "Impossible de mettre en pause : scan %s non actif",
                campaign_id,
            )
            return False

        self._paused_scans.add(campaign_id)
        await self._update_campaign_status(
            campaign_id,
            CampaignStatus.RUNNING,  # On garde le statut RUNNING
            {"paused_at": datetime.utcnow()},
        )

        logger.info("Scan %s mis en pause", campaign_id)
        return True

    async def resume_scan(self, campaign_id: str) -> bool:
        """
        Reprend un scan en pause.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            True si la reprise a réussi, False sinon
        """
        if campaign_id not in self._paused_scans:
            logger.warning(
                "Impossible de reprendre : scan %s n'est pas en pause",
                campaign_id,
            )
            return False

        self._paused_scans.discard(campaign_id)
        await self._update_campaign_status(
            campaign_id,
            CampaignStatus.RUNNING,
            {"resumed_at": datetime.utcnow()},
        )

        logger.info("Scan %s repris", campaign_id)
        return True

    async def cancel_scan(self, campaign_id: str) -> bool:
        """
        Annule un scan en cours.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            True si l'annulation a réussi, False sinon
        """
        if campaign_id not in self._active_scans:
            logger.warning(
                "Impossible d'annuler : scan %s non actif",
                campaign_id,
            )
            return False

        self._cancelled_scans.add(campaign_id)
        self._paused_scans.discard(campaign_id)

        # Annulation de la tâche asyncio
        task = self._active_scans.get(campaign_id)
        if task and not task.done():
            task.cancel()

        await self._update_campaign_status(
            campaign_id,
            CampaignStatus.CANCELLED,
            {"cancelled_at": datetime.utcnow()},
        )

        logger.info("Scan %s annulé", campaign_id)
        return True

    async def schedule_scan(
        self,
        campaign: Campaign,
        cron_expression: str,
    ) -> dict[str, Any]:
        """
        Planifie un scan avec une expression cron.

        Note: Cette méthode stocke la planification dans MongoDB.
        L'exécution réelle nécessite un scheduler externe (ex: APScheduler, Celery Beat).

        Args:
            campaign: Campagne à planifier
            cron_expression: Expression cron (ex: "0 2 * * *" pour tous les jours à 2h)

        Returns:
            Dictionnaire avec les détails de la planification
        """
        campaign_id = campaign.id or "unknown"

        schedule_doc = {
            "campaign_id": campaign_id,
            "campaign_name": campaign.name,
            "cron_expression": cron_expression,
            "targets": [t.model_dump() for t in campaign.targets],
            "config": campaign.config.model_dump(),
            "status": "scheduled",
            "created_at": datetime.utcnow(),
            "next_run": None,  # Calculé par le scheduler
        }

        await self.db["scan_schedules"].update_one(
            {"campaign_id": campaign_id},
            {"$set": schedule_doc},
            upsert=True,
        )

        logger.info(
            "Scan planifié pour la campagne %s avec cron '%s'",
            campaign.name,
            cron_expression,
        )

        return {
            "schedule_id": f"schedule_{campaign_id}",
            "campaign_id": campaign_id,
            "cron_expression": cron_expression,
            "status": "scheduled",
        }

    # ------------------------------------------------------------------
    # Gestion des campagnes
    # ------------------------------------------------------------------

    async def create_campaign(
        self,
        name: str,
        targets: list[ScanTarget],
        config: Optional[ScanConfig] = None,
        auth_config: Optional[dict[str, Any]] = None,
    ) -> Campaign:
        """
        Crée une nouvelle campagne de scan.

        Args:
            name: Nom de la campagne
            targets: Liste des cibles
            config: Configuration du scan (optionnel)
            auth_config: Configuration des tests d'authentification (optionnel)

        Returns:
            Campaign créée avec ID
        """
        # Configuration par défaut si non spécifiée
        if config is None:
            config = ScanConfig(
                scan_type=ScanScanType.QUICK,
                ports_range=None,
                timeout=DEFAULT_SCAN_CONFIG["timeout"],
                rate_limit=DEFAULT_SCAN_CONFIG["rate_limit"],
            )

        # Création de la campagne
        campaign = Campaign(
            name=name,
            targets=targets,
            config=config,
            status=CampaignStatus.PENDING,
        )

        # Ajout de la configuration auth si fournie
        if auth_config:
            campaign.config.auth_tests_enabled = auth_config.get(
                "enabled", False
            )

        # Stockage dans MongoDB
        campaign_doc = campaign.model_dump()
        result = await self.db["campaigns"].insert_one(campaign_doc)
        campaign.id = str(result.inserted_id)

        # Mise à jour avec l'ID
        await self.db["campaigns"].update_one(
            {"_id": result.inserted_id},
            {"$set": {"_id": campaign.id}},
        )

        logger.info(
            "Campagne '%s' créée avec l'ID %s",
            name,
            campaign.id,
        )

        return campaign

    async def list_campaigns(self) -> list[Campaign]:
        """
        Liste toutes les campagnes.

        Returns:
            Liste des campagnes
        """
        campaigns: list[Campaign] = []

        cursor = self.db["campaigns"].find().sort("created_at", -1)

        async for doc in cursor:
            try:
                # Conversion de l'ObjectId en string
                if "_id" in doc and not isinstance(doc["_id"], str):
                    doc["_id"] = str(doc["_id"])

                campaign = Campaign(**doc)
                campaigns.append(campaign)
            except Exception as e:
                logger.warning("Erreur lors de la conversion d'une campagne: %s", str(e))
                continue

        logger.info("Récupération de %d campagnes", len(campaigns))

        return campaigns

    async def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        """
        Récupère une campagne par son ID.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            Campaign ou None si non trouvée
        """
        doc = await self.db["campaigns"].find_one({"_id": campaign_id})

        if not doc:
            return None

        try:
            if "_id" in doc and not isinstance(doc["_id"], str):
                doc["_id"] = str(doc["_id"])

            return Campaign(**doc)
        except Exception as e:
            logger.error(
                "Erreur lors de la conversion de la campagne %s: %s",
                campaign_id,
                str(e),
            )
            return None

    async def update_campaign_status(
        self,
        campaign_id: str,
        status: str,
    ) -> bool:
        """
        Met à jour le statut d'une campagne.

        Args:
            campaign_id: Identifiant de la campagne
            status: Nouveau statut

        Returns:
            True si la mise à jour a réussi
        """
        try:
            status_enum = CampaignStatus(status)
            await self._update_campaign_status(campaign_id, status_enum)
            return True
        except ValueError:
            logger.error("Statut invalide: %s", status)
            return False

    async def store_campaign_results(
        self,
        campaign_id: str,
        results: dict[str, Any],
    ) -> bool:
        """
        Stocke les résultats d'une campagne.

        Args:
            campaign_id: Identifiant de la campagne
            results: Résultats à stocker

        Returns:
            True si le stockage a réussi
        """
        try:
            await self.db["campaigns"].update_one(
                {"_id": campaign_id},
                {
                    "$set": {
                        "results": results,
                        "updated_at": datetime.utcnow(),
                    }
                },
            )
            logger.info(
                "Résultats stockés pour la campagne %s",
                campaign_id,
            )
            return True
        except Exception as e:
            logger.error(
                "Erreur lors du stockage des résultats pour %s: %s",
                campaign_id,
                str(e),
            )
            return False


# ---------------------------------------------------------------------------
# Factory function pour l'initialisation
# ---------------------------------------------------------------------------

async def get_scan_orchestrator() -> ScanOrchestrator:
    """
    Factory function pour obtenir une instance de ScanOrchestrator.

    Returns:
        ScanOrchestrator initialisé
    """
    from app.utils.database import get_database

    db = await get_database()
    return ScanOrchestrator(db)