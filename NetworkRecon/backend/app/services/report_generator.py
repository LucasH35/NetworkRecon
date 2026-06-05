"""Service de génération et d'export de rapports NetworkRecon.

Ce module implémente la génération de rapports complets pour les campagnes
de scan réseau, incluant :
- Rapports JSON structurés
- Rapports CSV (UTF-8 BOM pour Excel)
- Rapports PDF professionnels avec reportlab
- Stockage et gestion des rapports dans MongoDB
"""

import asyncio
import csv
import io
import json
import logging
from datetime import datetime
from typing import Any, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.auth_test import AuthTestResult
from app.models.host import HostInfo
from app.models.report import ExportFormat, Report, ReportSummary
from app.models.scan import Campaign, CampaignStatus
from app.models.vulnerability import Severity, Vulnerability

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Couleurs par sévérité (pour PDF)
# ──────────────────────────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    "critical": "#DC143C",  # Rouge cramoisi
    "high": "#FF4500",      # Rouge-orange
    "medium": "#FFA500",    # Orange
    "low": "#FFD700",       # Or
    "info": "#4682B4",      # Bleu acier
}

SEVERITY_LABELS = {
    "critical": "Critique",
    "high": "Élevée",
    "medium": "Moyenne",
    "low": "Faible",
    "info": "Information",
}


class ReportGeneratorError(Exception):
    """Exception personnalisée pour les erreurs de génération de rapports."""
    pass


class CampaignNotFoundError(ReportGeneratorError):
    """Exception levée quand une campagne est introuvable."""
    pass


class ReportFormatError(ReportGeneratorError):
    """Exception levée pour un format d'export non supporté."""
    pass


class ReportGenerator:
    """Service de génération et d'export de rapports.

    Ce service génère des rapports complets pour les campagnes de scan réseau
    avec support pour les formats JSON, CSV et PDF.

    Attributes:
        db: Base de données Motor asynchrone
    """

    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        """Initialise le générateur de rapports.

        Args:
            db: Instance de base de données Motor asynchrone
        """
        self.db = db
        logger.info("ReportGenerator initialisé avec succès")

    # ──────────────────────────────────────────────────────────────────────────
    # Récupération des données depuis MongoDB
    # ──────────────────────────────────────────────────────────────────────────

    async def _get_campaign(self, campaign_id: str) -> Campaign:
        """Récupère une campagne par son ID.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            Campaign: La campagne trouvée

        Raises:
            CampaignNotFoundError: Si la campagne est introuvable
        """
        try:
            doc = await self.db.campaigns.find_one({"_id": campaign_id})
            if doc is None:
                raise CampaignNotFoundError(
                    f"Campagne introuvable : {campaign_id}"
                )
            doc["_id"] = str(doc["_id"])
            return Campaign(**doc)
        except CampaignNotFoundError:
            raise
        except Exception as e:
            logger.error(
                "Erreur lors de la récupération de la campagne %s : %s",
                campaign_id,
                e,
            )
            raise ReportGeneratorError(
                f"Erreur lors de la récupération de la campagne : {e}"
            )

    async def _get_hosts(self, campaign_id: str) -> list[dict]:
        """Récupère tous les hôtes associés à une campagne.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            list[dict]: Liste des documents hôtes
        """
        try:
            cursor = self.db.hosts.find({"campaign_id": campaign_id})
            hosts = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                hosts.append(doc)
            return hosts
        except Exception as e:
            logger.error(
                "Erreur lors de la récupération des hôtes pour %s : %s",
                campaign_id,
                e,
            )
            return []

    async def _get_vulnerabilities(self, campaign_id: str) -> list[dict]:
        """Récupère toutes les vulnérabilités associées à une campagne.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            list[dict]: Liste des documents de vulnérabilités
        """
        try:
            cursor = self.db.vulnerability_scans.find(
                {"campaign_id": campaign_id}
            )
            vulns = []
            async for doc in cursor:
                for v in doc.get("vulnerabilities", []):
                    v["_scan_id"] = str(doc.get("_id", ""))
                    vulns.append(v)
            return vulns
        except Exception as e:
            logger.error(
                "Erreur lors de la récupération des vulnérabilités pour %s : %s",
                campaign_id,
                e,
            )
            return []

    async def _get_auth_results(self, campaign_id: str) -> list[dict]:
        """Récupère les résultats de tests d'authentification d'une campagne.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            list[dict]: Liste des résultats d'authentification
        """
        try:
            cursor = self.db.auth_test_results.find(
                {"campaign_id": campaign_id}
            )
            results = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                results.append(doc)
            return results
        except Exception as e:
            logger.error(
                "Erreur lors de la récupération des tests d'auth pour %s : %s",
                campaign_id,
                e,
            )
            return []

    # ──────────────────────────────────────────────────────────────────────────
    # Construction des résumés
    # ──────────────────────────────────────────────────────────────────────────

    async def build_summary(self, campaign_id: str) -> ReportSummary:
        """Construit le résumé statistique d'une campagne.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            ReportSummary: Résumé statistique complet
        """
        logger.info(
            "Construction du résumé pour la campagne %s", campaign_id
        )

        hosts = await self._get_hosts(campaign_id)
        vulns_raw = await self._get_vulnerabilities(campaign_id)

        # Comptage des services
        total_services = sum(
            len(h.get("ports", [])) for h in hosts
        )

        # Comptage des vulnérabilités par sévérité
        by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for v in vulns_raw:
            cve = v.get("cve", {})
            severity = cve.get("severity", "info")
            if severity in by_severity:
                by_severity[severity] += 1

        total_vulns = sum(by_severity.values())

        # Durée du scan depuis la campagne
        scan_duration = None
        try:
            campaign = await self._get_campaign(campaign_id)
            if campaign.created_at:
                # Utiliser completed_at si disponible, sinon now
                end_time = datetime.utcnow()
                if campaign.status == CampaignStatus.COMPLETED:
                    # Chercher la date de fin dans les résultats
                    for result in campaign.results:
                        if result.end_time:
                            end_time = result.end_time
                            break
                scan_duration = (end_time - campaign.created_at).total_seconds()
        except Exception:
            pass

        summary = ReportSummary(
            total_hosts=len(hosts),
            total_services=total_services,
            total_vulnerabilities=total_vulns,
            by_severity=by_severity,
            scan_duration=scan_duration,
        )

        logger.info(
            "Résumé construit : %d hôtes, %d services, %d vulnérabilités",
            summary.total_hosts,
            summary.total_services,
            summary.total_vulnerabilities,
        )
        return summary

    async def get_hosts_summary(self, campaign_id: str) -> list[dict]:
        """Résumé des hôtes découverts.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            list[dict]: Liste des résumés d'hôtes
        """
        hosts = await self._get_hosts(campaign_id)
        summary = []
        for h in hosts:
            ports = h.get("ports", [])
            summary.append({
                "ip_address": h.get("ip_address", "N/A"),
                "hostname": h.get("hostname", "N/A"),
                "os_detection": h.get("os_detection", "N/A"),
                "status": h.get("status", "unknown"),
                "ports_count": len(ports),
                "open_ports": [
                    p.get("number")
                    for p in ports
                    if p.get("state") == "open"
                ],
            })
        return summary

    async def get_vulnerabilities_summary(self, campaign_id: str) -> dict:
        """Résumé des vulnérabilités par sévérité.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            dict: Résumé structuré des vulnérabilités
        """
        vulns_raw = await self._get_vulnerabilities(campaign_id)

        by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }

        for v in vulns_raw:
            cve = v.get("cve", {})
            severity = cve.get("severity", "info")
            entry = {
                "cve_id": cve.get("cve_id", "N/A"),
                "description": cve.get("description", "N/A"),
                "cvss_score": cve.get("cvss_score"),
                "host_ip": v.get("host_ip", "N/A"),
                "port": v.get("port"),
                "service": v.get("service", "N/A"),
                "remediation": v.get("remediation"),
            }
            if severity in by_severity:
                by_severity[severity].append(entry)
            else:
                by_severity["info"].append(entry)

        return {
            "total": len(vulns_raw),
            "by_severity": {
                sev: {
                    "count": len(entries),
                    "vulnerabilities": entries,
                }
                for sev, entries in by_severity.items()
            },
        }

    async def get_mitre_summary(self, campaign_id: str) -> dict:
        """Résumé des techniques MITRE ATT&CK identifiées.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            dict: Résumé des mappings MITRE
        """
        vulns_raw = await self._get_vulnerabilities(campaign_id)

        techniques: dict[str, dict] = {}
        tactics: dict[str, int] = {}

        for v in vulns_raw:
            mitre = v.get("mitre_mapping")
            if not mitre:
                continue

            tech_id = mitre.get("technique_id", "")
            tech_name = mitre.get("technique_name", "N/A")
            tactic = mitre.get("tactic", "N/A")

            if tech_id not in techniques:
                techniques[tech_id] = {
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "tactic": tactic,
                    "description": mitre.get("description", ""),
                    "url": mitre.get("url", ""),
                    "affected_hosts": set(),
                    "count": 0,
                }

            techniques[tech_id]["affected_hosts"].add(
                v.get("host_ip", "N/A")
            )
            techniques[tech_id]["count"] += 1

            tactics[tactic] = tactics.get(tactic, 0) + 1

        # Conversion des sets en listes pour la sérialisation
        for tech in techniques.values():
            tech["affected_hosts"] = sorted(list(tech["affected_hosts"]))
            tech["affected_hosts_count"] = len(tech["affected_hosts"])

        return {
            "total_techniques": len(techniques),
            "techniques": sorted(
                techniques.values(),
                key=lambda x: x["count"],
                reverse=True,
            ),
            "by_tactic": dict(
                sorted(tactics.items(), key=lambda x: x[1], reverse=True)
            ),
        }

    async def get_auth_summary(self, campaign_id: str) -> dict:
        """Résumé des tests d'authentification.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            dict: Résumé des tests d'authentification
        """
        results = await self._get_auth_results(campaign_id)

        total = len(results)
        successes = sum(1 for r in results if r.get("success", False))
        failures = total - successes

        by_service: dict[str, dict] = {}
        for r in results:
            service = r.get("service", "unknown")
            if service not in by_service:
                by_service[service] = {"total": 0, "successes": 0, "failures": 0}
            by_service[service]["total"] += 1
            if r.get("success", False):
                by_service[service]["successes"] += 1
            else:
                by_service[service]["failures"] += 1

        return {
            "total_tests": total,
            "successes": successes,
            "failures": failures,
            "success_rate": (
                round(successes / total * 100, 2) if total > 0 else 0.0
            ),
            "by_service": by_service,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Génération de rapports
    # ──────────────────────────────────────────────────────────────────────────

    async def generate_json_report(self, campaign_id: str) -> dict:
        """Génère un rapport JSON structuré.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            dict: Rapport JSON complet
        """
        logger.info("Génération du rapport JSON pour %s", campaign_id)

        campaign = await self._get_campaign(campaign_id)
        summary = await self.build_summary(campaign_id)
        hosts = await self.get_hosts_summary(campaign_id)
        vulns = await self.get_vulnerabilities_summary(campaign_id)
        mitre = await self.get_mitre_summary(campaign_id)
        auth = await self.get_auth_summary(campaign_id)

        report = {
            "report_type": "network_reconnaissance",
            "generated_at": datetime.utcnow().isoformat(),
            "campaign": {
                "id": campaign.id,
                "name": campaign.name,
                "description": campaign.description,
                "status": campaign.status.value if campaign.status else "unknown",
                "created_at": (
                    campaign.created_at.isoformat()
                    if campaign.created_at
                    else None
                ),
            },
            "summary": {
                "total_hosts": summary.total_hosts,
                "total_services": summary.total_services,
                "total_vulnerabilities": summary.total_vulnerabilities,
                "by_severity": summary.by_severity,
                "scan_duration_seconds": summary.scan_duration,
            },
            "hosts": hosts,
            "vulnerabilities": vulns,
            "mitre_attack": mitre,
            "authentication_tests": auth,
            "recommendations": self._generate_recommendations(
                summary, vulns, auth
            ),
        }

        logger.info(
            "Rapport JSON généré avec succès pour %s", campaign_id
        )
        return report

    async def generate_csv_report(self, campaign_id: str) -> str:
        """Génère un rapport CSV avec les résultats.

        Le CSV est encodé en UTF-8 avec BOM pour une compatibilité Excel.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            str: Contenu CSV du rapport
        """
        logger.info("Génération du rapport CSV pour %s", campaign_id)

        output = io.StringIO()
        writer = csv.writer(output, delimiter=";", quoting=csv.QUOTE_MINIMAL)

        # En-tête CSV
        writer.writerow(["=== RAPPORT NETWORKRECON ==="])
        writer.writerow(["Campagne", campaign_id])
        writer.writerow(["Date de génération", datetime.utcnow().isoformat()])
        writer.writerow([])

        # ── Section Hôtes ─────────────────────────────────────────────────
        writer.writerow(["=== HÔTES DÉCOUVERTS ==="])
        writer.writerow([
            "Adresse IP", "Hostname", "Système d'exploitation",
            "Statut", "Nombre de ports", "Ports ouverts",
        ])
        hosts = await self.get_hosts_summary(campaign_id)
        for h in hosts:
            open_ports_str = ", ".join(
                str(p) for p in h.get("open_ports", [])
            )
            writer.writerow([
                h["ip_address"],
                h["hostname"],
                h["os_detection"],
                h["status"],
                h["ports_count"],
                open_ports_str,
            ])
        writer.writerow([])

        # ── Section Vulnérabilités ────────────────────────────────────────
        writer.writerow(["=== VULNÉRABILITÉS ==="])
        writer.writerow([
            "CVE ID", "Sévérité", "Score CVSS", "Hôte", "Port",
            "Service", "Description", "Remédiation",
        ])
        vulns_data = await self.get_vulnerabilities_summary(campaign_id)
        for sev_name, sev_data in vulns_data.get("by_severity", {}).items():
            for v in sev_data.get("vulnerabilities", []):
                writer.writerow([
                    v.get("cve_id", ""),
                    SEVERITY_LABELS.get(sev_name, sev_name),
                    v.get("cvss_score", ""),
                    v.get("host_ip", ""),
                    v.get("port", ""),
                    v.get("service", ""),
                    v.get("description", ""),
                    v.get("remediation", ""),
                ])
        writer.writerow([])

        # ── Section MITRE ATT&CK ──────────────────────────────────────────
        writer.writerow(["=== TECHNIQUES MITRE ATT&CK ==="])
        writer.writerow([
            "Technique ID", "Nom", "Tactique", "Hôtes affectés",
            "Nombre de détections", "URL",
        ])
        mitre_data = await self.get_mitre_summary(campaign_id)
        for tech in mitre_data.get("techniques", []):
            writer.writerow([
                tech.get("technique_id", ""),
                tech.get("technique_name", ""),
                tech.get("tactic", ""),
                ", ".join(tech.get("affected_hosts", [])),
                tech.get("count", 0),
                tech.get("url", ""),
            ])
        writer.writerow([])

        # ── Section Tests d'authentification ──────────────────────────────
        writer.writerow(["=== TESTS D'AUTHENTIFICATION ==="])
        auth_data = await self.get_auth_summary(campaign_id)
        writer.writerow([
            "Service", "Total des tests", "Succès", "Échecs",
            "Taux de réussite (%)",
        ])
        for service, stats in auth_data.get("by_service", {}).items():
            writer.writerow([
                service,
                stats["total"],
                stats["successes"],
                stats["failures"],
                round(
                    stats["successes"] / stats["total"] * 100, 2
                ) if stats["total"] > 0 else 0,
            ])

        # Ajout du BOM UTF-8 pour Excel
        csv_content = "\ufeff" + output.getvalue()
        output.close()

        logger.info(
            "Rapport CSV généré avec succès pour %s", campaign_id
        )
        return csv_content

    async def generate_pdf_report(self, campaign_id: str) -> bytes:
        """Génère un rapport PDF professionnel avec reportlab.

        Le PDF inclut :
        - Page de couverture
        - Table des matières
        - Résumé exécutif
        - Section Hôtes découverts
        - Section Ports et services
        - Section Vulnérabilités (classées par sévérité)
        - Section MITRE ATT&CK
        - Section Tests d'authentification
        - Recommandations de remédiation

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            bytes: Contenu PDF du rapport

        Raises:
            ReportGeneratorError: Si reportlab n'est pas installé
        """
        try:
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import cm, mm
            from reportlab.platypus import (
                PageBreak,
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )
        except ImportError:
            raise ReportGeneratorError(
                "reportlab n'est pas installé. "
                "Installez-le avec : pip install reportlab"
            )

        logger.info("Génération du rapport PDF pour %s", campaign_id)

        # Récupération des données
        campaign = await self._get_campaign(campaign_id)
        summary = await self.build_summary(campaign_id)
        hosts = await self.get_hosts_summary(campaign_id)
        vulns_data = await self.get_vulnerabilities_summary(campaign_id)
        mitre_data = await self.get_mitre_summary(campaign_id)
        auth_data = await self.get_auth_summary(campaign_id)

        # Création du buffer et du document
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2.5 * cm,
            bottomMargin=2.5 * cm,
        )

        # Styles
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="CoverTitle",
            parent=styles["Title"],
            fontSize=28,
            spaceAfter=20,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#1a237e"),
        ))
        styles.add(ParagraphStyle(
            name="CoverSubtitle",
            parent=styles["Normal"],
            fontSize=14,
            spaceAfter=10,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#455a64"),
        ))
        styles.add(ParagraphStyle(
            name="SectionTitle",
            parent=styles["Heading1"],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor("#1a237e"),
            borderWidth=1,
            borderColor=colors.HexColor("#1a237e"),
            borderPadding=5,
        ))
        styles.add(ParagraphStyle(
            name="SubSection",
            parent=styles["Heading2"],
            fontSize=13,
            spaceBefore=12,
            spaceAfter=8,
            textColor=colors.HexColor("#37474f"),
        ))
        styles.add(ParagraphStyle(
            name="BodyFR",
            parent=styles["Normal"],
            fontSize=10,
            spaceAfter=6,
            leading=14,
        ))
        styles.add(ParagraphStyle(
            name="SmallText",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.grey,
        ))
        styles.add(ParagraphStyle(
            name="CriticalCell",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor(SEVERITY_COLORS["critical"]),
            fontName="Helvetica-Bold",
        ))

        elements: list = []

        # ──────────────────────────────────────────────────────────────────
        # PAGE DE COUVERTURE
        # ──────────────────────────────────────────────────────────────────
        elements.append(Spacer(1, 6 * cm))
        elements.append(Paragraph(
            "NetworkRecon", styles["CoverTitle"]
        ))
        elements.append(Paragraph(
            "Rapport de Reconnaissance Réseau", styles["CoverSubtitle"]
        ))
        elements.append(Spacer(1, 1.5 * cm))

        campaign_name = campaign.name or "Campagne sans nom"
        elements.append(Paragraph(
            f"<b>Campagne :</b> {campaign_name}", styles["CoverSubtitle"]
        ))
        elements.append(Paragraph(
            f"<b>Date :</b> {datetime.utcnow().strftime('%d/%m/%Y %H:%M')}",
            styles["CoverSubtitle"],
        ))
        if campaign.description:
            elements.append(Paragraph(
                f"<b>Description :</b> {campaign.description}",
                styles["CoverSubtitle"],
            ))
        elements.append(Spacer(1, 2 * cm))
        elements.append(Paragraph(
            "Document généré automatiquement par NetworkRecon",
            styles["SmallText"],
        ))
        elements.append(PageBreak())

        # ──────────────────────────────────────────────────────────────────
        # TABLE DES MATIÈRES
        # ──────────────────────────────────────────────────────────────────
        elements.append(Paragraph("Table des matières", styles["SectionTitle"]))
        elements.append(Spacer(1, 0.5 * cm))
        toc_items = [
            "1. Résumé exécutif",
            "2. Hôtes découverts",
            "3. Vulnérabilités",
            "4. Techniques MITRE ATT&CK",
            "5. Tests d'authentification",
            "6. Recommandations de remédiation",
        ]
        for item in toc_items:
            elements.append(Paragraph(item, styles["BodyFR"]))
        elements.append(PageBreak())

        # ──────────────────────────────────────────────────────────────────
        # RÉSUMÉ EXÉCUTIF
        # ──────────────────────────────────────────────────────────────────
        elements.append(Paragraph("1. Résumé exécutif", styles["SectionTitle"]))
        elements.append(Spacer(1, 0.3 * cm))

        summary_data = [
            ["Métrique", "Valeur"],
            ["Hôtes découverts", str(summary.total_hosts)],
            ["Services détectés", str(summary.total_services)],
            ["Vulnérabilités totales", str(summary.total_vulnerabilities)],
            ["  - Critiques", str(summary.by_severity.get("critical", 0))],
            ["  - Élevées", str(summary.by_severity.get("high", 0))],
            ["  - Moyennes", str(summary.by_severity.get("medium", 0))],
            ["  - Faibles", str(summary.by_severity.get("low", 0))],
            ["  - Information", str(summary.by_severity.get("info", 0))],
        ]
        if summary.scan_duration is not None:
            minutes = int(summary.scan_duration // 60)
            seconds = int(summary.scan_duration % 60)
            summary_data.append(
                ["Durée du scan", f"{minutes}m {seconds}s"]
            )

        summary_table = Table(summary_data, colWidths=[10 * cm, 6 * cm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white,
                colors.HexColor("#f5f5f5"),
            ]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(summary_table)
        elements.append(PageBreak())

        # ──────────────────────────────────────────────────────────────────
        # HÔTES DÉCOUVERTS
        # ──────────────────────────────────────────────────────────────────
        elements.append(
            Paragraph("2. Hôtes découverts", styles["SectionTitle"])
        )
        elements.append(Spacer(1, 0.3 * cm))

        if hosts:
            hosts_header = ["IP", "Hostname", "OS", "Statut", "Ports"]
            hosts_rows = [hosts_header]
            for h in hosts:
                open_ports = ", ".join(
                    str(p) for p in h.get("open_ports", [])[:5]
                )
                if len(h.get("open_ports", [])) > 5:
                    open_ports += f" (+{len(h['open_ports']) - 5})"
                hosts_rows.append([
                    h["ip_address"],
                    h.get("hostname", "N/A") or "N/A",
                    h.get("os_detection", "N/A") or "N/A",
                    h.get("status", "N/A"),
                    open_ports or "Aucun",
                ])

            hosts_table = Table(
                hosts_rows,
                colWidths=[3.2 * cm, 4 * cm, 4 * cm, 2 * cm, 3 * cm],
            )
            hosts_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ALIGN", (3, 0), (3, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                    colors.white,
                    colors.HexColor("#f5f5f5"),
                ]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            elements.append(hosts_table)
        else:
            elements.append(Paragraph(
                "Aucun hôte découvert pour cette campagne.",
                styles["BodyFR"],
            ))
        elements.append(PageBreak())

        # ──────────────────────────────────────────────────────────────────
        # VULNÉRABILITÉS
        # ──────────────────────────────────────────────────────────────────
        elements.append(
            Paragraph("3. Vulnérabilités", styles["SectionTitle"])
        )
        elements.append(Spacer(1, 0.3 * cm))

        severity_order = ["critical", "high", "medium", "low", "info"]
        for sev in severity_order:
            sev_data = vulns_data.get("by_severity", {}).get(sev, {})
            vuln_list = sev_data.get("vulnerabilities", [])
            if not vuln_list:
                continue

            color = colors.HexColor(SEVERITY_COLORS.get(sev, "#000000"))
            label = SEVERITY_LABELS.get(sev, sev)

            elements.append(Paragraph(
                f"<font color='{SEVERITY_COLORS.get(sev, '#000000')}'>"
                f"<b>{label}</b></font> ({len(vuln_list)} vulnérabilités)",
                styles["SubSection"],
            ))

            vuln_header = ["CVE ID", "CVSS", "Hôte", "Port", "Service", "Description"]
            vuln_rows = [vuln_header]
            for v in vuln_list[:20]:  # Limite à 20 par sévérité
                cvss_str = (
                    f"{v.get('cvss_score', 'N/A')}"
                    if v.get("cvss_score") is not None
                    else "N/A"
                )
                desc = v.get("description", "N/A")
                if len(desc) > 60:
                    desc = desc[:57] + "..."
                vuln_rows.append([
                    v.get("cve_id", "N/A"),
                    cvss_str,
                    v.get("host_ip", "N/A"),
                    str(v.get("port", "N/A")),
                    v.get("service", "N/A"),
                    desc,
                ])

            vuln_table = Table(
                vuln_rows,
                colWidths=[2.8 * cm, 1.3 * cm, 2.8 * cm, 1.3 * cm, 2 * cm, 6 * cm],
            )
            vuln_style = [
                ("BACKGROUND", (0, 0), (-1, 0), color),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                    colors.white,
                    colors.HexColor("#fafafa"),
                ]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
            vuln_table.setStyle(TableStyle(vuln_style))
            elements.append(vuln_table)
            elements.append(Spacer(1, 0.5 * cm))

            if len(vuln_list) > 20:
                elements.append(Paragraph(
                    f"<i>... et {len(vuln_list) - 20} vulnérabilités supplémentaires</i>",
                    styles["SmallText"],
                ))

        if not any(
            vulns_data.get("by_severity", {}).get(s, {}).get("vulnerabilities")
            for s in severity_order
        ):
            elements.append(Paragraph(
                "Aucune vulnérabilité détectée pour cette campagne.",
                styles["BodyFR"],
            ))

        elements.append(PageBreak())

        # ──────────────────────────────────────────────────────────────────
        # MITRE ATT&CK
        # ──────────────────────────────────────────────────────────────────
        elements.append(
            Paragraph(
                "4. Techniques MITRE ATT&CK", styles["SectionTitle"]
            )
        )
        elements.append(Spacer(1, 0.3 * cm))

        techniques = mitre_data.get("techniques", [])
        if techniques:
            elements.append(Paragraph(
                f"<b>Total des techniques identifiées :</b> "
                f"{mitre_data.get('total_techniques', 0)}",
                styles["BodyFR"],
            ))
            elements.append(Spacer(1, 0.3 * cm))

            mitre_header = ["Technique", "Nom", "Tactique", "Hôtes", "Détections"]
            mitre_rows = [mitre_header]
            for tech in techniques[:15]:
                mitre_rows.append([
                    tech.get("technique_id", ""),
                    tech.get("technique_name", "N/A"),
                    tech.get("tactic", "N/A"),
                    str(tech.get("affected_hosts_count", 0)),
                    str(tech.get("count", 0)),
                ])

            mitre_table = Table(
                mitre_rows,
                colWidths=[2.5 * cm, 5 * cm, 4 * cm, 2 * cm, 2.5 * cm],
            )
            mitre_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ALIGN", (3, 0), (4, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                    colors.white,
                    colors.HexColor("#eceff1"),
                ]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(mitre_table)

            # Répartition par tactique
            by_tactic = mitre_data.get("by_tactic", {})
            if by_tactic:
                elements.append(Spacer(1, 0.5 * cm))
                elements.append(Paragraph(
                    "<b>Répartition par tactique :</b>", styles["SubSection"]
                ))
                for tactic, count in by_tactic.items():
                    elements.append(Paragraph(
                        f"&bull; {tactic} : {count} détection(s)",
                        styles["BodyFR"],
                    ))
        else:
            elements.append(Paragraph(
                "Aucune technique MITRE ATT&CK identifiée.",
                styles["BodyFR"],
            ))

        elements.append(PageBreak())

        # ──────────────────────────────────────────────────────────────────
        # TESTS D'AUTHENTIFICATION
        # ──────────────────────────────────────────────────────────────────
        elements.append(
            Paragraph(
                "5. Tests d'authentification", styles["SectionTitle"]
            )
        )
        elements.append(Spacer(1, 0.3 * cm))

        total_tests = auth_data.get("total_tests", 0)
        if total_tests > 0:
            elements.append(Paragraph(
                f"<b>Total des tests :</b> {total_tests}", styles["BodyFR"]
            ))
            elements.append(Paragraph(
                f"<b>Succès :</b> {auth_data.get('successes', 0)} "
                f"({auth_data.get('success_rate', 0)}%)",
                styles["BodyFR"],
            ))
            elements.append(Paragraph(
                f"<b>Échecs :</b> {auth_data.get('failures', 0)}",
                styles["BodyFR"],
            ))
            elements.append(Spacer(1, 0.3 * cm))

            by_service = auth_data.get("by_service", {})
            if by_service:
                auth_header = ["Service", "Tests", "Succès", "Échecs", "Taux"]
                auth_rows = [auth_header]
                for service, stats in by_service.items():
                    rate = (
                        round(stats["successes"] / stats["total"] * 100, 1)
                        if stats["total"] > 0
                        else 0
                    )
                    auth_rows.append([
                        service,
                        str(stats["total"]),
                        str(stats["successes"]),
                        str(stats["failures"]),
                        f"{rate}%",
                    ])

                auth_table = Table(
                    auth_rows,
                    colWidths=[3.5 * cm, 3 * cm, 3 * cm, 3 * cm, 3 * cm],
                )
                auth_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#004d40")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                        colors.white,
                        colors.HexColor("#e0f2f1"),
                    ]),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]))
                elements.append(auth_table)
        else:
            elements.append(Paragraph(
                "Aucun test d'authentification effectué pour cette campagne.",
                styles["BodyFR"],
            ))

        elements.append(PageBreak())

        # ──────────────────────────────────────────────────────────────────
        # RECOMMANDATIONS DE REMÉDIATION
        # ──────────────────────────────────────────────────────────────────
        elements.append(
            Paragraph(
                "6. Recommandations de remédiation", styles["SectionTitle"]
            )
        )
        elements.append(Spacer(1, 0.3 * cm))

        recommendations = self._generate_recommendations(
            summary, vulns_data, auth_data
        )
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                elements.append(Paragraph(
                    f"<b>{i}.</b> {rec}", styles["BodyFR"]
                ))
        else:
            elements.append(Paragraph(
                "Aucune recommandation spécifique pour cette campagne.",
                styles["BodyFR"],
            ))

        # ── Pied de page ─────────────────────────────────────────────────
        elements.append(Spacer(1, 2 * cm))
        elements.append(Paragraph(
            "--- Fin du rapport ---", styles["SmallText"]
        ))
        elements.append(Paragraph(
            f"Généré le {datetime.utcnow().strftime('%d/%m/%Y à %H:%M:%S')} "
            "par NetworkRecon",
            styles["SmallText"],
        ))

        # Construction du PDF
        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()

        logger.info(
            "Rapport PDF généré avec succès pour %s (%d octets)",
            campaign_id,
            len(pdf_bytes),
        )
        return pdf_bytes

    # ──────────────────────────────────────────────────────────────────────────
    # Génération du rapport principal
    # ──────────────────────────────────────────────────────────────────────────

    async def generate_report(
        self,
        campaign_id: str,
        export_format: str = "json",
    ) -> Report:
        """Génère un rapport complet pour une campagne.

        Args:
            campaign_id: Identifiant de la campagne
            export_format: Format d'export (json, csv, pdf)

        Returns:
            Report: Objet rapport complet avec contenu et résumé

        Raises:
            CampaignNotFoundError: Si la campagne est introuvable
            ReportFormatError: Si le format n'est pas supporté
        """
        logger.info(
            "Génération du rapport pour la campagne %s (format: %s)",
            campaign_id,
            export_format,
        )

        # Validation du format
        try:
            fmt = ExportFormat(export_format)
        except ValueError:
            raise ReportFormatError(
                f"Format non supporté : {export_format}. "
                f"Formats disponibles : {[f.value for f in ExportFormat]}"
            )

        # Récupération de la campagne
        campaign = await self._get_campaign(campaign_id)

        # Génération du résumé
        summary = await self.build_summary(campaign_id)

        # Génération du contenu selon le format
        content: dict[str, Any] = {}
        if fmt == ExportFormat.JSON:
            content = await self.generate_json_report(campaign_id)
        elif fmt == ExportFormat.CSV:
            content = {"csv_content": await self.generate_csv_report(campaign_id)}
        elif fmt == ExportFormat.PDF:
            pdf_bytes = await self.generate_pdf_report(campaign_id)
            content = {"pdf_size_bytes": len(pdf_bytes)}
        elif fmt == ExportFormat.HTML:
            # HTML sera implémenté ultérieurement
            content = {"html_content": "<p>HTML export coming soon</p>"}

        # Construction de l'objet Report
        report = Report(
            campaign_id=campaign_id,
            generated_at=datetime.utcnow(),
            summary=summary,
            content=content,
            export_format=fmt,
            title=f"Rapport NetworkRecon - {campaign.name or campaign_id}",
            description=(
                f"Rapport de reconnaissance réseau pour la campagne "
                f"'{campaign.name}'"
            ),
            generated_by="report_generator",
        )

        # Stockage en base
        await self.store_report(report)

        logger.info(
            "Rapport généré et stocké : campaign=%s format=%s",
            campaign_id,
            export_format,
        )
        return report

    # ──────────────────────────────────────────────────────────────────────────
    # Export d'un rapport existant
    # ──────────────────────────────────────────────────────────────────────────

    async def export_report(
        self, report_id: str, format: str
    ) -> bytes:
        """Exporte un rapport déjà généré dans le format demandé.

        Args:
            report_id: Identifiant du rapport
            format: Format d'export (json, csv, pdf)

        Returns:
            bytes: Contenu du rapport exporté

        Raises:
            ReportGeneratorError: Si le rapport est introuvable ou erreur
        """
        logger.info(
            "Export du rapport %s en format %s", report_id, format
        )

        # Récupération du rapport depuis MongoDB
        doc = await self.db.reports.find_one({"_id": report_id})
        if doc is None:
            raise ReportGeneratorError(
                f"Rapport introuvable : {report_id}"
            )

        doc["_id"] = str(doc["_id"])
        report = Report(**doc)

        # Régénération selon le format demandé
        try:
            if format == "json":
                json_data = await self.generate_json_report(report.campaign_id)
                return json.dumps(json_data, indent=2, ensure_ascii=False).encode(
                    "utf-8"
                )
            elif format == "csv":
                csv_data = await self.generate_csv_report(report.campaign_id)
                return csv_data.encode("utf-8")
            elif format == "pdf":
                return await self.generate_pdf_report(report.campaign_id)
            elif format == "html":
                # HTML placeholder
                return b"<p>HTML export coming soon</p>"
            else:
                raise ReportFormatError(f"Format non supporté : {format}")
        except (CampaignNotFoundError, ReportFormatError):
            raise
        except Exception as e:
            raise ReportGeneratorError(
                f"Erreur lors de l'export : {e}"
            )

    # ──────────────────────────────────────────────────────────────────────────
    # Stockage et liste des rapports
    # ──────────────────────────────────────────────────────────────────────────

    async def store_report(self, report: Report) -> str:
        """Stocke un rapport dans MongoDB.

        Args:
            report: Objet Report à stocker

        Returns:
            str: Identifiant du rapport stocké
        """
        try:
            doc = report.model_dump(by_alias=True, exclude={"id"})
            result = await self.db.reports.insert_one(doc)
            report_id = str(result.inserted_id)

            # Mise à jour de l'ID dans le document
            await self.db.reports.update_one(
                {"_id": result.inserted_id},
                {"$set": {"_id": report_id}},
            )

            logger.info(
                "Rapport stocké avec l'ID %s (campagne: %s)",
                report_id,
                report.campaign_id,
            )
            return report_id
        except Exception as e:
            logger.error(
                "Erreur lors du stockage du rapport : %s", e
            )
            raise ReportGeneratorError(
                f"Erreur lors du stockage du rapport : {e}"
            )

    async def list_reports(self, campaign_id: str) -> list[Report]:
        """Liste les rapports d'une campagne.

        Args:
            campaign_id: Identifiant de la campagne

        Returns:
            list[Report]: Liste des rapports
        """
        try:
            cursor = self.db.reports.find(
                {"campaign_id": campaign_id}
            ).sort("generated_at", -1)

            reports = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                reports.append(Report(**doc))

            logger.info(
                " %d rapport(s) trouvé(s) pour la campagne %s",
                len(reports),
                campaign_id,
            )
            return reports
        except Exception as e:
            logger.error(
                "Erreur lors de la liste des rapports : %s", e
            )
            return []

    # ──────────────────────────────────────────────────────────────────────────
    # Génération de recommandations
    # ──────────────────────────────────────────────────────────────────────────

    def _generate_recommendations(
        self,
        summary: ReportSummary,
        vulns_data: dict,
        auth_data: dict,
    ) -> list[str]:
        """Génère des recommandations de remédiation basées sur les résultats.

        Args:
            summary: Résumé statistique
            vulns_data: Données de vulnérabilités
            auth_data: Données de tests d'authentification

        Returns:
            list[str]: Liste des recommandations
        """
        recommendations: list[str] = []

        # Recommandations basées sur les vulnérabilités critiques
        critical_count = summary.by_severity.get("critical", 0)
        if critical_count > 0:
            recommendations.append(
                f"<b>URGENT :</b> {critical_count} vulnérabilité(s) critique(s) "
                f"détectée(s). Appliquer les correctifs immédiatement et "
                f"isoler les hôtes affectés si nécessaire."
            )

        high_count = summary.by_severity.get("high", 0)
        if high_count > 0:
            recommendations.append(
                f"<b>Important :</b> {high_count} vulnérabilité(s) à sévérité "
                f"élevée requièrent une correction dans les plus brefs délais."
            )

        # Recommandations basées sur les CVE spécifiques
        for sev in ["critical", "high"]:
            sev_data = vulns_data.get("by_severity", {}).get(sev, {})
            for v in sev_data.get("vulnerabilities", []):
                remediation = v.get("remediation")
                if remediation and remediation not in recommendations:
                    recommendations.append(
                        f"[{v.get('cve_id', 'N/A')}] {remediation}"
                    )

        # Recommandations basées sur MITRE ATT&CK
        mitre_techniques = vulns_data.get("by_severity", {})
        if any(
            mitre_techniques.get(s, {}).get("vulnerabilities")
            for s in ["critical", "high"]
        ):
            recommendations.append(
                "Renforcer les contrôles d'accès réseau (segmentation, "
                "pare-feu) pour limiter la surface d'attaque."
            )

        # Recommandations basées sur les tests d'authentification
        if auth_data.get("successes", 0) > 0:
            recommendations.append(
                f"<b>Attention :</b> {auth_data['successes']} test(s) "
                f"authentification réussi(s). Renforcer les mots de passe "
                f"et implémenter l'authentification multi-facteurs (MFA)."
            )

        success_rate = auth_data.get("success_rate", 0)
        if success_rate > 50:
            recommendations.append(
                f"Le taux de réussite des tests d'authentification est "
                f"de {success_rate}%. Réviser les politiques de mots de passe."
            )

        # Recommandations générales
        if summary.total_hosts > 0:
            recommendations.append(
                "Effectuer un scan de vulnérabilités périodique "
                "(mensuel minimum) pour maintenir la visibilité."
            )

        if summary.total_services > 100:
            recommendations.append(
                "Réduire la surface d'attaque en désactivant les services "
                "non essentiels et en appliquant le principe du moindre privilège."
            )

        return recommendations

    # ──────────────────────────────────────────────────────────────────────────
    # Utilitaires
    # ──────────────────────────────────────────────────────────────────────────

    async def get_report(self, report_id: str) -> Optional[Report]:
        """Récupère un rapport par son ID.

        Args:
            report_id: Identifiant du rapport

        Returns:
            Optional[Report]: Le rapport trouvé ou None
        """
        try:
            doc = await self.db.reports.find_one({"_id": report_id})
            if doc:
                doc["_id"] = str(doc["_id"])
                return Report(**doc)
            return None
        except Exception as e:
            logger.error(
                "Erreur lors de la récupération du rapport %s : %s",
                report_id,
                e,
            )
            return None

    async def delete_report(self, report_id: str) -> bool:
        """Supprime un rapport.

        Args:
            report_id: Identifiant du rapport

        Returns:
            bool: True si supprimé, False sinon
        """
        try:
            result = await self.db.reports.delete_one({"_id": report_id})
            deleted = result.deleted_count > 0
            if deleted:
                logger.info("Rapport %s supprimé", report_id)
            return deleted
        except Exception as e:
            logger.error(
                "Erreur lors de la suppression du rapport %s : %s",
                report_id,
                e,
            )
            return False
