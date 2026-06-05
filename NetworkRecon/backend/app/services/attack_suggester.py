"""Service de suggestion d'attaques brute force basé sur les CVE découvertes."""

import logging
from typing import Optional
from datetime import datetime, timedelta

from app.models.auth_test import (
    AttackSuggestion,
    AttackSeverity,
    ServiceType,
)
from app.utils.database import get_database

logger = logging.getLogger(__name__)

# ── Mapping services → attaques brute force ──────────────────────────────
# Chaque service ouvert peut être une cible d'attaque.
# Le severity est ajusté si des CVE critiques sont associées.

SERVICE_ATTACK_MAP: dict[str, dict] = {
    "ssh": {
        "service": ServiceType.SSH,
        "base_severity": AttackSeverity.HIGH,
        "description": "Brute force SSH - tentative de connexion avec identifiants courants",
        "wordlist": "rockyou.txt",
        "duration": "~5 min par hôte",
    },
    "ftp": {
        "service": ServiceType.FTP,
        "base_severity": AttackSeverity.HIGH,
        "description": "Brute force FTP - authentification avec identifiants par défaut ou courants",
        "wordlist": "rockyou.txt",
        "duration": "~3 min par hôte",
    },
    "smb": {
        "service": ServiceType.SMB,
        "base_severity": AttackSeverity.CRITICAL,
        "description": "Brute force SMB - accès aux partages réseau avec identifiants compromis",
        "wordlist": "rockyou.txt",
        "duration": "~10 min par hôte",
    },
    "rdp": {
        "service": ServiceType.RDP,
        "base_severity": AttackSeverity.CRITICAL,
        "description": "Brute force RDP - accès distant Windows avec identifiants courants",
        "wordlist": "rockyou.txt",
        "duration": "~8 min par hôte",
    },
    "http": {
        "service": ServiceType.HTTP,
        "base_severity": AttackSeverity.MEDIUM,
        "description": "Brute force HTTP - attaque sur panneau d'authentification web",
        "wordlist": "rockyou.txt",
        "duration": "~5 min par hôte",
    },
    "https": {
        "service": ServiceType.HTTPS,
        "base_severity": AttackSeverity.MEDIUM,
        "description": "Brute force HTTPS - attaque sur panneau d'authentification web sécurisé",
        "wordlist": "rockyou.txt",
        "duration": "~5 min par hôte",
    },
    "mysql": {
        "service": ServiceType.MYSQL,
        "base_severity": AttackSeverity.HIGH,
        "description": "Brute force MySQL - accès à la base de données avec identifiants courants",
        "wordlist": "rockyou.txt",
        "duration": "~4 min par hôte",
    },
    "postgresql": {
        "service": ServiceType.POSTGRESQL,
        "base_severity": AttackSeverity.HIGH,
        "description": "Brute force PostgreSQL - accès à la base de données",
        "wordlist": "rockyou.txt",
        "duration": "~4 min par hôte",
    },
    "redis": {
        "service": ServiceType.REDIS,
        "base_severity": AttackSeverity.CRITICAL,
        "description": "Brute force Redis - accès au cache avec authentification optional",
        "wordlist": "common_redis_passwords.txt",
        "duration": "~1 min par hôte",
    },
    "mongodb": {
        "service": ServiceType.MONGODB,
        "base_severity": AttackSeverity.HIGH,
        "description": "Brute force MongoDB - accès à la base NoSQL",
        "wordlist": "rockyou.txt",
        "duration": "~3 min par hôte",
    },
    "telnet": {
        "service": ServiceType.SSH,  # Telnet mapped to SSH for testing
        "base_severity": AttackSeverity.CRITICAL,
        "description": "Brute force Telnet - protocole non chiffré, credentials en clair",
        "wordlist": "rockyou.txt",
        "duration": "~3 min par hôte",
    },
    "vnc": {
        "service": ServiceType.RDP,  # VNC mapped to RDP for testing
        "base_severity": AttackSeverity.HIGH,
        "description": "Brute force VNC - accès graphique distant",
        "wordlist": "vnc_passwords.txt",
        "duration": "~5 min par hôte",
    },
    "ldap": {
        "service": ServiceType.SMB,  # LDAP mapped to SMB for domain attacks
        "base_severity": AttackSeverity.CRITICAL,
        "description": "Brute force LDAP - authentification annuaire Active Directory",
        "wordlist": "ad_passwords.txt",
        "duration": "~10 min par hôte",
    },
}

# ── CVE qui augmentent la priorité ──────────────────────────────────────
# Si ces CVE sont trouvées sur un service, la severity est augmentée

CVE_SEVERITY_BOOST: dict[str, AttackSeverity] = {
    # SSH vulnérable → priorité maximale
    "CVE-2023-38408": AttackSeverity.CRITICAL,
    "CVE-2023-51385": AttackSeverity.CRITICAL,
    "CVE-2021-41617": AttackSeverity.HIGH,
    # HTTP/Injection → priorité haute
    "CVE-2021-44228": AttackSeverity.CRITICAL,  # Log4Shell
    "CVE-2022-22965": AttackSeverity.CRITICAL,  # Spring4Shell
    "CVE-2021-41773": AttackSeverity.CRITICAL,  # Apache RCE
    "CVE-2017-5638": AttackSeverity.CRITICAL,   # Struts RCE
    # SSL/TLS → priorité moyenne
    "CVE-2014-0160": AttackSeverity.HIGH,        # Heartbleed
    "CVE-2014-3566": AttackSeverity.MEDIUM,      # POODLE
    # MySQL
    "CVE-2009-2942": AttackSeverity.HIGH,
    "CVE-2021-2307": AttackSeverity.MEDIUM,
}


class AttackSuggestionService:
    """Analyse les hôtes et CVE pour suggérer des attaques brute force."""

    def __init__(self, db):
        self._db = db

    async def get_suggestions(
        self,
        campaign_id: Optional[str] = None,
        host_ip: Optional[str] = None,
    ) -> list[AttackSuggestion]:
        """
        Génère des suggestions d'attaques basées sur les hôtes découverts
        et les CVE trouvées.
        """
        suggestions: list[AttackSuggestion] = []
        seen: set[str] = set()  # éviter les doublons (host:service)

        # 1. Récupérer les hôtes avec leurs ports
        host_query = {}
        if host_ip:
            host_query["ip_address"] = host_ip

        hosts = []
        async for doc in self._db["hosts"].find(host_query):
            hosts.append(doc)

        if not hosts:
            logger.info("Aucun hôte trouvé pour générer des suggestions")
            return []

        # 2. Récupérer les CVE (depuis archived_vulnerabilities)
        vuln_query = {}
        if host_ip:
            vuln_query["host_ip"] = host_ip
        if campaign_id:
            vuln_query["campaign_id"] = campaign_id

        host_cves: dict[str, list[dict]] = {}  # ip → [cve_docs]
        async for doc in self._db["archived_vulnerabilities"].find(vuln_query):
            ip = doc.get("host_ip", "")
            if ip not in host_cves:
                host_cves[ip] = []
            host_cves[ip].append(doc)

        # 3. Analyser chaque hôte et ses ports
        for host in hosts:
            ip = host.get("ip_address", "")
            hostname = host.get("hostname")
            ports = host.get("ports", [])
            cves = host_cves.get(ip, [])

            # Indexer les CVE par service
            cves_by_service: dict[str, list[dict]] = {}
            for v in cves:
                svc = v.get("service", "").lower()
                if svc not in cves_by_service:
                    cves_by_service[svc] = []
                cves_by_service[svc].append(v)

            for port_info in ports:
                service_name = (port_info.get("service") or "").lower()
                port_number = port_info.get("number", 0)
                version = port_info.get("version", "")
                state = port_info.get("state", "open")

                if state != "open" or not service_name:
                    continue

                # Vérifier si on a une attaque pour ce service
                attack_info = SERVICE_ATTACK_MAP.get(service_name)
                if not attack_info:
                    continue

                # Éviter les doublons
                key = f"{ip}:{service_name}:{port_number}"
                if key in seen:
                    continue
                seen.add(key)

                # Déterminer la sévérité
                severity = attack_info["base_severity"]
                related_cves: list[str] = []
                reasons: list[str] = []

                # Vérifier les CVE associées à ce service
                service_cves = cves_by_service.get(service_name, [])
                for cve_doc in service_cves:
                    cve_id = cve_doc.get("cve", {}).get("cve_id", "")
                    if cve_id:
                        related_cves.append(cve_id)
                        # Augmenter la sévérité si CVE critique
                        if cve_id in CVE_SEVERITY_BOOST:
                            boost = CVE_SEVERITY_BOOST[cve_id]
                            if self._severity_rank(boost) > self._severity_rank(severity):
                                severity = boost

                # Construire la raison
                if related_cves:
                    reasons.append(
                        f"{len(related_cves)} CVE détectée(s) sur {service_name.upper()}"
                    )
                    if version:
                        reasons.append(f"Version: {service_name} {version}")
                else:
                    reasons.append(
                        f"Service {service_name.upper()} ouvert (port {port_number})"
                    )
                    if version:
                        reasons.append(f"Version détectée: {version}")

                # Construire la description
                desc_parts = [attack_info["description"]]
                if related_cves:
                    desc_parts.append(
                        f"CVE associées: {', '.join(related_cves[:3])}"
                    )
                if version:
                    desc_parts.append(f"Version: {version}")

                suggestion = AttackSuggestion(
                    host_ip=ip,
                    hostname=hostname,
                    service=attack_info["service"],
                    port=port_number,
                    severity=severity,
                    reason=" | ".join(reasons),
                    cve_ids=related_cves,
                    description=". ".join(desc_parts),
                    recommended_wordlist=attack_info["wordlist"],
                    estimated_duration=attack_info["duration"],
                )
                suggestions.append(suggestion)

        # Trier par sévérité (critical en premier)
        suggestions.sort(
            key=lambda s: self._severity_rank(s.severity), reverse=True
        )

        logger.info(
            "Généré %d suggestions d'attaques pour %d hôtes",
            len(suggestions),
            len(hosts),
        )
        return suggestions

    @staticmethod
    def _severity_rank(severity: AttackSeverity) -> int:
        """Retourne un score de sévérité pour le tri."""
        return {
            AttackSeverity.CRITICAL: 4,
            AttackSeverity.HIGH: 3,
            AttackSeverity.MEDIUM: 2,
            AttackSeverity.LOW: 1,
        }.get(severity, 0)
