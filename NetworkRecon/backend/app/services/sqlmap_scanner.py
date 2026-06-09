"""
Service SQLMap pour l'exécution de tests d'injection SQL.
Exécute sqlmap en tant que processus asynchrone et parse les résultats.
"""

import asyncio
import json
import logging
import os
import re
import tempfile
from datetime import datetime
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.sqlmap import (
    SqlmapCampaign,
    SqlmapConfig,
    SqlmapDatabase,
    SqlmapResult,
    SqlmapStatus,
    SqlmapTable,
    SqlmapVulnerability,
)

logger = logging.getLogger(__name__)


class SqlmapError(Exception):
    """Erreur lors de l'exécution de SQLMap."""
    pass


class SqlmapScanner:
    """Service d'exécution de SQLMap."""

    # Mapping techniques SQLMap
    TECHNIQUE_MAP = {
        "B": "boolean-based blind",
        "U": "union query-based",
        "E": "error-based",
        "S": "stacked queries",
        "T": "time-based blind",
        "I": "inline query",
    }

    def __init__(self, db: AsyncIOMotorDatabase):
        """Initialise le scanner SQLMap.

        Args:
            db: Instance de base de données Motor asynchrone
        """
        self.db = db
        self._sqlmap_path = self._find_sqlmap()
        logger.info("SqlmapScanner initialisé, sqlmap: %s", self._sqlmap_path)

    def _find_sqlmap(self) -> str:
        """Trouve le chemin de sqlmap."""
        # Vérifier dans PATH
        import shutil
        sqlmap = shutil.which("sqlmap")
        if sqlmap:
            return sqlmap

        # Vérifier les emplacements courants
        paths = [
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap",
            "/opt/sqlmap/sqlmap.py",
            os.path.expanduser("~/sqlmap/sqlmap.py"),
        ]
        for p in paths:
            if os.path.exists(p):
                return p

        # Retourner sqlmap.py par défaut (sera installé dans le Dockerfile)
        return "sqlmap"

    async def verify_authorization(self, target_url: str) -> bool:
        """Vérifie que la cible est autorisée pour les tests SQLMap.

        Args:
            target_url: URL cible à vérifier

        Returns:
            True si autorisé

        Raises:
            SqlmapError: Si non autorisé
        """
        from ipaddress import ip_address
        from urllib.parse import urlparse

        try:
            parsed = urlparse(target_url)
            hostname = parsed.hostname

            if not hostname:
                raise SqlmapError(f"URL invalide: {target_url}")

            # Essayer de résoudre en IP
            try:
                ip = ip_address(hostname)
                # Vérifier que l'IP est dans le réseau autorisé
                if not ip.is_private and not ip.is_loopback:
                    raise SqlmapError(
                        f"Cible non autorisée: {hostname} "
                        "(seules les IPs privées sont autorisées)"
                    )
            except ValueError:
                # Ce n'est pas une IP, c'est un nom d'hôte
                # Autoriser les noms d'hôte internes
                pass

            return True

        except SqlmapError:
            raise
        except Exception as e:
            raise SqlmapError(f"Erreur de vérification d'autorisation: {e}")

    async def run_campaign(self, campaign: SqlmapCampaign) -> SqlmapCampaign:
        """Exécute une campagne SQLMap complète.

        Args:
            campaign: Campagne à exécuter

        Returns:
            Campagne mise à jour avec les résultats
        """
        logger.info("Démarrage de la campagne SQLMap: %s", campaign.name)

        # Mettre à jour le statut
        campaign.status = SqlmapStatus.RUNNING
        await self._update_campaign(campaign)

        try:
            # Vérifier l'autorisation
            await self.verify_authorization(campaign.target_url)

            # Construire la commande sqlmap
            cmd = self._build_command(campaign.config)

            # Exécuter sqlmap
            raw_output, return_code = await self._execute_sqlmap(cmd)

            # Parser les résultats
            result = self._parse_output(campaign.target_url, raw_output)

            # Si des DBs sont trouvées, énumérer les tables
            if result.databases:
                result.databases = await self._enumerate_tables(
                    campaign.config, result.databases
                )

            campaign.results.append(result)

            # Compter les vulnérabilités
            campaign.vulnerabilities_count = sum(
                len(r.vulnerabilities) for r in campaign.results
            )
            campaign.urls_completed = 1

            # Mettre à jour le statut
            if result.vulnerabilities:
                campaign.status = SqlmapStatus.COMPLETED
                logger.info(
                    "Campagne terminée avec %d vulnérabilités",
                    campaign.vulnerabilities_count,
                )
            elif result.error_message:
                campaign.status = SqlmapStatus.FAILED
                campaign.error_message = result.error_message
                logger.error("Campagne échouée: %s", result.error_message)
            else:
                campaign.status = SqlmapStatus.COMPLETED
                logger.info("Campagne terminée, aucune vulnérabilité trouvée")

        except Exception as e:
            campaign.status = SqlmapStatus.FAILED
            campaign.error_message = str(e)
            logger.error("Erreur campagne SQLMap: %s", e)

        campaign.completed_at = datetime.utcnow()
        await self._update_campaign(campaign)

        return campaign

    def _build_command(self, config: SqlmapConfig) -> list[str]:
        """Construit la commande SQLMap à partir de la configuration.

        Args:
            config: Configuration SQLMap

        Returns:
            Liste des arguments de la commande
        """
        cmd = [self._sqlmap_path, "-u", config.target_url]

        # Niveau et risque
        cmd.extend(["--level", str(config.level)])
        cmd.extend(["--risk", str(config.risk)])

        # Techniques
        if config.techniques and config.techniques != "BEUST":
            cmd.extend(["--technique", config.techniques])

        # DBMS
        if config.dbms:
            cmd.extend(["--dbms", config.dbms])

        # Tamper
        if config.tamper:
            cmd.extend(["--tamper", config.tamper])

        # Threads
        if config.threads > 1:
            cmd.extend(["--threads", str(config.threads)])

        # Forms
        if config.forms:
            cmd.append("--forms")

        # Crawl
        if config.depth_crawl > 0:
            cmd.extend(["--crawl", str(config.depth_crawl)])

        # Données POST
        if config.data:
            cmd.extend(["--data", config.data])

        # Cookie
        if config.cookie:
            cmd.extend(["--cookie", config.cookie])

        # User-Agent aléatoire
        if config.random_agent:
            cmd.append("--random-agent")

        # Verbosité
        if config.verbose > 0:
            cmd.extend(["-v", str(config.verbose)])

        # Sortie JSON
        cmd.extend(["--output-dir", "/tmp/sqlmap_output"])

        # Batch mode (pas d'interaction)
        cmd.append("--batch")

        # Purge le cache
        cmd.append("--flush-session")

        logger.info("Commande SQLMap: %s", " ".join(cmd))
        return cmd

    async def _execute_sqlmap(self, cmd: list[str]) -> tuple[str, int]:
        """Exécute la commande SQLMap de manière asynchrone.

        Args:
            cmd: Commande et arguments

        Returns:
            Tuple (sortie brute, code de retour)
        """
        try:
            # Créer le répertoire de sortie
            os.makedirs("/tmp/sqlmap_output", exist_ok=True)

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Timeout de 10 minutes par défaut
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=600
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
                raise SqlmapError("Timeout: SQLMap a dépassé 10 minutes")

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            # Combiner stdout et stderr
            output = stdout_str
            if stderr_str:
                output += "\n\n--- STDERR ---\n" + stderr_str

            return output, process.returncode or 0

        except asyncio.TimeoutError:
            raise SqlmapError("Timeout: SQLMap a dépassé le temps limite")
        except Exception as e:
            raise SqlmapError(f"Erreur d'exécution SQLMap: {e}")

    def _parse_output(self, target_url: str, raw_output: str) -> SqlmapResult:
        """Parse la sortie de SQLMap et extrait les résultats.

        Args:
            target_url: URL testée
            raw_output: Sortie brute de sqlmap

        Returns:
            Résultat parsé
        """
        result = SqlmapResult(target_url=target_url, raw_output=raw_output)

        try:
            # Détecter les vulnérabilités
            vulns = self._parse_vulnerabilities(raw_output)
            result.vulnerabilities = vulns

            if vulns:
                # Prendre la première vulnérabilité comme principale
                first_vuln = vulns[0]
                result.parameter = first_vuln.parameter
                result.injection_type = first_vuln.injection_type
                result.title = first_vuln.title
                result.dbms = first_vuln.dbms

            # Détecter les bases de données
            result.databases = self._parse_databases(raw_output)

            # Détecter le DBMS
            if not result.dbms:
                result.dbms = self._detect_dbms(raw_output)

            # Détecter l'OS
            result.os = self._detect_os(raw_output)

        except Exception as e:
            logger.error("Erreur parsing sortie SQLMap: %s", e)
            result.error_message = f"Erreur de parsing: {e}"

        return result

    def _parse_vulnerabilities(self, output: str) -> list[SqlmapVulnerability]:
        """Parse les vulnérabilités depuis la sortie SQLMap.

        Args:
            output: Sortie brute

        Returns:
            Liste de vulnérabilités
        """
        vulns = []

        # Pattern pour les vulnérabilités détectées
        # Type: Parameter: id (GET)
        # Title: AND boolean-based blind - WHERE or HAVING clause
        # Payload: id=1 AND 1=1
        patterns = [
            # Pattern 1: Tableau de vulnérabilités
            r"Parameter:\s+(.+?)\s+\((\w+)\)\s*\n\s*Type:\s+(.+)",
            # Pattern 2: Format Title
            r"Title:\s+(.+?)\s*\n\s*Payload:\s+(.+)",
        ]

        # Extraire les paramètres vulnérables
        param_pattern = r"Parameter:\s+(.+?)\s+\((\w+)\)"
        title_pattern = r"Title:\s+(.+)"
        payload_pattern = r"Payload:\s+(.+)"

        lines = output.split("\n")
        current_param = None
        current_type = None

        for line in lines:
            line = line.strip()

            # Détecter le paramètre
            param_match = re.search(param_pattern, line)
            if param_match:
                current_param = param_match.group(1)
                current_type = param_match.group(2)
                continue

            # Détecter le titre
            title_match = re.search(title_pattern, line)
            if title_match and current_param:
                title = title_match.group(1)
                vuln = SqlmapVulnerability(
                    parameter=current_param,
                    injection_type=current_type or "Unknown",
                    title=title,
                )
                vulns.append(vuln)
                continue

            # Détecter le payload
            payload_match = re.search(payload_pattern, line)
            if payload_match and vulns:
                vulns[-1].payload = payload_match.group(1)

        # Aussi chercher les patterns "is vulnerable"
        vuln_line_pattern = r"The (?:GET|POST|Cookie|URI) parameter '.+?' is vulnerable"
        for line in lines:
            if re.search(vuln_line_pattern, line, re.IGNORECASE):
                # Extraire le paramètre
                param_match = re.search(r"parameter '(.+?)'", line)
                if param_match:
                    param = param_match.group(1)
                    # Vérifier si déjà ajouté
                    if not any(v.parameter == param for v in vulns):
                        vulns.append(SqlmapVulnerability(
                            parameter=param,
                            injection_type="Unknown",
                            title="SQL Injection detected",
                        ))

        return vulns

    def _parse_databases(self, output: str) -> list[SqlmapDatabase]:
        """Parse les bases de données depuis la sortie SQLMap.

        Args:
            output: Sortie brute

        Returns:
            Liste de bases de données
        """
        databases = []

        # Pattern: available databases [N]:
        db_section_pattern = r"available databases \[\d+\]:"
        db_name_pattern = r"\[\*\]\s+(.+)"

        in_db_section = False
        for line in output.split("\n"):
            line = line.strip()

            if re.search(db_section_pattern, line, re.IGNORECASE):
                in_db_section = True
                continue

            if in_db_section:
                db_match = re.search(db_name_pattern, line)
                if db_match:
                    db_name = db_match.group(1).strip()
                    databases.append(SqlmapDatabase(name=db_name))
                elif line and not line.startswith("[*]"):
                    # Fin de section
                    in_db_section = False

        return databases

    async def _enumerate_tables(
        self, config: SqlmapConfig, databases: list[SqlmapDatabase]
    ) -> list[SqlmapDatabase]:
        """Énumère les tables et colonnes pour chaque base de données trouvée.

        Utilise --dump --start=1 --stop=5 pour récupérer tables, colonnes et échantillon.

        Args:
            config: Configuration SQLMap de base
            databases: Liste des bases de données trouvées

        Returns:
            Liste de bases de données avec tables/colonnes remplies
        """
        for db in databases:
            try:
                logger.info("Énumération tables + colonnes pour DB: %s", db.name)

                # Dump avec limites pour récupérer structure + échantillon
                cmd = [
                    self._sqlmap_path,
                    "-u", config.target_url,
                    "-D", db.name,
                    "--dump",
                    "--start", "1",
                    "--stop", "5",
                    "--batch",
                    "--flush-session",
                ]

                if config.random_agent:
                    cmd.append("--random-agent")

                if config.cookie:
                    cmd.extend(["--cookie", config.cookie])

                if config.data:
                    cmd.extend(["--data", config.data])

                output, _ = await self._execute_sqlmap(cmd)
                tables = self._parse_tables_with_columns(output)

                if not tables:
                    # Retry sans flush
                    cmd_no_flush = [c for c in cmd if c != "--flush-session"]
                    output, _ = await self._execute_sqlmap(cmd_no_flush)
                    tables = self._parse_tables_with_columns(output)

                db.tables = tables
                db.tables_count = len(tables)
                logger.info("DB %s: %d tables trouvées", db.name, len(tables))

            except Exception as e:
                logger.error("Erreur énumération tables pour %s: %s", db.name, e)

        return databases

    def _parse_tables_with_columns(self, output: str) -> list[SqlmapTable]:
        """Parse les tables, colonnes et données depuis la sortie sqlmap --dump.

        Args:
            output: Sortie brute de sqlmap

        Returns:
            Liste de tables avec colonnes et échantillon
        """
        tables = []
        current_table = None

        lines = output.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Pattern: Database: xxxxx  ou  Table: xxxxx
            table_header_match = re.search(r"Table:\s+(\S+)", line)
            if table_header_match:
                table_name = table_header_match.group(1).strip("`\"'")
                current_table = SqlmapTable(name=table_name)
                tables.append(current_table)
                i += 1
                continue

            # Pattern: [N columns]  (en-tête du dump)
            col_header_match = re.search(r"\[(\d+)\s+columns?\]", line)
            if col_header_match and current_table:
                # Lignes suivantes = colonnes
                i += 1
                while i < len(lines):
                    col_line = lines[i].strip()
                    # Colonnes entre +--- et |---|
                    if col_line.startswith("+---") or col_line.startswith("|"):
                        if col_line.startswith("|"):
                            cols = [c.strip() for c in col_line.split("|")[1:-1] if c.strip()]
                            for c in cols:
                                if c and c not in current_table.columns and not c.startswith("---"):
                                    current_table.columns.append(c)
                        i += 1
                    elif col_line.startswith("[*]"):
                        # Début des données
                        i += 1
                        break
                    else:
                        break
                continue

            # Pattern: [N rows] (fin de dump d'une table)
            row_count_match = re.search(r"\[(\d+)\s+rows?\]", line)
            if row_count_match and current_table:
                current_table.rows_count = int(row_count_match.group(1))
                i += 1
                continue

            # Pattern lignes de données (entre | ... |)
            if line.startswith("|") and current_table and current_table.columns:
                data = {}
                cells = [c.strip() for c in line.split("|")[1:-1]]
                for idx, col in enumerate(current_table.columns):
                    if idx < len(cells):
                        data[col] = cells[idx]
                if data and any(v.strip() for v in data.values() if isinstance(v, str)):
                    current_table.sample_data.append(data)
                i += 1
                continue

            # Pattern [N entries] fin de dump
            entries_match = re.search(r"\[(\d+)\s+entr", line)
            if entries_match and current_table:
                current_table.rows_count = int(entries_match.group(1))
                i += 1
                continue

            i += 1

        return tables

    def _detect_dbms(self, output: str) -> Optional[str]:
        """Détecte le DBMS depuis la sortie SQLMap.

        Args:
            output: Sortie brute

        Returns:
            Nom du DBMS ou None
        """
        dbms_patterns = {
            "MySQL": r"MySQL",
            "PostgreSQL": r"PostgreSQL|PostgreSQL|Postgres",
            "Microsoft SQL Server": r"Microsoft SQL Server|MS SQL Server|MSSQL",
            "Oracle": r"Oracle",
            "SQLite": r"SQLite",
            "MariaDB": r"MariaDB",
            "MongoDB": r"MongoDB",
        }

        for dbms, pattern in dbms_patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                return dbms

        return None

    def _detect_os(self, output: str) -> Optional[str]:
        """Détecte l'OS depuis la sortie SQLMap.

        Args:
            output: Sortie brute

        Returns:
            Nom de l'OS ou None
        """
        os_patterns = {
            "Linux": r"Linux|Ubuntu|Debian|CentOS|Fedora|RHEL",
            "Windows": r"Windows|Microsoft|Win32|Win64",
            "macOS": r"macOS|Mac OS X|Darwin",
        }

        for os_name, pattern in os_patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                return os_name

        return None

    async def _update_campaign(self, campaign: SqlmapCampaign) -> None:
        """Met à jour une campagne dans MongoDB.

        Args:
            campaign: Campagne à mettre à jour
        """
        doc = campaign.model_dump(by_alias=True)
        if campaign.id:
            await self.db.sqlmap_campaigns.update_one(
                {"_id": campaign.id},
                {"$set": doc},
                upsert=True,
            )
        else:
            result = await self.db.sqlmap_campaigns.insert_one(doc)
            campaign.id = str(result.inserted_id)

    async def get_campaign(self, campaign_id: str) -> Optional[SqlmapCampaign]:
        """Récupère une campagne par son ID.

        Args:
            campaign_id: ID de la campagne

        Returns:
            Campagne ou None
        """
        doc = await self.db.sqlmap_campaigns.find_one({"_id": campaign_id})
        if doc:
            doc["_id"] = str(doc["_id"])
            return SqlmapCampaign(**doc)
        return None

    async def list_campaigns(self, limit: int = 50) -> list[SqlmapCampaign]:
        """Liste les campagnes SQLMap.

        Args:
            limit: Nombre maximum de campagnes

        Returns:
            Liste de campagnes
        """
        cursor = self.db.sqlmap_campaigns.find().sort("created_at", -1).limit(limit)
        campaigns = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            campaigns.append(SqlmapCampaign(**doc))
        return campaigns

    async def delete_campaign(self, campaign_id: str) -> bool:
        """Supprime une campagne SQLMap.

        Args:
            campaign_id: ID de la campagne

        Returns:
            True si supprimée
        """
        result = await self.db.sqlmap_campaigns.delete_one({"_id": campaign_id})
        return result.deleted_count > 0
