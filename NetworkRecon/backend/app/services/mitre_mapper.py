"""Service de mapping MITRE ATT&CK pour NetworkRecon.

Ce module fournit un mapper statique et dynamique entre les services réseau
détectés, les CVE identifiées et les techniques du framework MITRE ATT&CK.
Il inclut :
- Une base de mapping exhaustive service → techniques MITRE
- Un mapper CVE → techniques MITRE via l'API OTX (AlienVault)
- La construction de parcours d'attaque (attack path)
- L'export STIX 2.1
- Le stockage des mappings dans MongoDB
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

import aiohttp
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.mitre import MitreMapping, ServiceToMitre
from app.models.vulnerability import CVE, Severity
from app.utils.database import get_database

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tactiques MITRE ATT&CK (Enterprise, v14)
# ---------------------------------------------------------------------------
MITRE_TACTICS: list[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# URL de base pour les liens MITRE ATT&CK
_MITRE_BASE_URL = "https://attack.mitre.org/techniques"

# URL de l'API OTX pour les mappings CVE → ATT&CK (gratuite)
_OTX_API_URL = "https://otx.alienvault.com/api/v1/pulses"


def _technique_url(technique_id: str) -> str:
    """Construit l'URL de documentation MITRE pour une technique."""
    return f"{_MITRE_BASE_URL}/{technique_id}/"


# ---------------------------------------------------------------------------
# Base de mapping statique : service → techniques MITRE ATT&CK
# ---------------------------------------------------------------------------
# Chaque entrée est un dict avec les clés :
#   technique_id, technique_name, tactic, description
# On stocke aussi un "keywords" utilisé pour le matching dynamique.

_SERVICE_MITRE_DB: dict[str, list[dict[str, str]]] = {
    # ── SSH (port 22) ────────────────────────────────────────────────────
    "ssh": [
        {
            "technique_id": "T1021.004",
            "technique_name": "Remote Services: SSH",
            "tactic": "Lateral Movement",
            "description": (
                "Utilisation du protocole SSH pour se déplacer latéralement "
                "vers d'autres systèmes du réseau."
            ),
        },
        {
            "technique_id": "T1562.001",
            "technique_name": "Impair Defenses: Disable or Modify Tools",
            "tactic": "Defense Evasion",
            "description": (
                "Désactivation ou modification d'outils de sécurité via SSH "
                "(iptables, SELinux, agent EDR)."
            ),
        },
        {
            "technique_id": "T1552.004",
            "technique_name": "Unsecured Credentials: Private Keys",
            "tactic": "Credential Access",
            "description": (
                "Récupération de clés privées SSH exposées ou mal protégées "
                "sur le système cible."
            ),
        },
        {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic": "Initial Access",
            "description": (
                "Utilisation de comptes SSH légitimes pour l'accès initial "
                "au système."
            ),
        },
    ],
    # ── FTP (port 21) ────────────────────────────────────────────────────
    "ftp": [
        {
            "technique_id": "T1021.002",
            "technique_name": "Remote Services: SMB/Windows Admin Shares",
            "tactic": "Lateral Movement",
            "description": (
                "Utilisation de FTP pour transmettre des payloads ou "
                "des outils vers des systèmes distants."
            ),
        },
        {
            "technique_id": "T1133",
            "technique_name": "External Remote Services",
            "tactic": "Initial Access",
            "description": (
                "Accès initial via un service FTP exposé sur Internet, "
                "souvent avec des identifiants par défaut."
            ),
        },
        {
            "technique_id": "T1083",
            "technique_name": "File and Directory Discovery",
            "tactic": "Discovery",
            "description": (
                "Exploration de l'arborescence de fichiers via FTP "
                "pour découvrir des données sensibles."
            ),
        },
    ],
    # ── SMB (port 445) ───────────────────────────────────────────────────
    "smb": [
        {
            "technique_id": "T1021.002",
            "technique_name": "Remote Services: SMB/Windows Admin Shares",
            "tactic": "Lateral Movement",
            "description": (
                "Utilisation de SMB pour se déplacer latéralement via les "
                "partages réseau et les shares administratifs Windows."
            ),
        },
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "description": (
                "Attaques par force brute contre les partages SMB "
                "pour obtenir des identifiants valides."
            ),
        },
        {
            "technique_id": "T1572",
            "technique_name": "Protocol Tunneling",
            "tactic": "Command and Control",
            "description": (
                "Tunneling de protocoles via SMB pour contourner les "
                "contrôles de sécurité réseau."
            ),
        },
        {
            "technique_id": "T1110.001",
            "technique_name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
            "description": (
                "Devination de mots de passe sur les partages SMB "
                "avec des dictionnaires de mots de passe courants."
            ),
        },
    ],
    # ── HTTP (ports 80/443) ──────────────────────────────────────────────
    "http": [
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": (
                "Exploitation de vulnérabilités dans une application web "
                "exposée publiquement (RCE, SQLi, XSS, etc.)."
            ),
        },
        {
            "technique_id": "T1133",
            "technique_name": "External Remote Services",
            "tactic": "Initial Access",
            "description": (
                "Accès initial via des services HTTP exposés "
                "(panneaux d'administration, API)."
            ),
        },
        {
            "technique_id": "T1071.001",
            "technique_name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "description": (
                "Utilisation de HTTP/HTTPS comme protocole de "
                "commande et contrôle (C2) pour contourner la détection."
            ),
        },
        {
            "technique_id": "T1059.007",
            "technique_name": "Command and Scripting Interpreter: JavaScript",
            "tactic": "Execution",
            "description": (
                "Exécution de code JavaScript malveillant via des "
                "injections dans les pages web."
            ),
        },
        {
            "technique_id": "T1053.003",
            "technique_name": "Scheduled Task/Job: Cron",
            "tactic": "Execution",
            "description": (
                "Planification de tâches cron via des CGI ou des "
                "interfaces d'administration web."
            ),
        },
    ],
    # ── HTTPS ─────────────────────────────────────────────────────────────
    "https": [
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": (
                "Exploitation de vulnérabilités dans une application web "
                "exposée publiquement via HTTPS."
            ),
        },
        {
            "technique_id": "T1071.001",
            "technique_name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "description": (
                "Utilisation du protocole HTTPS pour le trafic C2 "
                "afin de chiffrer les communications."
            ),
        },
    ],
    # ── MySQL (port 3306) ────────────────────────────────────────────────
    "mysql": [
        {
            "technique_id": "T1021.004",
            "technique_name": "Remote Services: SSH",
            "tactic": "Lateral Movement",
            "description": (
                "Connexion distante à MySQL pour exécuter des commandes "
                "ou extraire des données."
            ),
        },
        {
            "technique_id": "T1110.001",
            "technique_name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
            "description": (
                "Attaques de devination de mots de passe sur MySQL "
                "(root, admin, comptes par défaut)."
            ),
        },
        {
            "technique_id": "T1505.003",
            "technique_name": "Server Software Component: Web Shell",
            "tactic": "Persistence",
            "description": (
                "Installation de web shells via des fonctions MySQL "
                "(SELECT INTO OUTFILE, UDF)."
            ),
        },
    ],
    # ── PostgreSQL (port 5432) ───────────────────────────────────────────
    "postgresql": [
        {
            "technique_id": "T1021.004",
            "technique_name": "Remote Services: SSH",
            "tactic": "Lateral Movement",
            "description": (
                "Connexion distante à PostgreSQL pour exécuter des "
                "requêtes ou extraire des données."
            ),
        },
        {
            "technique_id": "T1110.001",
            "technique_name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
            "description": (
                "Attaques de devination de mots de passe sur PostgreSQL "
                "(postgres, user par défaut)."
            ),
        },
        {
            "technique_id": "T1059.006",
            "technique_name": "Command and Scripting Interpreter: Python",
            "tactic": "Execution",
            "description": (
                "Exécution de code Python via les extensions PostgreSQL "
                "(plpythonu) pour l'exécution de commandes système."
            ),
        },
    ],
    # ── RDP (port 3389) ──────────────────────────────────────────────────
    "rdp": [
        {
            "technique_id": "T1021.001",
            "technique_name": "Remote Services: Remote Desktop Protocol",
            "tactic": "Lateral Movement",
            "description": (
                "Utilisation de RDP pour se déplacer latéralement "
                "vers des systèmes Windows."
            ),
        },
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "description": (
                "Attaques par force brute sur les sessions RDP "
                "pour obtenir des identifiants valides."
            ),
        },
        {
            "technique_id": "T1563.002",
            "technique_name": "Remote Service Stop: Service Stop",
            "tactic": "Impact",
            "description": (
                "Arrêt des services de sécurité via RDP pour "
                "faciliter l'exécution d'attaques."
            ),
        },
        {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic": "Initial Access",
            "description": (
                "Utilisation de comptes légitimes via RDP pour "
                "l'accès initial au système."
            ),
        },
    ],
    # ── Telnet (port 23) ─────────────────────────────────────────────────
    "telnet": [
        {
            "technique_id": "T1021.002",
            "technique_name": "Remote Services: SMB/Windows Admin Shares",
            "tactic": "Lateral Movement",
            "description": (
                "Utilisation de Telnet pour des connexions distantes "
                "non chiffrées vers des équipements réseau."
            ),
        },
        {
            "technique_id": "T1552.001",
            "technique_name": "Unsecured Credentials: Credentials In Files",
            "tactic": "Credential Access",
            "description": (
                "Interception de credentials Telnet en clair via "
                "l'écoute réseau (sniffing)."
            ),
        },
        {
            "technique_id": "T1040",
            "technique_name": "Network Sniffing",
            "tactic": "Credential Access",
            "description": (
                "Capture de trafic Telnet non chiffré pour extraire "
                "les identifiants de connexion."
            ),
        },
    ],
    # ── SNMP (port 161) ──────────────────────────────────────────────────
    "snmp": [
        {
            "technique_id": "T1040",
            "technique_name": "Network Sniffing",
            "tactic": "Credential Access",
            "description": (
                "Capture du trafic SNMP pour extraire les communautés "
                "et les informations de configuration."
            ),
        },
        {
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
            "description": (
                "Exfiltration de données via le protocole SNMP "
                "(GET/SET sur des OID sensibles)."
            ),
        },
        {
            "technique_id": "T1082",
            "technique_name": "System Information Discovery",
            "tactic": "Discovery",
            "description": (
                "Collecte d'informations système via SNMP "
                "(sysDescr, sysName, hrSystem)."
            ),
        },
    ],
    # ── DNS (port 53) ────────────────────────────────────────────────────
    "dns": [
        {
            "technique_id": "T1071.004",
            "technique_name": "Application Layer Protocol: DNS",
            "tactic": "Command and Control",
            "description": (
                "Utilisation du protocole DNS comme canal C2 "
                "(DNS tunneling, DGA)."
            ),
        },
        {
            "technique_id": "T1568",
            "technique_name": "Dynamic Resolution",
            "tactic": "Command and Control",
            "description": (
                "Utilisation de la résolution dynamique (fast-flux, "
                "DGA) pour les communications C2."
            ),
        },
        {
            "technique_id": "T1071.004",
            "technique_name": "Application Layer Protocol: DNS",
            "tactic": "Exfiltration",
            "description": (
                "Exfiltration de données via des requêtes DNS "
                "encodées (DNS exfiltration)."
            ),
        },
    ],
    # ── LDAP (port 389) ──────────────────────────────────────────────────
    "ldap": [
        {
            "technique_id": "T1087.002",
            "technique_name": "Account Discovery: Domain Account",
            "tactic": "Discovery",
            "description": (
                "Découverte des comptes de domaine via des requêtes "
                "LDAP anonymes ou authentifiées."
            ),
        },
        {
            "technique_id": "T1558",
            "technique_name": "Steal or Forge Kerberos Tickets",
            "tactic": "Credential Access",
            "description": (
                "Vol de tickets Kerberos (AS-REP, TGS) via des "
                "requêtes LDAP/Kerberos."
            ),
        },
        {
            "technique_id": "T1018",
            "technique_name": "Remote System Discovery",
            "tactic": "Discovery",
            "description": (
                "Découverte de systèmes distants via LDAP "
                "(recherche d'objetscomputer)."
            ),
        },
        {
            "technique_id": "T1087.004",
            "technique_name": "Account Discovery: Cloud Account",
            "tactic": "Discovery",
            "description": (
                "Découverte de comptes cloud via LDAP "
                "(Azure AD, Active Directory)."
            ),
        },
    ],
    # ── Redis (port 6379) ────────────────────────────────────────────────
    "redis": [
        {
            "technique_id": "T1098",
            "technique_name": "Account Manipulation",
            "tactic": "Persistence",
            "description": (
                "Manipulation des comptes Redis (ajout de clés SSH, "
                "modification de la configuration) pour la persistance."
            ),
        },
        {
            "technique_id": "T1133",
            "technique_name": "External Remote Services",
            "tactic": "Initial Access",
            "description": (
                "Accès initial via Redis exposé sans authentification, "
                "souvent sur le port 6379."
            ),
        },
        {
            "technique_id": "T1059.006",
            "technique_name": "Command and Scripting Interpreter: Python",
            "tactic": "Execution",
            "description": (
                "Exécution de code Python via Redis (MODULE LOAD, "
                " EVAL) pour l'exécution de commandes."
            ),
        },
    ],
    # ── SMTP (port 25) ───────────────────────────────────────────────────
    "smtp": [
        {
            "technique_id": "T1048.002",
            "technique_name": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
            "tactic": "Exfiltration",
            "description": (
                "Exfiltration de données via SMTP avec chiffrement "
                "(STARTTLS,附件加密)."
            ),
        },
        {
            "technique_id": "T1566.001",
            "technique_name": "Phishing: Spearphishing Attachment",
            "tactic": "Initial Access",
            "description": (
                "Envoi de phishing avec pièces jointes malveillantes "
                "via un serveur SMTP compromis."
            ),
        },
        {
            "technique_id": "T1048.001",
            "technique_name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
            "tactic": "Exfiltration",
            "description": (
                "Exfiltration de données via SMTP avec chiffrement "
                "symétrique."
            ),
        },
    ],
    # ── Microsoft SQL Server (port 1433) ─────────────────────────────────
    "mssql": [
        {
            "technique_id": "T1505.002",
            "technique_name": "Server Software Component: Transport Agent",
            "tactic": "Persistence",
            "description": (
                "Installation de transport agents SQL Server "
                "pour la persistance et l'exécution de code."
            ),
        },
        {
            "technique_id": "T1110.001",
            "technique_name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
            "description": (
                "Attaques de devination de mots de passe sur SQL Server "
                "(sa, comptes administrateur)."
            ),
        },
        {
            "technique_id": "T1059.005",
            "technique_name": "Command and Scripting Interpreter: Visual Basic",
            "tactic": "Execution",
            "description": (
                "Exécution de code VBScript via xp_cmdshell "
                "et les procédures stockées."
            ),
        },
    ],
    # ── Oracle Database (port 1521) ──────────────────────────────────────
    "oracle": [
        {
            "technique_id": "T1110.001",
            "technique_name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
            "description": (
                "Attaques de devination de mots de passe sur Oracle DB "
                "(SYS, SYSTEM, comptes par défaut)."
            ),
        },
        {
            "technique_id": "T1053.003",
            "technique_name": "Scheduled Task/Job: Cron",
            "tactic": "Execution",
            "description": (
                "Planification de jobs Oracle DB pour l'exécution "
                "de code système."
            ),
        },
    ],
    # ── VNC (port 5900) ──────────────────────────────────────────────────
    "vnc": [
        {
            "technique_id": "T1021.005",
            "technique_name": "Remote Services: VNC",
            "tactic": "Lateral Movement",
            "description": (
                "Utilisation de VNC pour se déplacer latéralement "
                "vers des systèmes graphiques distants."
            ),
        },
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "description": (
                "Attaques par force brute sur les sessions VNC "
                "pour obtenir l'accès au bureau distant."
            ),
        },
    ],
    # ── Memcached (port 11211) ───────────────────────────────────────────
    "memcached": [
        {
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
            "description": (
                "Amplification et exfiltration de données via "
                "Memcached (attaque d'amplification UDP)."
            ),
        },
        {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "tactic": "Impact",
            "description": (
                "Attaque DDoS par amplification via Memcached "
                "avec des paquets UDP volumineux."
            ),
        },
    ],
    # ── NFS (port 2049) ──────────────────────────────────────────────────
    "nfs": [
        {
            "technique_id": "T1083",
            "technique_name": "File and Directory Discovery",
            "tactic": "Discovery",
            "description": (
                "Exploration des partages NFS montés pour découvrir "
                "des données sensibles."
            ),
        },
        {
            "technique_id": "T1039",
            "technique_name": "Data from Network Shared Drive",
            "tactic": "Collection",
            "description": (
                "Collecte de données depuis les partages NFS "
                "pour l'exfiltration."
            ),
        },
    ],
    # ── SIP (port 5060/5061) ────────────────────────────────────────────
    "sip": [
        {
            "technique_id": "T1040",
            "technique_name": "Network Sniffing",
            "tactic": "Credential Access",
            "description": (
                "Capture du trafic SIP non chiffré pour extraire "
                "les identifiants et les flux audio."
            ),
        },
        {
            "technique_id": "T1071.001",
            "technique_name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "description": (
                "Utilisation du protocole SIP pour des communications "
                "C2 via les réseaux VoIP."
            ),
        },
    ],
    # ── NTP (port 123) ───────────────────────────────────────────────────
    "ntp": [
        {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "tactic": "Impact",
            "description": (
                "Attaque DDoS par amplification NTP avec les "
                "requêtes monlist."
            ),
        },
        {
            "technique_id": "T1040",
            "technique_name": "Network Sniffing",
            "tactic": "Credential Access",
            "description": (
                "Capture du trafic NTP pour l'énumération "
                "des systèmes réseau."
            ),
        },
    ],
    # ── Kerberos (port 88) ───────────────────────────────────────────────
    "kerberos": [
        {
            "technique_id": "T1558.001",
            "technique_name": "Steal or Forge Kerberos Tickets: Golden Ticket",
            "tactic": "Credential Access",
            "description": (
                "Forge de tickets Golden Ticket pour l'accès "
                "persistant au domaine."
            ),
        },
        {
            "technique_id": "T1558.003",
            "technique_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
            "tactic": "Credential Access",
            "description": (
                "Attaque Kerberoasting pour extraire les mots de passe "
                "des services Kerberos (SPN)."
            ),
        },
    ],
    # ── IPP (port 631) ───────────────────────────────────────────────────
    "ipp": [
        {
            "technique_id": "T1059.007",
            "technique_name": "Command and Scripting Interpreter: JavaScript",
            "tactic": "Execution",
            "description": (
                "Exécution de code via des failles dans les "
                "pilotes d'impression (PrintNightmare)."
            ),
        },
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": (
                "Exploitation de vulnérabilités dans les services "
                "d'impression exposés (CUPS, IPP)."
            ),
        },
    ],
    # ── Docker (port 2375/2376) ──────────────────────────────────────────
    "docker": [
        {
            "technique_id": "T1610",
            "technique_name": "Deploy Container",
            "tactic": "Execution",
            "description": (
                "Déploiement de conteneurs malveillants via l'API "
                "Docker exposée."
            ),
        },
        {
            "technique_id": "T1611",
            "technique_name": "Escape to Host",
            "tactic": "Privilege Escalation",
            "description": (
                "Évasion de conteneur pour obtenir l'accès "
                "à l'hôte hôte."
            ),
        },
    ],
    # ── Kubernetes API (port 6443) ───────────────────────────────────────
    "kubernetes": [
        {
            "technique_id": "T1610",
            "technique_name": "Deploy Container",
            "tactic": "Execution",
            "description": (
                "Déploiement de conteneurs malveillants via "
                "l'API Kubernetes."
            ),
        },
        {
            "technique_id": "T1613",
            "technique_name": "Container and Resource Discovery",
            "tactic": "Discovery",
            "description": (
                "Découverte des conteneurs et ressources "
                "Kubernetes via l'API exposée."
            ),
        },
    ],
    # ── ZooKeeper (port 2181) ────────────────────────────────────────────
    "zookeeper": [
        {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "tactic": "Impact",
            "description": (
                "Attaque DDoS via ZooKeeper avec des requêtes "
                "四字未授权."
            ),
        },
        {
            "technique_id": "T1082",
            "technique_name": "System Information Discovery",
            "tactic": "Discovery",
            "description": (
                "Énumération des données ZooKeeper exposées "
                "pour la découverte d'informations."
            ),
        },
    ],
    # ── CouchDB (port 5984) ──────────────────────────────────────────────
    "couchdb": [
        {
            "technique_id": "T1133",
            "technique_name": "External Remote Services",
            "tactic": "Initial Access",
            "description": (
                "Accès initial via CouchDB exposé sans "
                "authentification."
            ),
        },
        {
            "technique_id": "T1083",
            "technique_name": "File and Directory Discovery",
            "tactic": "Discovery",
            "description": (
                "Exploration des bases CouchDB pour découvrir "
                "des données sensibles."
            ),
        },
    ],
    # ── Elasticsearch (port 9200) ────────────────────────────────────────
    "elasticsearch": [
        {
            "technique_id": "T1530",
            "technique_name": "Data from Cloud Storage",
            "tactic": "Collection",
            "description": (
                "Collecte de données depuis Elasticsearch "
                "exposé sans authentification."
            ),
        },
        {
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
            "description": (
                "Exfiltration de données via l'API REST "
                "d'Elasticsearch."
            ),
        },
    ],
    # ── MongoDB (port 27017) ─────────────────────────────────────────────
    "mongodb": [
        {
            "technique_id": "T1005",
            "technique_name": "Data from Local System",
            "tactic": "Collection",
            "description": (
                "Collecte de données depuis MongoDB exposé "
                "sans authentification."
            ),
        },
        {
            "technique_id": "T1133",
            "technique_name": "External Remote Services",
            "tactic": "Initial Access",
            "description": (
                "Accès initial via MongoDB exposé sans "
                "authentification."
            ),
        },
    ],
    # ── Tomcat (port 8080) ───────────────────────────────────────────────
    "tomcat": [
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": (
                "Exploitation de vulnérabilités dans Apache Tomcat "
                "(manager, host-manager)."
            ),
        },
        {
            "technique_id": "T1505.003",
            "technique_name": "Server Software Component: Web Shell",
            "tactic": "Persistence",
            "description": (
                "Déploiement de web shells WAR sur Tomcat "
                "via le manager."
            ),
        },
    ],
    # ── Jenkins (port 8080/8443) ─────────────────────────────────────────
    "jenkins": [
        {
            "technique_id": "T1053.003",
            "technique_name": "Scheduled Task/Job: Cron",
            "tactic": "Execution",
            "description": (
                "Exécution de scripts via les jobs Jenkins "
                "pour compromettre le système."
            ),
        },
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": (
                "Exploitation de Jenkins exposé avec des "
                "identifiants par défaut (admin/admin)."
            ),
        },
    ],
    # ── RabbitMQ (port 15672) ────────────────────────────────────────────
    "rabbitmq": [
        {
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
            "description": (
                "Exfiltration de données via RabbitMQ management "
                "API exposée."
            ),
        },
        {
            "technique_id": "T1133",
            "technique_name": "External Remote Services",
            "tactic": "Initial Access",
            "description": (
                "Accès initial via RabbitMQ management "
                "avec identifiants par défaut."
            ),
        },
    ],
}

# ---------------------------------------------------------------------------
# Mapping CVE → techniques MITRE ATT&CK (par mot-clé dans la description)
# Les mots-clés sont associés à des techniques pour le matching automatique.
# ---------------------------------------------------------------------------
_CVE_KEYWORD_TECHNIQUES: list[dict[str, Any]] = [
    {
        "keywords": ["remote code execution", "rce", "command injection"],
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "description": "Exécution de code à distance via l'exploitation de vulnérabilités.",
    },
    {
        "keywords": ["sql injection", "sqli", "sql-injection"],
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploitation d'injection SQL dans une application exposée.",
    },
    {
        "keywords": ["cross-site scripting", "xss", "stored xss", "reflected xss"],
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Compromission via attaque drive-by exploitant des failles XSS.",
    },
    {
        "keywords": ["privilege escalation", "local privilege", "elevation of privilege"],
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Escalade de privilèges via exploitation de vulnérabilités.",
    },
    {
        "keywords": ["authentication bypass", "auth bypass", "bypass authentication"],
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Contournement d'authentification pour accéder à des comptes valides.",
    },
    {
        "keywords": ["denial of service", "dos", "ddos", "crash", "overflow", "buffer overflow"],
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Attaque par déni de service exploitant des vulnérabilités.",
    },
    {
        "keywords": ["information disclosure", "information leak", "info leak"],
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "Collection",
        "description": "Collecte de données système exposées par la vulnérabilité.",
    },
    {
        "keywords": ["path traversal", "directory traversal", "lfi", "local file inclusion"],
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Accès non autorisé à des fichiers via traversée de répertoires.",
    },
    {
        "keywords": ["remote file inclusion", "rfi"],
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Exécution de code distant via inclusion de fichiers.",
    },
    {
        "keywords": ["deserialization", "object injection", "insecure deserialization"],
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Exécution de code via désérialisation non sécurisée.",
    },
    {
        "keywords": ["ssrf", "server-side request forgery"],
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploitation d'SSRF pour accéder à des ressources internes.",
    },
    {
        "keywords": ["xxe", "xml external entity", "xml injection"],
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Exécution de code via XXE injection.",
    },
    {
        "keywords": ["memory corruption", "use-after-free", "uaf", "heap overflow", "stack overflow"],
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "description": "Exécution de code via corruption mémoire.",
    },
    {
        "keywords": ["default credentials", "hardcoded credentials", "weak passwords"],
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Accès via identifiants par défaut ou faibles.",
    },
    {
        "keywords": ["directory listing", "directory browsing"],
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Découverte de fichiers via listage de répertoires exposé.",
    },
    {
        "keywords": ["open redirect", "url redirect"],
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Redirection malveillante exploitant une faille d'open redirect.",
    },
    {
        "keywords": ["code injection", "code injection vulnerability"],
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Exécution de code via injection de code.",
    },
    {
        "keywords": ["file upload", "unrestricted file upload"],
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Exécution de code via upload de fichiers non restreint.",
    },
    {
        "keywords": ["buffer over-read", "out-of-bounds read"],
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "Collection",
        "description": "Lecture de mémoire non autorisée via over-read.",
    },
    {
        "keywords": ["elevation", "escalation", "root", "admin", "system"],
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Escalade de privilèges via exploitation.",
    },
    {
        "keywords": ["cross-site request forgery", "csrf"],
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Attaque CSRF exploitant une session utilisateur active.",
    },
    {
        "keywords": ["password leak", "credential leak", "password exposure"],
        "technique_id": "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
        "description": "Exposition de credentials dans des fichiers.",
    },
    {
        "keywords": ["log4j", "log4shell", "jndi injection", "jndi"],
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploitation de Log4Shell (Log4j) dans des applications Java.",
    },
    {
        "keywords": ["spring4shell", "spring", "spel injection"],
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploitation de Spring4Shell dans les applications Spring.",
    },
    {
        "keywords": ["openssl", "heartbleed", "ssl", "tls"],
        "technique_id": "T1040",
        "technique_name": "Network Sniffing",
        "tactic": "Credential Access",
        "description": "Capture de données via vulnérabilités SSL/TLS.",
    },
]


class MitreMapper:
    """Mapper entre services réseau, CVE et techniques MITRE ATT&CK.

    Fournit :
    - Mapping statique service → techniques
    - Mapping dynamique CVE → techniques via OTX API
    - Construction de parcours d'attaque
    - Export STIX 2.1
    - Stockage MongoDB
    """

    def __init__(self) -> None:
        """Initialise le mapper avec la base de mapping statique."""
        self._service_db: dict[str, list[dict[str, str]]] = _SERVICE_MITRE_DB
        self._cve_keywords: list[dict[str, Any]] = _CVE_KEYWORD_TECHNIQUES
        self._otx_cache: dict[str, list[dict[str, str]]] = {}

        logger.info(
            "MitreMapper initialisé avec %d services et %d patterns CVE",
            len(self._service_db),
            len(self._cve_keywords),
        )

    # ------------------------------------------------------------------
    # Mapping service → MITRE
    # ------------------------------------------------------------------
    async def map_service_to_mitre(
        self,
        service: str,
        version: str = "",
        vulnerabilities: list[CVE] | None = None,
    ) -> list[MitreMapping]:
        """Mappe un service réseau vers les techniques MITRE ATT&CK.

        Args:
            service: Nom du service (ex: ``ssh``, ``http``, ``mysql``).
            version: Version optionnelle du service.
            vulnerabilities: Liste de CVE associées au service.

        Returns:
            Liste de ``MitreMapping`` correspondant au service.
        """
        service_lower = service.lower().strip()
        logger.info(
            "Mapping service '%s' (version=%s) vers MITRE ATT&CK",
            service_lower,
            version,
        )

        mappings: list[MitreMapping] = []

        # Mapping statique
        entries = self._service_db.get(service_lower, [])
        if entries:
            for entry in entries:
                url = _technique_url(entry["technique_id"])
                mapping = MitreMapping(
                    technique_id=entry["technique_id"],
                    technique_name=entry["technique_name"],
                    tactic=entry["tactic"],
                    description=entry["description"],
                    url=url,
                )
                mappings.append(mapping)
            logger.info(
                "  → %d techniques statiques trouvées pour '%s'",
                len(entries),
                service_lower,
            )
        else:
            logger.warning(
                "  → Aucun mapping statique pour le service '%s'",
                service_lower,
            )

        # Mapping dynamique via les CVE du service
        if vulnerabilities:
            for cve in vulnerabilities:
                cve_mappings = await self.map_vulnerability_to_mitre(cve)
                for m in cve_mappings:
                    if m.technique_id not in {x.technique_id for x in mappings}:
                        mappings.append(m)
            logger.info(
                "  → %d techniques ajoutées via %d CVE",
                len(mappings) - len(entries),
                len(vulnerabilities),
            )

        logger.info(
            "Total mapping pour '%s': %d techniques MITRE",
            service_lower,
            len(mappings),
        )
        return mappings

    # ------------------------------------------------------------------
    # Mapping CVE → MITRE (par mots-clés + API OTX)
    # ------------------------------------------------------------------
    async def map_vulnerability_to_mitre(self, cve: CVE) -> list[MitreMapping]:
        """Mappe une CVE vers les techniques MITRE ATT&CK.

        Utilise d'abord le matching local par mots-clés, puis tente
        l'enrichissement via l'API OTX d'AlienVault.

        Args:
            cve: Objet ``CVE`` à mapper.

        Returns:
            Liste de ``MitreMapping`` correspondant à la CVE.
        """
        logger.info(
            "Mapping CVE '%s' (sévérité=%s, score=%.1f) vers MITRE",
            cve.cve_id,
            cve.severity.value,
            cve.cvss_score or 0.0,
        )

        mappings: list[MitreMapping] = []
        seen_ids: set[str] = set()

        # 1. Matching local par mots-clés
        desc_lower = cve.description.lower()
        for pattern in self._cve_keywords:
            for keyword in pattern["keywords"]:
                if keyword in desc_lower:
                    if pattern["technique_id"] not in seen_ids:
                        url = _technique_url(pattern["technique_id"])
                        mapping = MitreMapping(
                            technique_id=pattern["technique_id"],
                            technique_name=pattern["technique_name"],
                            tactic=pattern["tactic"],
                            description=pattern["description"],
                            url=url,
                        )
                        mappings.append(mapping)
                        seen_ids.add(pattern["technique_id"])
                    break  # un seul match par pattern suffit

        logger.info(
            "  → %d techniques trouvées par matching local",
            len(mappings),
        )

        # 2. Enrichissement via l'API OTX (best-effort, non bloquant)
        otx_mappings = await self._fetch_otx_mappings(cve.cve_id)
        for entry in otx_mappings:
            tid = entry.get("technique_id", "")
            if tid and tid not in seen_ids:
                url = _technique_url(tid) if tid.startswith("T") else None
                mapping = MitreMapping(
                    technique_id=tid,
                    technique_name=entry.get("technique_name", tid),
                    tactic=entry.get("tactic", "Unknown"),
                    description=entry.get("description", ""),
                    url=url,
                )
                mappings.append(mapping)
                seen_ids.add(tid)

        if otx_mappings:
            logger.info(
                "  → %d techniques supplémentaires depuis OTX",
                len(otx_mappings),
            )

        logger.info(
            "Total mapping pour '%s': %d techniques MITRE",
            cve.cve_id,
            len(mappings),
        )
        return mappings

    async def _fetch_otx_mappings(self, cve_id: str) -> list[dict[str, str]]:
        """Interroge l'API OTX pour obtenir les techniques ATT&CK d'une CVE.

        Résultats mis en cache pour éviter les appels répétés.

        Args:
            cve_id: Identifiant CVE (ex: ``CVE-2023-1234``).

        Returns:
            Liste de dicts avec ``technique_id``, ``technique_name``,
            ``tactic``, ``description``.
        """
        if cve_id in self._otx_cache:
            return self._otx_cache[cve_id]

        url = f"{_OTX_API_URL}/{cve_id}/general"
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        logger.debug(
                            "  OTX API retourne %d pour %s",
                            resp.status,
                            cve_id,
                        )
                        self._otx_cache[cve_id] = []
                        return []
                    data = await resp.json()

            mappings: list[dict[str, str]] = []
            # OTX fournit les ATT&CK IDs dans les références
            for ref in data.get("references", []):
                link = ref.get("link", "")
                # Extraction d'IDs MITRE depuis les liens
                if "attack.mitre.org" in link:
                    technique_id = link.rstrip("/").split("/")[-1]
                    if technique_id.startswith("T"):
                        mappings.append({
                            "technique_id": technique_id,
                            "technique_name": f"ATT&CK Technique {technique_id}",
                            "tactic": "Unknown",
                            "description": f"Technique MITRE liée à {cve_id} via OTX.",
                        })

            # Aussi depuis les tags ATT&CK
            for tag in data.get("tags", []):
                if tag.upper().startswith("T") and "." in tag:
                    tid = tag.upper().replace(" ", "")
                    if tid.startswith("T") and tid not in {
                        m["technique_id"] for m in mappings
                    }:
                        mappings.append({
                            "technique_id": tid,
                            "technique_name": f"ATT&CK Technique {tid}",
                            "tactic": "Unknown",
                            "description": f"Technique MITRE liée à {cve_id} via OTX.",
                        })

            self._otx_cache[cve_id] = mappings
            return mappings

        except asyncio.TimeoutError:
            logger.debug("  Timeout API OTX pour %s", cve_id)
            self._otx_cache[cve_id] = []
            return []
        except Exception as exc:
            logger.debug(
                "  Erreur API OTX pour %s: %s",
                cve_id,
                exc,
            )
            self._otx_cache[cve_id] = []
            return []

    # ------------------------------------------------------------------
    # Consultation de la base
    # ------------------------------------------------------------------
    def get_techniques_for_tactic(self, tactic: str) -> list[MitreMapping]:
        """Retourne toutes les techniques associées à une tactique donnée.

        Args:
            tactic: Nom exact de la tactique MITRE (ex: ``Initial Access``).

        Returns:
            Liste de ``MitreMapping`` pour cette tactique.
        """
        logger.info("Recherche de techniques pour la tactique '%s'", tactic)
        results: list[MitreMapping] = []
        seen_ids: set[str] = set()

        for service_name, entries in self._service_db.items():
            for entry in entries:
                if entry["tactic"].lower() == tactic.lower():
                    tid = entry["technique_id"]
                    if tid not in seen_ids:
                        url = _technique_url(tid)
                        results.append(MitreMapping(
                            technique_id=tid,
                            technique_name=entry["technique_name"],
                            tactic=entry["tactic"],
                            description=entry["description"],
                            url=url,
                        ))
                        seen_ids.add(tid)

        logger.info(
            "  → %d techniques uniques pour la tactique '%s'",
            len(results),
            tactic,
        )
        return results

    def get_tactics(self) -> list[str]:
        """Retourne la liste complète des tactiques MITRE ATT&CK.

        Returns:
            Liste ordonnée des tactiques.
        """
        return list(MITRE_TACTICS)

    # ------------------------------------------------------------------
    # Récupération depuis l'API MITRE (enrichissement dynamique)
    # ------------------------------------------------------------------
    async def get_attack_technique(self, technique_id: str) -> dict:
        """Récupère les détails d'une technique depuis l'API MITRE.

        Utilise l'API STIX 2.1 de MITRE ATT&CK pour obtenir les
        informations complètes d'une technique.

        Args:
            technique_id: Identifiant de technique (ex: ``T1190``).

        Returns:
            Dict contenant ``id``, ``name``, ``description``,
            ``tactic``, ``url``, ``detection``, ``mitigation``.
        """
        logger.info(
            "Récupération des détails de la technique '%s' depuis MITRE",
            technique_id,
        )

        stix_url = (
            "https://raw.githubusercontent.com/mitre/cti/master/"
            "enterprise-attack/enterprise-attack.json"
        )

        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(stix_url) as resp:
                    if resp.status != 200:
                        logger.warning(
                            "  MITRE STIX retourne %d",
                            resp.status,
                        )
                        return self._fallback_technique(technique_id)
                    data = await resp.json()

            # Recherche de la technique dans le bundle STIX
            for obj in data.get("objects", []):
                if obj.get("type") == "attack-pattern":
                    refs = obj.get("external_references", [])
                    for ref in refs:
                        if ref.get("external_id") == technique_id:
                            # Extraction de la tactique
                            kill_chain = obj.get("kill_chain_phases", [])
                            tactics = [
                                phase["phase_name"]
                                for phase in kill_chain
                                if phase.get("kill_chain_name")
                                == "mitre-attack"
                            ]

                            result = {
                                "id": technique_id,
                                "name": obj.get("name", technique_id),
                                "description": obj.get("description", ""),
                                "tactic": tactics[0] if tactics else "Unknown",
                                "url": _technique_url(technique_id),
                                "detection": obj.get(
                                    "x_mitre_detection", ""
                                ),
                                "mitigation": "",
                            }

                            # Chercher les mitigations
                            for mit in data.get("objects", []):
                                if mit.get("type") == "course-of-action":
                                    mit_refs = mit.get(
                                        "external_references", []
                                    )
                                    for mr in mit_refs:
                                        if mr.get("external_id", "").startswith(
                                            "M"
                                        ):
                                            # Vérifier lien avec technique
                                            if technique_id in str(
                                                mit.get(
                                                    "revoked_by",
                                                    [],
                                                )
                                            ):
                                                result["mitigation"] = mit.get(
                                                    "description", ""
                                                )
                                                break

                            logger.info(
                                "  → Technique '%s': %s",
                                technique_id,
                                result["name"],
                            )
                            return result

            logger.warning(
                "  Technique '%s' non trouvée dans le STIX",
                technique_id,
            )
            return self._fallback_technique(technique_id)

        except asyncio.TimeoutError:
            logger.warning(
                "  Timeout lors de la récupération MITRE pour '%s'",
                technique_id,
            )
            return self._fallback_technique(technique_id)
        except Exception as exc:
            logger.warning(
                "  Erreur lors de la récupération MITRE pour '%s': %s",
                technique_id,
                exc,
            )
            return self._fallback_technique(technique_id)

    def _fallback_technique(self, technique_id: str) -> dict:
        """Retourne un dict minimal quand l'API MITRE est indisponible."""
        # Chercher dans la base locale
        for entries in self._service_db.values():
            for entry in entries:
                if entry["technique_id"] == technique_id:
                    return {
                        "id": technique_id,
                        "name": entry["technique_name"],
                        "description": entry["description"],
                        "tactic": entry["tactic"],
                        "url": _technique_url(technique_id),
                        "detection": "",
                        "mitigation": "",
                    }
        return {
            "id": technique_id,
            "name": technique_id,
            "description": "",
            "tactic": "Unknown",
            "url": _technique_url(technique_id),
            "detection": "",
            "mitigation": "",
        }

    # ------------------------------------------------------------------
    # Construction de parcours d'attaque
    # ------------------------------------------------------------------
    def build_attack_path(self, mappings: list[MitreMapping]) -> dict:
        """Construit un parcours d'attaque (attack path) à partir de mappings.

        Regroupe les techniques par tactique dans l'ordre du kill chain
        MITRE ATT&CK et fournit un scoring basé sur la sévérité.

        Args:
            mappings: Liste de ``MitreMapping`` à organiser.

        Returns:
            Dict contenant ``tactics_chain``, ``total_techniques``,
            ``attack_complexity``, ``highest_risk_technique``.
        """
        logger.info(
            "Construction du parcours d'attaque à partir de %d mappings",
            len(mappings),
        )

        if not mappings:
            return {
                "tactics_chain": [],
                "total_techniques": 0,
                "attack_complexity": "none",
                "highest_risk_technique": None,
            }

        # Ordre du kill chain MITRE ATT&CK
        tactic_order = {t: i for i, t in enumerate(MITRE_TACTICS)}

        # Regrouper par tactique
        tactic_groups: dict[str, list[MitreMapping]] = {}
        for m in mappings:
            tactic_groups.setdefault(m.tactic, []).append(m)

        # Trier par ordre du kill chain
        sorted_tactics = sorted(
            tactic_groups.keys(),
            key=lambda t: tactic_order.get(t, 999),
        )

        # Construire la chaîne
        tactics_chain = []
        for tactic in sorted_tactics:
            techniques = tactic_groups[tactic]
            tactics_chain.append({
                "tactic": tactic,
                "techniques": [
                    {
                        "technique_id": t.technique_id,
                        "technique_name": t.technique_name,
                        "description": t.description,
                        "url": t.url,
                    }
                    for t in techniques
                ],
                "technique_count": len(techniques),
            })

        # Calcul de complexité d'attaque
        total = len(mappings)
        tactic_count = len(tactics_chain)
        if tactic_count >= 5 and total >= 15:
            complexity = "critical"
        elif tactic_count >= 4 and total >= 10:
            complexity = "high"
        elif tactic_count >= 2 and total >= 5:
            complexity = "medium"
        else:
            complexity = "low"

        # Technique la plus risquée (priorité aux Initial Access, Privilege Escalation)
        high_risk_tactics = {
            "Initial Access",
            "Privilege Escalation",
            "Execution",
            "Credential Access",
        }
        highest_risk = None
        for m in mappings:
            if m.tactic in high_risk_tactics:
                highest_risk = {
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic,
                }
                break
        if highest_risk is None and mappings:
            m = mappings[0]
            highest_risk = {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
            }

        result = {
            "tactics_chain": tactics_chain,
            "total_techniques": total,
            "total_tactics": tactic_count,
            "attack_complexity": complexity,
            "highest_risk_technique": highest_risk,
        }

        logger.info(
            "  → Parcours: %d tactiques, %d techniques, complexité=%s",
            tactic_count,
            total,
            complexity,
        )
        return result

    # ------------------------------------------------------------------
    # Stockage MongoDB
    # ------------------------------------------------------------------
    async def store_mapping(
        self,
        scan_id: str,
        host_ip: str,
        mappings: list[MitreMapping],
    ) -> str:
        """Stocke les mappings MITRE dans MongoDB.

        Crée un document ``mitre_mappings`` dans la collection dédiée
        avec les métadonnées du scan et de l'hôte.

        Args:
            scan_id: Identifiant du scan associé.
            host_ip: Adresse IP de l'hôte cible.
            mappings: Liste de ``MitreMapping`` à stocker.

        Returns:
            Identifiant MongoDB du document créé.
        """
        logger.info(
            "Stockage de %d mappings MITRE pour scan=%s, host=%s",
            len(mappings),
            scan_id,
            host_ip,
        )

        db: AsyncIOMotorDatabase = await get_database()

        attack_path = self.build_attack_path(mappings)

        document = {
            "scan_id": scan_id,
            "host_ip": host_ip,
            "mappings": [m.model_dump() for m in mappings],
            "attack_path": attack_path,
            "total_techniques": len(mappings),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        result = await db.mitre_mappings.insert_one(document)
        doc_id = str(result.inserted_id)

        logger.info(
            "  → Document MongoDB créé: id=%s, %d mappings",
            doc_id,
            len(mappings),
        )
        return doc_id

    # ------------------------------------------------------------------
    # Utilitaires
    # ------------------------------------------------------------------
    @staticmethod
    def get_critical_path(mappings: list[MitreMapping]) -> dict:
        """Identifie le chemin d'attaque le plus critique.

        Priorise les tactiques liées à l'accès initial et à l'escalade
        de privilèges.

        Args:
            mappings: Liste de ``MitreMapping``.

        Returns:
            Dict contenant ``critical_techniques``, ``critical_tactics``,
            ``risk_score`` (0-100).
        """
        logger.info("Analyse du chemin critique parmi %d mappings", len(mappings))

        if not mappings:
            return {
                "critical_techniques": [],
                "critical_tactics": [],
                "risk_score": 0,
            }

        # Poids des tactiques (plus élevé = plus critique)
        tactic_weights = {
            "Initial Access": 30,
            "Privilege Escalation": 25,
            "Execution": 20,
            "Credential Access": 18,
            "Lateral Movement": 15,
            "Defense Evasion": 12,
            "Persistence": 14,
            "Discovery": 8,
            "Collection": 10,
            "Command and Control": 16,
            "Exfiltration": 20,
            "Impact": 22,
            "Resource Development": 5,
            "Reconnaissance": 5,
        }

        risk_score = 0
        critical_tactics: set[str] = set()
        critical_techniques: list[dict[str, str]] = []

        for m in mappings:
            weight = tactic_weights.get(m.tactic, 5)
            risk_score += weight
            critical_tactics.add(m.tactic)
            critical_techniques.append({
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "weight": weight,
            })

        # Normaliser le score (max 100)
        risk_score = min(100, risk_score)

        # Trier par poids décroissant
        critical_techniques.sort(key=lambda x: x["weight"], reverse=True)

        result = {
            "critical_techniques": critical_techniques,
            "critical_tactics": sorted(critical_tactics),
            "risk_score": risk_score,
        }

        logger.info(
            "  → Score de risque: %d, %d tactiques critiques",
            risk_score,
            len(critical_tactics),
        )
        return result

    @staticmethod
    def export_to_stix(mappings: list[MitreMapping]) -> dict:
        """Exporte les mappings au format STIX 2.1 (basique).

        Génère un bundle STIX 2.1 contenant des objets
        ``attack-pattern`` correspondant aux techniques.

        Args:
            mappings: Liste de ``MitreMapping`` à exporter.

        Returns:
            Dict au format STIX 2.1 bundle.
        """
        logger.info("Export STIX 2.1 de %d mappings", len(mappings))

        stix_objects: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        for m in mappings:
            stix_obj = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": f"attack-pattern--{uuid4().hex[:8]}-{uuid4().hex[:4]}-{uuid4().hex[:4]}-{uuid4().hex[:4]}-{uuid4().hex[:12]}",
                "created": now,
                "modified": now,
                "name": m.technique_name,
                "description": m.description or "",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": m.technique_id,
                        "url": m.url or _technique_url(m.technique_id),
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": m.tactic.lower().replace(" ", "-"),
                    }
                ],
            }
            stix_objects.append(stix_obj)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid4().hex[:8]}-{uuid4().hex[:4]}-{uuid4().hex[:4]}-{uuid4().hex[:4]}-{uuid4().hex[:12]}",
            "spec_version": "2.1",
            "created": now,
            "objects": stix_objects,
        }

        logger.info(
            "  → Bundle STIX créé: %d objets attack-pattern",
            len(stix_objects),
        )
        return bundle
