# Mapping MITRE ATT&CK — NetworkRecon

---

## Vue d'ensemble

NetworkRecon mappe automatiquement les services réseau et les vulnérabilités détectées vers le framework MITRE ATT&CK (Enterprise, v14). Ce document décrit les services supportés, les techniques associées et comment enrichir la base de mapping.

---

## Services supportés

### Liste des services

| Service | Port(s) | Techniques MITRE | Tactiques |
|---------|---------|------------------|-----------|
| **SSH** | 22 | T1021.004, T1562.001, T1552.004, T1078 | Lateral Movement, Defense Evasion, Credential Access, Initial Access |
| **FTP** | 21 | T1021.002, T1133, T1083 | Lateral Movement, Initial Access, Discovery |
| **SMB** | 445 | T1021.002, T1110, T1572, T1110.001 | Lateral Movement, Credential Access, Command and Control |
| **HTTP** | 80, 8080 | T1190, T1133, T1071.001, T1059.007, T1053.003 | Initial Access, Command and Control, Execution |
| **HTTPS** | 443, 8443 | T1190, T1071.001 | Initial Access, Command and Control |
| **MySQL** | 3306 | T1021.004, T1110.001, T1505.003 | Lateral Movement, Credential Access, Persistence |
| **PostgreSQL** | 5432 | T1021.004, T1110.001, T1059.006 | Lateral Movement, Credential Access, Execution |
| **RDP** | 3389 | T1021.001, T1110, T1563.002, T1078 | Lateral Movement, Credential Access, Impact, Initial Access |
| **Telnet** | 23 | T1021.002, T1552.001, T1040 | Lateral Movement, Credential Access |
| **SNMP** | 161 | T1040, T1048, T1082 | Credential Access, Exfiltration, Discovery |
| **DNS** | 53 | T1071.004, T1568 | Command and Control, Exfiltration |
| **LDAP** | 389 | T1087.002, T1558, T1018, T1087.004 | Discovery, Credential Access |
| **Redis** | 6379 | T1098, T1133, T1059.006 | Persistence, Initial Access, Execution |
| **SMTP** | 25 | T1048.002, T1566.001, T1048.001 | Exfiltration, Initial Access |
| **MSSQL** | 1433 | T1505.002, T1110.001, T1059.005 | Persistence, Credential Access, Execution |
| **Oracle** | 1521 | T1110.001, T1053.003 | Credential Access, Execution |
| **VNC** | 5900 | T1021.005, T1110 | Lateral Movement, Credential Access |
| **Memcached** | 11211 | T1048, T1498 | Exfiltration, Impact |
| **NFS** | 2049 | T1083, T1039 | Discovery, Collection |
| **SIP** | 5060, 5061 | T1040, T1071.001 | Credential Access, Command and Control |
| **NTP** | 123 | T1498, T1040 | Impact, Credential Access |
| **Kerberos** | 88 | T1558.001, T1558.003 | Credential Access |
| **IPP** | 631 | T1059.007, T1190 | Execution, Initial Access |
| **Docker** | 2375, 2376 | T1610, T1611 | Execution, Privilege Escalation |
| **Kubernetes** | 6443 | T1610, T1613 | Execution, Discovery |
| **ZooKeeper** | 2181 | T1498, T1082 | Impact, Discovery |
| **CouchDB** | 5984 | T1133, T1083 | Initial Access, Discovery |
| **Elasticsearch** | 9200 | T1530, T1048 | Collection, Exfiltration |
| **MongoDB** | 27017 | T1005, T1133 | Collection, Initial Access |
| **Tomcat** | 8080 | T1190, T1505.003 | Initial Access, Persistence |
| **Jenkins** | 8080, 8443 | T1053.003, T1190 | Execution, Initial Access |
| **RabbitMQ** | 15672 | T1048, T1133 | Exfiltration, Initial Access |

---

## Détail des techniques par service

### SSH (port 22)

```yaml
service: ssh
techniques:
  - id: T1021.004
    name: "Remote Services: SSH"
    tactic: "Lateral Movement"
    description: >
      Utilisation du protocole SSH pour se déplacer latéralement
      vers d'autres systèmes du réseau.

  - id: T1562.001
    name: "Impair Defenses: Disable or Modify Tools"
    tactic: "Defense Evasion"
    description: >
      Désactivation ou modification d'outils de sécurité via SSH
      (iptables, SELinux, agent EDR).

  - id: T1552.004
    name: "Unsecured Credentials: Private Keys"
    tactic: "Credential Access"
    description: >
      Récupération de clés privées SSH exposées ou mal protégées
      sur le système cible.

  - id: T1078
    name: "Valid Accounts"
    tactic: "Initial Access"
    description: >
      Utilisation de comptes SSH légitimes pour l'accès initial
      au système.
```

### HTTP/HTTPS (ports 80/443)

```yaml
service: http/https
techniques:
  - id: T1190
    name: "Exploit Public-Facing Application"
    tactic: "Initial Access"
    description: >
      Exploitation de vulnérabilités dans une application web
      exposée publiquement (RCE, SQLi, XSS, etc.).

  - id: T1133
    name: "External Remote Services"
    tactic: "Initial Access"
    description: >
      Accès initial via des services HTTP exposés
      (panneaux d'administration, API).

  - id: T1071.001
    name: "Application Layer Protocol: Web Protocols"
    tactic: "Command and Control"
    description: >
      Utilisation de HTTP/HTTPS comme protocole de
      commande et contrôle (C2).

  - id: T1059.007
    name: "Command and Scripting Interpreter: JavaScript"
    tactic: "Execution"
    description: >
      Exécution de code JavaScript malveillant via des
      injections dans les pages web.
```

### SMB (port 445)

```yaml
service: smb
techniques:
  - id: T1021.002
    name: "Remote Services: SMB/Windows Admin Shares"
    tactic: "Lateral Movement"
    description: >
      Utilisation de SMB pour se déplacer latéralement via les
      partages réseau et les shares administratifs Windows.

  - id: T1110
    name: "Brute Force"
    tactic: "Credential Access"
    description: >
      Attaques par force brute contre les partages SMB
      pour obtenir des identifiants valides.

  - id: T1572
    name: "Protocol Tunneling"
    tactic: "Command and Control"
    description: >
      Tunneling de protocoles via SMB pour contourner les
      contrôles de sécurité réseau.
```

### RDP (port 3389)

```yaml
service: rdp
techniques:
  - id: T1021.001
    name: "Remote Services: Remote Desktop Protocol"
    tactic: "Lateral Movement"
    description: >
      Utilisation de RDP pour se déplacer latéralement
      vers des systèmes Windows.

  - id: T1110
    name: "Brute Force"
    tactic: "Credential Access"
    description: >
      Attaques par force brute sur les sessions RDP
      pour obtenir des identifiants valides.

  - id: T1078
    name: "Valid Accounts"
    tactic: "Initial Access"
    description: >
      Utilisation de comptes légitimes via RDP pour
      l'accès initial au système.
```

---

## Mapping CVE → MITRE ATT&CK

En plus du mapping statique service→technique, NetworkRecon mappe les CVE vers MITRE via :

### 1. Matching local par mots-clés

| Mots-clés dans la CVE | Technique MITRE | Tactique |
|------------------------|-----------------|----------|
| `remote code execution`, `rce`, `command injection` | T1203 | Execution |
| `sql injection`, `sqli` | T1190 | Initial Access |
| `cross-site scripting`, `xss` | T1189 | Initial Access |
| `privilege escalation`, `elevation of privilege` | T1068 | Privilege Escalation |
| `authentication bypass`, `auth bypass` | T1078 | Initial Access |
| `denial of service`, `dos`, `ddos` | T1499 | Impact |
| `information disclosure`, `info leak` | T1005 | Collection |
| `path traversal`, `directory traversal`, `lfi` | T1083 | Discovery |
| `remote file inclusion`, `rfi` | T1059 | Execution |
| `deserialization`, `insecure deserialization` | T1059 | Execution |
| `ssrf`, `server-side request forgery` | T1190 | Initial Access |
| `xxe`, `xml external entity` | T1059 | Execution |
| `memory corruption`, `use-after-free`, `heap overflow` | T1203 | Execution |
| `default credentials`, `hardcoded credentials` | T1110.001 | Credential Access |
| `directory listing`, `directory browsing` | T1083 | Discovery |
| `open redirect`, `url redirect` | T1189 | Initial Access |
| `code injection` | T1059 | Execution |
| `file upload`, `unrestricted file upload` | T1059 | Execution |
| `cross-site request forgery`, `csrf` | T1189 | Initial Access |
| `password leak`, `credential leak` | T1552.001 | Credential Access |
| `log4j`, `log4shell`, `jndi injection` | T1190 | Initial Access |
| `spring4shell`, `spring`, `spel injection` | T1190 | Initial Access |
| `openssl`, `heartbleed`, `ssl`, `tls` | T1040 | Credential Access |

### 2. API OTX (AlienVault)

NetworkRecon interroge l'API OTX d'AlienVault pour enrichir le mapping CVE→MITRE :

```
GET https://otx.alienvault.com/api/v1/pulses/{cve_id}/general
```

Les résultats sont mis en cache pour éviter les appels répétés.

---

## Tactiques MITRE ATT&CK (Enterprise, v14)

```yaml
tactics:
  - id: TA0043
    name: "Reconnaissance"
    description: "Collecte d'informations pour planifier les opérations"

  - id: TA0042
    name: "Resource Development"
    description: "Création d'outils et d'infrastructures"

  - id: TA0001
    name: "Initial Access"
    description: "Obtenir un accès initial au réseau"

  - id: TA0002
    name: "Execution"
    description: "Exécution de code malveillant"

  - id: TA0003
    name: "Persistence"
    description: "Maintenir l'accès au système"

  - id: TA0004
    name: "Privilege Escalation"
    description: "Obtenir des privilèges plus élevés"

  - id: TA0005
    name: "Defense Evasion"
    description: "Éviter la détection"

  - id: TA0006
    name: "Credential Access"
    description: "Obtenir des identifiants"

  - id: TA0007
    name: "Discovery"
    description: "Explorer l'environnement"

  - id: TA0008
    name: "Lateral Movement"
    description: "Se déplacer dans le réseau"

  - id: TA0009
    name: "Collection"
    description: "Collecter des données"

  - id: TA0011
    name: "Command and Control"
    description: "Communiquer avec le système compromis"

  - id: TA0010
    name: "Exfiltration"
    description: "Exfiltrer les données"

  - id: TA0040
    name: "Impact"
    description: "Interrompre ou détruire les systèmes"
```

---

## Export STIX 2.1

L'endpoint `GET /api/mitre/export/stix` exporte les données au format STIX 2.1 :

```json
{
  "type": "bundle",
  "id": "bundle--networkrecon-mitre-attack",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "attack-pattern",
      "id": "attack-pattern--T1190",
      "spec_version": "2.1",
      "created": "2026-01-01T00:00:00.000Z",
      "modified": "2026-01-01T00:00:00.000Z",
      "name": "Exploit Public-Facing Application",
      "description": "...",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "T1190",
          "url": "https://attack.mitre.org/techniques/T1190/"
        }
      ]
    }
  ]
}
```

---

## Comment enrichir la base de mapping

### Ajouter un nouveau service

1. **Modifier** `backend/app/services/mitre_mapper.py`

2. **Ajouter une entrée** dans `_SERVICE_MITRE_DB` :

```python
_SERVICE_MITRE_DB = {
    # ... services existants ...

    # ── Nouveau service (port XXXX) ──────────────────────────────
    "nom_du_service": [
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": (
                "Description de la technique appliquée "
                "à ce service."
            ),
        },
        {
            "technique_id": "T1021",
            "technique_name": "Remote Services",
            "tactic": "Lateral Movement",
            "description": "...",
        },
    ],
}
```

3. **Valider le format** de `technique_id` :
   - Pattern : `T\d{4}(\.\d{3})?`
   - Exemples : `T1190`, `T1021.004`

4. **Tester** le mapping :

```bash
curl http://localhost:8000/api/mitre/techniques?service=nom_du_service
```

### Ajouter un pattern CVE→MITRE

1. **Modifier** `backend/app/services/mitre_mapper.py`

2. **Ajouter dans** `_CVE_KEYWORD_TECHNIQUES` :

```python
_CVE_KEYWORD_TECHNIQUES = [
    # ... patterns existants ...

    {
        "keywords": ["mot-clé-1", "mot-clé-2", "mot-clé-3"],
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Description de la correspondance.",
    },
]
```

3. **Convention de nommage** pour les mots-clés :
   - Minuscules
   - Anglais (langue de la CVE)
   - Pas d'accents
   - Exemples : `remote code execution`, `sql injection`, `buffer overflow`

### Vérification des mappings

```bash
# Lister toutes les techniques pour un service
curl http://localhost:8000/api/mitre/techniques?service=ssh

# Lister toutes les tactiques
curl http://localhost:8000/api/mitre/tactics

# Détail d'une technique
curl http://localhost:8000/api/mitre/techniques/T1190

# Parcours d'attaque
curl http://localhost:8000/api/mitre/attack-paths

# Export STIX
curl http://localhost:8000/api/mitre/export/stix
```

---

## Références

- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [STIX 2.1 Specification](https://oasis-open.github.io/cti-documentation/stix/intro.html)
- [NIST NVD](https://nvd.nist.gov/)
- [AlienVault OTX API](https://otx.alienvault.com/api)
