# Architecture technique — NetworkRecon

---

## Vue d'ensemble

NetworkRecon suit une architecture modulaire en couches, séparant clairement les responsabilités :

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           COUCHE PRÉSENTATION                          │
│                                                                         │
│  ┌─────────────────────────────┐   ┌──────────────────────────────┐    │
│  │      Frontend (Nginx)       │   │     API Documentation        │    │
│  │   HTML / CSS / JavaScript   │   │  Swagger UI  │  ReDoc        │    │
│  │       Port 3000             │   │        Port 8000/docs        │    │
│  └──────────────┬──────────────┘   └──────────────┬───────────────┘    │
│                 │                                  │                    │
├─────────────────┼──────────────────────────────────┼────────────────────┤
│                 │       COUCHE API (FastAPI)        │                    │
│                 ▼                                  ▼                    │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                         FastAPI Router                            │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐  │  │
│  │  │ scans   │ │ hosts   │ │ vulns   │ │ mitre   │ │ reports │  │  │
│  │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘  │  │
│  │       │           │           │           │           │          │  │
│  │  ┌────┴────┐ ┌────┴────┐ ┌────┴────┐ ┌────┴────┐ ┌────┴────┐  │  │
│  │  │dashboard│ │network  │ │auth-test│ │         │ │         │  │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘  │  │
│  └──────────────────────────┬───────────────────────────────────────┘  │
│                             │                                          │
├─────────────────────────────┼──────────────────────────────────────────┤
│                  COUCHE SERVICES (Logique métier)                      │
│                             ▼                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                 │
│  │ ScanService  │  │HostService   │  │VulnScanner   │                 │
│  │              │  │              │  │              │                 │
│  │ Orchestre    │  │ CRUD Hôtes   │  │ NVD API      │                 │
│  │ les scans    │  │ + enrichit   │  │ CVE lookup   │                 │
│  └──────┬───────┘  └──────────────┘  └──────────────┘                 │
│         │                                                              │
│  ┌──────┴───────┐  ┌──────────────┐  ┌──────────────┐                 │
│  │ MitreMapper  │  │AuthTester    │  │ReportGen     │                 │
│  │              │  │              │  │              │                 │
│  │ Service→MITRE│  │ Brute force  │  │ JSON/CSV/    │                 │
│  │ CVE→MITRE    │  │ contrôlée    │  │ HTML/PDF     │                 │
│  │ STIX 2.1     │  │              │  │              │                 │
│  └──────────────┘  └──────────────┘  └──────────────┘                 │
│                                                                       │
├───────────────────────────────────────────────────────────────────────┤
│                    COUCHE SCANNERS (Scan réseau)                      │
│                                                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐    │
│  │ NmapScanner  │  │BannerGrabber │  │ ServiceIdentifier        │    │
│  │              │  │              │  │                          │    │
│  │ Wrapper      │  │ TCP connect  │  │ Matching service→version │    │
│  │ python-nmap  │  │ banner read  │  │ Fingerprinting           │    │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘    │
│                                                                       │
├───────────────────────────────────────────────────────────────────────┤
│                      COUCHE DONNÉES (MongoDB)                         │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │                    Motor (Async MongoDB Driver)                   │ │
│  │                                                                    │ │
│  │  Collections: campaigns, hosts, vulnerability_scans,              │ │
│  │               auth_test_campaigns, auth_test_results,             │ │
│  │               reports, credentials_files, network_ranges          │ │
│  └──────────────────────────┬───────────────────────────────────────┘ │
│                             │                                          │
│  ┌──────────────────────────▼───────────────────────────────────────┐ │
│  │                      MongoDB 7.0                                   │ │
│  │                    Port 27017                                      │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Diagramme des composants

### Backend — Structure interne

```
backend/app/
│
├── main.py                    # Point d'entrée FastAPI
│   ├── lifespan()             # Gestion startup/shutdown
│   ├── CORS middleware        # Configuration CORS
│   └── Router includes        # Montage des routes
│
├── config.py                  # Configuration centralisée
│   └── Settings (Pydantic)    # Variables d'environnement
│
├── models/                    # Modèles de données
│   ├── scan.py                # Campaign, ScanConfig, ScanResult
│   ├── host.py                # HostInfo, PortInfo
│   ├── vulnerability.py       # CVE, Vulnerability, MitreMapping
│   ├── mitre.py               # MitreMapping, ServiceToMitre
│   ├── auth_test.py           # AuthCampaign, AuthTestResult
│   ├── report.py              # Report, ReportSummary
│   └── network.py             # NetworkRange
│
├── routes/                    # Points d'entrée API
│   ├── scans.py               # /api/scans/*
│   ├── hosts.py               # /api/hosts/*
│   ├── vulnerabilities.py     # /api/vulnerabilities/*
│   ├── mitre.py               # /api/mitre/*
│   ├── auth_tests.py          # /api/auth-tests/*
│   ├── reports.py             # /api/reports/*
│   ├── dashboard.py           # /api/dashboard/*
│   └── network.py             # /api/network/*
│
├── services/                  # Logique métier
│   ├── scan_service.py        # Orchestration scans réseau
│   ├── host_service.py        # CRUD hôtes + enrichissement
│   ├── vulnerability_scanner.py # Scan vulns (NVD API)
│   ├── mitre_mapper.py        # Mapping service/CVE → MITRE
│   ├── auth_tester.py         # Tests d'authentification
│   ├── report_generator.py    # Génération rapports
│   └── network_service.py     # Gestion plages réseau
│
├── scanners/                  # Modules de scan bas niveau
│   ├── nmap_scanner.py        # Wrapper python-nmap
│   ├── banner_grabber.py      # Récupération bannières TCP
│   └── service_identifier.py  # Identification services
│
└── utils/
    └── database.py            # Connexion Motor/MongoDB
```

### Frontend — Structure

```
frontend/
├── src/
│   ├── index.html             # SPA (Single Page Application)
│   ├── css/
│   │   └── style.css          # Styles CSS
│   └── js/
│       ├── app.js             # Router et navigation
│       ├── api.js             # Client API (fetch)
│       ├── dashboard.js       # Vue tableau de bord
│       ├── campaigns.js       # Gestion campagnes
│       ├── hosts.js           # Liste hôtes
│       ├── vulnerabilities.js # Vulnérabilités
│       ├── mitre.js           # Matrice MITRE
│       ├── auth-tests.js      # Tests d'auth
│       └── reports.js         # Génération rapports
├── nginx.conf                 # Configuration Nginx
└── Dockerfile                 # Image production
```

---

## Flux de données

### 1. Scan réseau complet

```
Utilisateur                    API                    Service              Scanner              MongoDB
    │                           │                        │                     │                     │
    │  POST /api/scans/         │                        │                     │                     │
    │  (targets, config)        │                        │                     │                     │
    │──────────────────────────▶│                        │                     │                     │
    │                           │  insert_one(campaign)  │                     │                     │
    │                           │─────────────────────────────────────────────────────────────────▶│
    │                           │                        │                     │                     │
    │                           │  asyncio.create_task() │                     │                     │
    │                           │───────────────────────▶│                     │                     │
    │  201 Created              │                        │                     │                     │
    │◀──────────────────────────│                        │                     │                     │
    │                           │                        │                     │                     │
    │                           │   Pour chaque cible :  │                     │                     │
    │                           │                        │  run_scan(target)   │                     │
    │                           │                        │────────────────────▶│                     │
    │                           │                        │                     │  nmap -sV -sC       │
    │                           │                        │                     │  target             │
    │                           │                        │                     │◀────────────────────│
    │                           │                        │  hosts_found        │                     │
    │                           │                        │◀────────────────────│                     │
    │                           │                        │                     │                     │
    │                           │  insert_many(hosts)    │                     │                     │
    │                           │─────────────────────────────────────────────────────────────────▶│
    │                           │                        │                     │                     │
    │                           │   Scan vulnérabilités  │                     │                     │
    │                           │                        │  scan_vulns(hosts)  │                     │
    │                           │                        │────────────────────▶│                     │
    │                           │                        │                     │  NVD API lookup     │
    │                           │                        │                     │◀────────────────────│
    │                           │                        │  vulnerabilities    │                     │
    │                           │                        │◀────────────────────│                     │
    │                           │                        │                     │                     │
    │                           │  insert(vuln_scans)    │                     │                     │
    │                           │─────────────────────────────────────────────────────────────────▶│
    │                           │                        │                     │                     │
    │                           │   Mapping MITRE        │                     │                     │
    │                           │                        │  map_to_mitre()     │                     │
    │                           │                        │────────────────────▶│                     │
    │                           │                        │  mitre_mappings     │                     │
    │                           │                        │◀────────────────────│                     │
    │                           │                        │                     │                     │
    │  GET /api/scans/{id}/     │                        │                     │                     │
    │  status                   │                        │                     │                     │
    │──────────────────────────▶│                        │                     │                     │
    │  { status, progress }     │  find_one(campaign)    │                     │                     │
    │◀──────────────────────────│─────────────────────────────────────────────────────────────────▶│
```

### 2. Consultation des résultats

```
Utilisateur                    API                    Service              MongoDB
    │                           │                        │                     │
    │  GET /api/dashboard/stats │                        │                     │
    │──────────────────────────▶│                        │                     │
    │                           │  count_documents()     │                     │
    │                           │  aggregate(pipeline)   │                     │
    │                           │────────────────────────────────────────────▶│
    │  { stats }                │                        │                     │
    │◀──────────────────────────│                        │                     │
    │                           │                        │                     │
    │  GET /api/hosts/          │                        │                     │
    │──────────────────────────▶│                        │                     │
    │  [{ host1 }, { host2 }]   │  find().sort().limit() │                     │
    │◀──────────────────────────│────────────────────────────────────────────▶│
    │                           │                        │                     │
    │  GET /api/hosts/{ip}/     │                        │                     │
    │  mitre                    │                        │                     │
    │──────────────────────────▶│                        │                     │
    │                           │  find_one(host)        │                     │
    │                           │────────────────────────────────────────────▶│
    │                           │  map_service_to_mitre()│                     │
    │  [{ mapping1 }, ...]      │                        │                     │
    │◀──────────────────────────│                        │                     │
```

---

## Modèles de données (MongoDB Collections)

### `campaigns`

```json
{
  "_id": "ObjectId",
  "name": "string",
  "description": "string | null",
  "targets": [
    {
      "ip_range": "string (CIDR)",
      "authorized": "boolean",
      "target_list": ["string (IP)"]
    }
  ],
  "config": {
    "scan_type": "quick | full | stealth",
    "ports_range": "string | null",
    "timeout": "integer",
    "rate_limit": "integer"
  },
  "results": [
    {
      "scan_id": "string",
      "target": "string",
      "start_time": "datetime",
      "end_time": "datetime | null",
      "hosts_found": ["string (IP)"],
      "status": "pending | running | completed | failed | cancelled"
    }
  ],
  "created_at": "datetime",
  "status": "pending | running | completed | failed | cancelled"
}
```

### `hosts`

```json
{
  "_id": "ObjectId",
  "ip_address": "string (unique)",
  "hostname": "string | null",
  "mac_address": "string | null",
  "os_detection": "string | null",
  "status": "up | down",
  "ports": [
    {
      "number": "integer (1-65535)",
      "protocol": "tcp | udp",
      "state": "open | closed | filtered",
      "service": "string | null",
      "version": "string | null",
      "banner": "string | null"
    }
  ],
  "last_seen": "datetime",
  "first_seen": "datetime",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

### `vulnerability_scans`

```json
{
  "_id": "ObjectId",
  "scan_id": "string",
  "vulnerabilities": [
    {
      "host_ip": "string",
      "port": "integer | null",
      "service": "string | null",
      "cve": {
        "cve_id": "string (CVE-YYYY-NNNN+)",
        "description": "string",
        "severity": "critical | high | medium | low | info",
        "cvss_score": "float (0.0-10.0) | null",
        "affected_products": ["string"]
      },
      "mitre_mapping": {
        "technique_id": "string (TNNNN)",
        "technique_name": "string",
        "tactic": "string",
        "description": "string | null",
        "url": "string (URL) | null"
      } | null,
      "remediation": "string | null"
    }
  ],
  "summary": {
    "total_vulnerabilities": "integer",
    "by_severity": {
      "critical": "integer",
      "high": "integer",
      "medium": "integer",
      "low": "integer",
      "info": "integer"
    },
    "affected_hosts": "integer"
  },
  "scan_time": "datetime"
}
```

### `auth_test_campaigns`

```json
{
  "_id": "ObjectId",
  "name": "string",
  "targets": ["string (IP)"],
  "config": {
    "service_type": "ssh | ftp | smb | rdp | http | https | mysql | postgresql | redis | mongodb",
    "credentials_file": "string | null",
    "max_attempts": "integer (1-100)",
    "delay_between": "float (0.1-60.0)"
  },
  "results": [
    {
      "host_ip": "string",
      "port": "integer",
      "service": "string",
      "credential_used": "string",
      "success": "boolean",
      "timestamp": "datetime",
      "error_message": "string | null"
    }
  ],
  "status": "pending | running | completed | failed | cancelled",
  "created_at": "datetime",
  "completed_at": "datetime | null"
}
```

### `reports`

```json
{
  "_id": "ObjectId",
  "campaign_id": "string",
  "generated_at": "datetime",
  "summary": {
    "total_hosts": "integer",
    "total_services": "integer",
    "total_vulnerabilities": "integer",
    "by_severity": {
      "critical": "integer",
      "high": "integer",
      "medium": "integer",
      "low": "integer",
      "info": "integer"
    },
    "scan_duration": "float | null"
  },
  "content": "object (contenu détaillé)",
  "export_format": "pdf | csv | json | html",
  "title": "string | null",
  "description": "string | null",
  "generated_by": "string | null"
}
```

### `credentials_files`

```json
{
  "_id": "ObjectId",
  "filename": "string",
  "original_filename": "string",
  "content": "string (username:password, un par ligne)",
  "credentials_count": "integer",
  "uploaded_at": "datetime"
}
```

### `network_ranges`

```json
{
  "_id": "ObjectId",
  "name": "string",
  "cidr": "string (ex: 192.168.1.0/24)",
  "description": "string | null",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

---

## Patterns utilisés

### 1. Async/Await

Toute l'application est asynchrone pour maximiser les performances I/O :

```python
# Routes
@router.get("/hosts/{ip}")
async def get_host_by_ip(ip: str):
    db = await get_database()
    doc = await db.hosts.find_one({"ip_address": ip})
    return HostInfo(**doc)

# Services
class VulnerabilityScanner:
    async def lookup_cve(self, service: str, version: str) -> list[CVE]:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                return await response.json()
```

### 2. Dependency Injection

FastAPI gère l'injection des dépendances via `Depends()` :

```python
async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[str]:
    if credentials is None:
        return None
    return credentials.credentials

@router.get("/scans/")
async def list_campaigns(user: Optional[str] = Depends(get_current_user)):
    # user est injecté automatiquement
    pass
```

### 3. Pydantic Models

Validation automatique des données d'entrée et de sortie :

```python
class ScanTarget(BaseModel):
    ip_range: str
    authorized: bool = False
    target_list: List[str] = []

    @field_validator("ip_range")
    @classmethod
    def validate_ip_range(cls, v: str) -> str:
        import ipaddress
        ipaddress.ip_network(v, strict=False)
        return v
```

### 4. Background Tasks

Les scans longs s'exécutent en arrière-plan :

```python
@router.post("/scans/")
async def create_campaign(...):
    campaign = Campaign(...)
    await db.campaigns.insert_one(campaign.model_dump())

    # Lancer en arrière-plan sans bloquer la requête
    asyncio.create_task(service.run_campaign(campaign))

    return campaign  # Retour immédiat
```

### 5. Service Layer Pattern

La logique métier est isolée dans des services dédiés :

```
Routes (HTTP) → Services (Logique) → Scanners (Nmap/NVD) → Database
```

### 6. Aggregation Pipeline

Requêtes MongoDB complexes pour les statistiques :

```python
pipeline = [
    {"$unwind": "$vulnerabilities"},
    {"$unwind": "$vulnerabilities.cve"},
    {"$group": {"_id": "$vulnerabilities.cve.severity", "count": {"$sum": 1}}},
]
async for doc in db.vulnerability_scans.aggregate(pipeline):
    severity_counts[doc["_id"]] = doc["count"]
```

---

## Sécurité

### 1. Chiffrement

| Composant | Méthode |
|-----------|---------|
| Communication API | HTTPS (via reverse proxy) |
| MongoDB | TLS inter-conteneurs |
| Credentials stockés | Hash bcrypt (auth tests) |

### 2. Autorisation

- Token Bearer optionnel (JWT prévu pour v0.2.0)
- Validation de l'autorisation de scan (`authorized: true`)
- Logs d'audit des actions sensibles

### 3. Rate Limiting

```
Limite par endpoint :
- Création de campagne : 10/min
- Lookup CVE : 30/min
- Tests d'auth : 5/min
- Autres : 100/min
```

### 4. Validation des entrées

- Validation Pydantic sur tous les modèles
- Regex pour les formats (CVE, MITRE technique ID, IP, MAC)
- Limites sur les paramètres (timeout, max_attempts, etc.)

### 5. Isolation réseau

```yaml
# docker-compose.yml
networks:
  networkrecon-internal:
    driver: bridge
    internal: true    # Pas d'accès Internet
  networkrecon-public:
    driver: bridge    # Accès Internet pour les scans
```

### 6. Non-root user (Docker)

```dockerfile
# Le backend tourne en tant qu'utilisateur non-root
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser
```

---

## Flux réseau

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│Internet  │────▶│ Frontend │────▶│ Backend  │────▶│ MongoDB  │
│          │     │ (Nginx)  │     │ (FastAPI)│     │          │
│          │     │ :3000    │     │ :8000    │     │ :27017   │
└──────────┘     └──────────┘     └────┬─────┘     └──────────┘
                                       │
                                       │  Scan réseau
                                       ▼
                               ┌──────────────────┐
                               │ Réseau cible      │
                               │ 192.168.2.0/24    │
                               │                   │
                               │ ┌─────┐ ┌─────┐  │
                               │ │Host1│ │Host2│  │
                               │ └─────┘ └─────┘  │
                               └──────────────────┘
```
