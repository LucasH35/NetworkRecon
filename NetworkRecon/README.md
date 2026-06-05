# NetworkRecon

**Outil de reconnaissance réseau asynchrone** basé sur FastAPI, MongoDB et nmap.

NetworkRecon permet de scanner des réseaux, d'identifier les services, de détecter les vulnérabilités et de mapper les résultats vers le framework MITRE ATT&CK. L'interface web offre un tableau de bord interactif pour visualiser les campagnes, les hôtes découverts et les risques associés.

> **Avertissement** : Cet outil est conçu pour un usage légal uniquement. Assurez-vous d'avoir l'autorisation explicite avant de scanner un réseau.

---

## Fonctionnalités principales

- **Scan réseau asynchrone** — Découverte d'hôtes, scan de ports et détection de services via nmap
- **Détection de vulnérabilités** — Recherche de CVE connues via l'API NVD (NIST)
- **Mapping MITRE ATT&CK** — Association automatique des services/vulnérabilités aux techniques d'attaque
- **Tests d'authentification** — Campagnes de brute force contrôlées (SSH, FTP, SMB, RDP, etc.)
- **Génération de rapports** — Export en JSON, CSV, HTML et PDF
- **Tableau de bord** — Statistiques en temps réel, répartition des vulnérabilités par sévérité
- **Architecture async** — Backend FastAPI avec Motor (MongoDB async) pour des performances optimales

---

## Architecture technique

```
┌─────────────────────────────────────────────────────────────────┐
│                        NetworkRecon                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   Frontend   │    │    Backend   │    │   MongoDB    │      │
│  │   (Nginx)    │───▶│   (FastAPI)  │───▶│   (Mongo 7)  │      │
│  │  Port 3000   │    │  Port 8000   │    │  Port 27017  │      │
│  └──────────────┘    └──────┬───────┘    └──────────────┘      │
│                             │                                   │
│                    ┌────────┼────────┐                          │
│                    │        │        │                          │
│              ┌─────▼───┐ ┌──▼────┐ ┌▼──────────┐              │
│              │ Scanners │ │Services│ │  Routes   │              │
│              │ (nmap)   │ │(vulns, │ │ (API)     │              │
│              │          │ │ MITRE, │ │           │              │
│              └──────────┘ │ auth)  │ └───────────┘              │
│                           └────────┘                            │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  Réseau: networkrecon-internal (bridge) │ networkrecon-public   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Prérequis

| Composant | Version minimale | Usage |
|-----------|-----------------|-------|
| Python    | 3.11+           | Backend FastAPI |
| Docker    | 24.0+           | Conteneurisation (recommandé) |
| Docker Compose | 2.20+    | Orchestration des services |
| nmap      | 7.80+           | Scan réseau |
| MongoDB   | 7.0+            | Base de données (fournie via Docker) |

---

## Installation

### Via Docker Compose (recommandé)

```bash
# Cloner le dépôt
git clone https://github.com/lucash/networkrecon.git
cd NetworkRecon

# Copier le fichier d'environnement
cp .env.example .env

# Modifier les identifiants par défaut
# IMPORTANT: Changer MONGODB_INITDB_ROOT_PASSWORD et SECRET_KEY
nano .env

# Lancer l'ensemble des services
docker compose up --build -d

# Vérifier le statut des conteneurs
docker compose ps
```

### En mode développement local

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend ( nécessite Node.js )
cd frontend
npx http-server src -p 3000
```

---

## Configuration

Copiez `.env.example` en `.env` et configurez les variables :

```bash
# MongoDB
MONGODB_INITDB_ROOT_USERNAME=admin
MONGODB_INITDB_ROOT_PASSWORD=<mot_de_passe_complexe>
MONGODB_DATABASE=networkrecon

# Backend
API_HOST=0.0.0.0
API_PORT=8000
SECRET_KEY=<clé_secrète_aleatoire>

# Application
APP_ENV=development
DEBUG=true

# CORS
CORS_ORIGINS=["http://localhost:3000"]

# Scan
SCAN_TIMEOUT=300
MAX_CONCURRENT_SCANS=5
```

| Variable | Description | Défaut |
|----------|-------------|--------|
| `MONGODB_INITDB_ROOT_USERNAME` | Utilisateur root MongoDB | `admin` |
| `MONGODB_INITDB_ROOT_PASSWORD` | Mot de passe root MongoDB | — |
| `MONGODB_DATABASE` | Nom de la base de données | `networkrecon` |
| `SECRET_KEY` | Clé secrète pour les sessions | — |
| `SCAN_TIMEOUT` | Timeout des scans (secondes) | `300` |
| `MAX_CONCURRENT_SCANS` | Scans simultanés max | `5` |

---

## Utilisation

### 1. Lancer l'application

```bash
docker compose up --build
```

### 2. Accéder aux interfaces

| Service | URL | Description |
|---------|-----|-------------|
| Frontend | http://localhost:3000 | Interface web interactive |
| API Docs | http://localhost:8000/docs | Swagger UI (OpenAPI) |
| ReDoc | http://localhost:8000/redoc | Documentation API |
| Health | http://localhost:8000/health | Vérification de santé |

### 3. Créer une campagne de scan

```bash
# Exemple : scan complet de la plage 192.168.2.0/24
curl -X POST "http://localhost:8000/api/scans/?name=Scan+LAN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [
      {
        "ip_range": "192.168.2.0/24",
        "authorized": true,
        "target_list": []
      }
    ],
    "config": {
      "scan_type": "full",
      "ports_range": "1-1024,8080,8443",
      "timeout": 600,
      "rate_limit": 1000
    }
  }'
```

### 4. Consulter les résultats

```bash
# Statistiques globales
curl http://localhost:8000/api/dashboard/stats

# Liste des hôtes découverts
curl http://localhost:8000/api/hosts/?limit=10

# Vulnérabilités critiques
curl "http://localhost:8000/api/vulnerabilities/?severity=critical"

# Mapping MITRE ATT&CK
curl http://localhost:8000/api/mitre/techniques
```

---

## Structure du projet

```
NetworkRecon/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py              # Point d'entrée FastAPI
│   │   ├── config.py            # Configuration (Pydantic Settings)
│   │   ├── models/              # Modèles Pydantic
│   │   │   ├── scan.py          # Campagnes, résultats de scan
│   │   │   ├── host.py          # Hôtes et ports
│   │   │   ├── vulnerability.py # CVE, sévérités
│   │   │   ├── mitre.py         # Mapping MITRE ATT&CK
│   │   │   ├── auth_test.py     # Tests d'authentification
│   │   │   ├── report.py        # Rapports
│   │   │   └── network.py       # Plages réseau
│   │   ├── routes/              # Routes API (FastAPI Router)
│   │   │   ├── scans.py         # CRUD campagnes + lifecycle
│   │   │   ├── hosts.py         # Détails hôtes, ports, vulns
│   │   │   ├── vulnerabilities.py # CVE lookup, summary
│   │   │   ├── mitre.py         # Techniques, tactiques, STIX
│   │   │   ├── auth_tests.py    # Campagnes de test
│   │   │   ├── reports.py       # Génération, export
│   │   │   ├── dashboard.py     # Statistiques
│   │   │   └── network.py       # Plages réseau
│   │   ├── services/            # Logique métier
│   │   │   ├── scan_service.py  # Orchestration des scans
│   │   │   ├── host_service.py  # Gestion des hôtes
│   │   │   ├── vulnerability_scanner.py # Scan de vulnérabilités
│   │   │   ├── mitre_mapper.py  # Mapping MITRE ATT&CK
│   │   │   ├── auth_tester.py   # Tests d'authentification
│   │   │   ├── report_generator.py # Génération de rapports
│   │   │   └── network_service.py  # Gestion réseau
│   │   ├── scanners/            # Modules de scan
│   │   │   ├── nmap_scanner.py  # Wrapper nmap
│   │   │   ├── banner_grabber.py # Récupération de bannières
│   │   │   └── service_identifier.py # Identification de services
│   │   └── utils/
│   │       └── database.py      # Connexion MongoDB
│   ├── tests/                   # Tests unitaires
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── index.html           # Page principale
│   │   ├── css/style.css        # Styles
│   │   └── js/
│   │       ├── app.js           # Application principale
│   │       ├── api.js           # Client API
│   │       ├── dashboard.js     # Tableau de bord
│   │       ├── campaigns.js     # Gestion des campagnes
│   │       ├── hosts.js         # Liste des hôtes
│   │       ├── vulnerabilities.js # Vulnérabilités
│   │       ├── mitre.js         # Mapping MITRE
│   │       ├── auth-tests.js    # Tests d'auth
│   │       └── reports.js       # Rapports
│   ├── nginx.conf
│   └── Dockerfile
├── docs/                        # Documentation
│   ├── INSTALLATION.md
│   ├── API.md
│   ├── ARCHITECTURE.md
│   └── MITRE_MAPPING.md
├── docker-compose.yml
├── .env.example
├── .gitignore
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

---

## Résumé des endpoints API

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| **Scans** | | |
| `GET` | `/api/scans/` | Lister les campagnes |
| `POST` | `/api/scans/` | Créer une campagne |
| `GET` | `/api/scans/{id}` | Détails d'une campagne |
| `GET` | `/api/scans/{id}/status` | Statut temps réel |
| `POST` | `/api/scans/{id}/pause` | Pause |
| `POST` | `/api/scans/{id}/resume` | Reprise |
| `POST` | `/api/scans/{id}/cancel` | Annulation |
| `DELETE` | `/api/scans/{id}` | Suppression |
| **Hosts** | | |
| `GET` | `/api/hosts/` | Lister les hôtes |
| `GET` | `/api/hosts/{ip}` | Détails d'un hôte |
| `GET` | `/api/hosts/{ip}/ports` | Ports ouverts |
| `GET` | `/api/hosts/{ip}/vulnerabilities` | Vulnérabilités |
| `GET` | `/api/hosts/{ip}/mitre` | Mappings MITRE |
| **Vulnérabilités** | | |
| `GET` | `/api/vulnerabilities/` | Lister les vulns |
| `GET` | `/api/vulnerabilities/summary` | Résumé par sévérité |
| `GET` | `/api/vulnerabilities/{cve_id}` | Détail d'une CVE |
| `POST` | `/api/vulnerabilities/lookup` | Recherche CVE |
| **MITRE ATT&CK** | | |
| `GET` | `/api/mitre/tactics` | Lister les tactiques |
| `GET` | `/api/mitre/techniques` | Lister les techniques |
| `GET` | `/api/mitre/techniques/{id}` | Détail d'une technique |
| `GET` | `/api/mitre/attack-paths` | Parcours d'attaque |
| `GET` | `/api/mitre/export/stix` | Export STIX 2.1 |
| **Auth Tests** | | |
| `POST` | `/api/auth-tests/` | Lancer une campagne |
| `GET` | `/api/auth-tests/` | Lister les campagnes |
| `GET` | `/api/auth-tests/{id}` | Résultats |
| `POST` | `/api/auth-tests/credentials` | Uploader credentials |
| **Reports** | | |
| `POST` | `/api/reports/generate` | Générer un rapport |
| `GET` | `/api/reports/{id}` | Récupérer un rapport |
| `GET` | `/api/reports/{id}/export/{format}` | Exporter |
| **Dashboard** | | |
| `GET` | `/api/dashboard/stats` | Statistiques globales |
| `GET` | `/api/dashboard/severity-distribution` | Répartition sévérités |
| `GET` | `/api/dashboard/top-vulns` | Top vulnérabilités |
| `GET` | `/api/dashboard/network-overview` | Vue réseau |

---

## Screenshots

<!-- Ajouter des captures d'écran ici -->

- **Tableau de bord** : Vue d'ensemble avec statistiques et graphiques
- **Campagne de scan** : Détails d'un scan en cours sur 192.168.2.0/24
- **Hôtes découverts** : Liste des hôtes avec ports et services
- **Vulnérabilités** : Tableau des CVE avec sévérités et recommandations
- **MITRE ATT&CK** : Matrice des techniques identifiées

---

## Roadmap

### v0.2.0 (en cours)
- [ ] Authentification JWT avec rôles
- [ ] WebSocket pour les mises à jour en temps réel
- [ ] Scan asynchrone avec file d'attente (Celery/Redis)
- [ ] Export PDF avec graphiques

### v0.3.0
- [ ] Scan de vulnérabilités actif (Nuclei)
- [ ] Intégration Shodan/Censys
- [ ] Système d'alertes et notifications
- [ ] API GraphQL

### v0.4.0
- [ ] Multi-utilisateurs avec permissions granulaires
- [ ] Scheduling de scans récurrents
- [ ] Intégration SIEM (Splunk, ELK)
- [ ] Dashboard personnalisable

---

## Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

## Auteurs

- **Lucash** — Développeur principal — [GitHub](https://github.com/lucash)

---

## Contribution

Consultez le guide de contribution dans [CONTRIBUTING.md](CONTRIBUTING.md) pour参与 au projet.
