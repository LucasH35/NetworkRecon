# Guide d'installation — NetworkRecon

Ce guide détaille l'installation de NetworkRecon sur différentes plateformes.

---

## Table des matières

1. [Installation via Docker (recommandé)](#1-installation-via-docker-recommandé)
2. [Installation sur Ubuntu/Debian](#2-installation-sur-ubuntudebian)
3. [Installation sur macOS](#3-installation-sur-macos)
4. [Installation sur Windows (WSL2)](#4-installation-sur-windows-wsl2)
5. [Configuration de MongoDB](#5-configuration-de-mongodb)
6. [Vérification de l'installation](#6-vérification-de-linstallation)

---

## 1. Installation via Docker (recommandé)

C'est la méthode la plus simple et la plus fiable. Elle garantit un environnement reproductible.

### Prérequis

```bash
# Vérifier Docker
docker --version   # >= 24.0

# Vérifier Docker Compose
docker compose version  # >= 2.20
```

### Étapes

```bash
# 1. Cloner le dépôt
git clone https://github.com/lucash/networkrecon.git
cd NetworkRecon

# 2. Copier et configurer l'environnement
cp .env.example .env

# 3. Modifier les paramètres de sécurité
# IMPORTANT : Changer au minimum ces variables :
#   - MONGODB_INITDB_ROOT_PASSWORD
#   - SECRET_KEY
nano .env
```

**Fichier `.env` minimal :**

```bash
MONGODB_INITDB_ROOT_USERNAME=admin
MONGODB_INITDB_ROOT_PASSWORD=MonMotDePasseComplet2024!
MONGODB_DATABASE=networkrecon
SECRET_KEY=cle-aleatoire-32-caracteres-minimum
```

```bash
# 4. Construire et lancer
docker compose up --build -d

# 5. Vérifier le statut
docker compose ps
docker compose logs -f backend
```

### Services démarrés

| Service | Port | Description |
|---------|------|-------------|
| Frontend | 3000 | Interface web |
| Backend API | 8000 | API FastAPI + Swagger |
| MongoDB | 27017 | Base de données |

### Arrêter les services

```bash
docker compose down          # Arrêter les conteneurs
docker compose down -v       # Arrêter + supprimer les volumes (données)
```

---

## 2. Installation sur Ubuntu/Debian

### Prérequis système

```bash
# Mettre à jour le système
sudo apt update && sudo apt upgrade -y

# Installer les dépendances
sudo apt install -y \
  python3.11 \
  python3.11-venv \
  python3-pip \
  git \
  nmap \
  libpq-dev \
  gcc
```

### Installer nmap

```bash
# nmap est généralement disponible dans les dépôts
sudo apt install -y nmap

# Vérifier la version
nmap --version  # >= 7.80
```

### Configuration du projet

```bash
# Cloner le dépôt
git clone https://github.com/lucash/networkrecon.git
cd NetworkRecon/backend

# Créer l'environnement virtuel
python3.11 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install --upgrade pip
pip install -r requirements.txt
```

### Configurer l'environnement

```bash
cd ..
cp .env.example .env

# Modifier les variables
nano .env
```

### Lancer en développement

```bash
cd backend
source venv/bin/activate

# Démarrer le serveur de développement
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Lancer MongoDB (si pas Docker)

```bash
# Installer MongoDB 7.0
# https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/

# Ou via Docker isolé
docker run -d \
  --name mongodb \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=changeme \
  -v mongo_data:/data/db \
  mongo:7
```

---

## 3. Installation sur macOS

### Prérequis

```bash
# Installer Homebrew (si pas déjà installé)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Installer les dépendances
brew install python@3.11 git nmap docker docker-compose
```

### Configuration

```bash
# Cloner le dépôt
git clone https://github.com/lucash/networkrecon.git
cd NetworkRecon/backend

# Créer l'environnement virtuel
python3.11 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install --upgrade pip
pip install -r requirements.txt

# Configuration
cd ..
cp .env.example .env
nano .env
```

### Lancer

```bash
# Option 1 : Docker Compose (recommandé)
docker compose up --build

# Option 2 : Développement local
cd backend
source venv/bin/activate
uvicorn app.main:app --reload --port 8000
```

---

## 4. Installation sur Windows (WSL2)

### Prérequis

1. **Activer WSL2** :
```powershell
# PowerShell en administrateur
wsl --install
# Redémarrer, puis installer Ubuntu 22.04+
```

2. **Installer Docker Desktop** :
   - Télécharger depuis https://www.docker.com/products/docker-desktop/
   - Activer l'intégration WSL2 dans les paramètres Docker

### Dans WSL2 (Ubuntu)

```bash
# Mettre à jour le système
sudo apt update && sudo apt upgrade -y

# Installer les dépendances
sudo apt install -y \
  python3.11 \
  python3.11-venv \
  python3-pip \
  git \
  nmap
```

### Configuration

```bash
# Cloner le dépôt
git clone https://github.com/lucash/networkrecon.git
cd NetworkRecon/backend

# Environnement virtuel
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configuration
cd ..
cp .env.example .env
nano .env
```

### Lancer

```bash
# Via Docker (recommandé sur Windows)
docker compose up --build

# Ou en local
cd backend
source venv/bin/activate
uvicorn app.main:app --reload --port 8000
```

### Notes Windows

- Utilisez le système de fichiers WSL (`/home/...`) et non `/mnt/c/...` pour de meilleures performances
- L'accès aux ports peut nécessiter une configuration de pare-feu Windows
- MongoDB doit tourner dans Docker ou sur WSL, pas en natif Windows

---

## 5. Configuration de MongoDB

### Via Docker Compose (automatique)

Le fichier `docker-compose.yml` configure MongoDB automatiquement avec :
- Authentification root activée
- Volume persistant (`mongo_data`)
- Health check intégré
- Réseau interne isolé (`networkrecon-internal`)

### Configuration manuelle

Si vous utilisez MongoDB séparément :

```bash
# Créer l'utilisateur applicatif
mongosh -u admin -p <password> --authenticationDatabase admin

# Dans le shell MongoDB :
use networkrecon
db.createUser({
  user: "networkrecon_app",
  pwd: "<mot_de_passe_app>",
  roles: [
    { role: "readWrite", db: "networkrecon" }
  ]
})
```

### Collections MongoDB

NetworkRecon crée automatiquement les collections suivantes :

| Collection | Description |
|------------|-------------|
| `campaigns` | Campagnes de scan |
| `hosts` | Hôtes découverts |
| `vulnerability_scans` | Résultats de scan de vulnérabilités |
| `auth_test_campaigns` | Campagnes de test d'auth |
| `auth_test_results` | Résultats de tests d'auth |
| `reports` | Rapports générés |
| `credentials_files` | Fichiers de credentials uploadés |
| `network_ranges` | Plages réseau |

### Index recommandés

```javascript
// Performance des requêtes
db.hosts.createIndex({ "ip_address": 1 }, { unique: true })
db.hosts.createIndex({ "status": 1 })
db.hosts.createIndex({ "last_seen": -1 })
db.campaigns.createIndex({ "status": 1, "created_at": -1 })
db.vulnerability_scans.createIndex({ "vulnerabilities.cve.severity": 1 })
db.vulnerability_scans.createIndex({ "vulnerabilities.host_ip": 1 })
db.auth_test_results.createIndex({ "host_ip": 1, "timestamp": -1 })
```

---

## 6. Vérification de l'installation

### Test rapide

```bash
# 1. Vérifier que le backend répond
curl http://localhost:8000/health
# Résultat attendu : {"status":"ok"}

# 2. Vérifier la documentation API
# Ouvrir http://localhost:8000/docs dans un navigateur

# 3. Vérifier le frontend
# Ouvrir http://localhost:3000 dans un navigateur
```

### Test de scan complet

```bash
# Lancer un scan sur votre réseau local
# Remplacer 192.168.2.0/24 par votre plage réseau
curl -X POST "http://localhost:8000/api/scans/?name=Test+Installation" \
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
      "scan_type": "quick",
      "timeout": 120
    }
  }'

# Récupérer l'ID de la campagne depuis la réponse
# Puis vérifier le statut :
curl http://localhost:8000/api/scans/<campaign_id>/status
```

### Vérification Docker

```bash
# Lister les conteneurs actifs
docker compose ps

# Vérifier les logs
docker compose logs backend
docker compose logs frontend
docker compose logs mongodb

# Vérifier l'espace disque
docker system df
```

### Dépannage

| Problème | Solution |
|----------|----------|
| `Connection refused` sur le port 8000 | Vérifier que le backend est démarré : `docker compose logs backend` |
| `MongoDB not available` | Attendre le health check MongoDB : `docker compose ps` |
| `nmap: command not found` | Installer nmap : `sudo apt install nmap` |
| `Permission denied` sur le scan | Vérifier les droits d'exécution de nmap |
| Frontend vide | Vérifier la config CORS dans `.env` |

---

## Suivant

- [Documentation API](API.md)
- [Architecture technique](ARCHITECTURE.md)
- [Mapping MITRE ATT&CK](MITRE_MAPPING.md)
