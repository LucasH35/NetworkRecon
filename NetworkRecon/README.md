# NetworkRecon

**Outil de reconnaissance réseau asynchrone** pour l'analyse de sécurité offensive.

NetworkRecon scanne les réseaux, identifie les services, détecte les vulnérabilités et mappe les résultats vers le framework **MITRE ATT&CK**. Le projet inclut une machine cible vulnérable (`target-lab`) pour tester les attaques (brute force, SQLMap).

> **Avertissement** : Cet outil est conçu pour un usage éducatif et légal uniquement. Ne jamais scanner un réseau sans autorisation explicite.

---

## Objectif du projet

Développer un outil de reconnaissance réseau complet conteneurisé avec Docker, capable de :

1. **Scanner** des réseaux et découvrir les hôtes actifs
2. **Identifier** les services et versions (SSH, HTTP, MySQL, etc.)
3. **Détecter** les vulnérabilités connues (CVE)
4. **Mapper** les résultats vers les techniques MITRE ATT&CK
5. **Tester** la robustesse des mots de passe (brute force)
6. **Analyser** les injections SQL via SQLMap
7. **Générer** des rapports de audit complets

---

## Prérequis

| Composant | Version minimale | Installation |
|-----------|-----------------|--------------|
| Docker | 20.10+ | [docker.com](https://docs.docker.com/get-docker/) |
| Docker Compose | 2.0+ | Inclus avec Docker Desktop |
| Git | 2.0+ | [git-scm.com](https://git-scm.com/) |

**Espace disque** : ~2 Go (images Docker)
**RAM** : 4 Go minimum recommandés

---

## Installation et lancement

### 1. Cloner le dépôt

```bash
git clone https://github.com/LucasH35/NetworkRecon.git
cd NetworkRecon
```

### 2. Lancer l'ensemble des services

```bash
docker compose up -d
```

### 3. Vérifier le démarrage

```bash
docker compose ps
```

**Résultat attendu** : 4 conteneurs en état `Up` ou `healthy`

| Conteneur | Port | Description |
|-----------|------|-------------|
| networkrecon-frontend | 3000 | Interface web |
| networkrecon-backend | 8000 | API REST |
| networkrecon-mongo | 27017 | Base de données |
| target-lab | 8080, 2222, 3307 | Machine cible vulnérable |

---

## Accès aux interfaces

| Service | URL | Description |
|---------|-----|-------------|
| **Frontend** | http://localhost:3000 | Interface web principale |
| **API Docs** | http://localhost:8000/docs | Swagger UI (test API) |
| **Target Lab** | http://localhost:8080 | Page de la machine cible |

---

## Procédure de test

### Test 1 : Scan réseau

1. Ouvrir http://localhost:3000
2. Cliquer sur **"Nouveau scan"**
3. Configurer :
   - Nom : `Test target-lab`
   - Cible : **`target-lab`** (ou `172.19.0.2`)
   - Type : **QUICK**
4. Cliquer sur **"Lancer le scan"**
5. Attendre la fin du scan (~30 secondes)

**Résultat attendu** :
- 1 hôte découvert (`target-lab`)
- 3 ports ouverts : 22 (SSH), 80 (HTTP), 3306 (MySQL)
- Système d'exploitation : Ubuntu 22.04

### Test 2 : Détection de vulnérabilités

1. Aller dans **"Hôtes découverts"**
2. Cliquer sur `target-lab`
3. Onglet **"Vulnérabilités"**

**Résultat attendu** :
- Plusieurs CVE détectés (OpenSSH, Nginx, MySQL)
- Sévérités : Critical, High, Medium, Low

### Test 3 : Brute Force SSH

1. Onglet **"Attaque des services"**
2. Service SSH (port 22) : cliquer **"Attaquer"**
3. Configurer : durée max 60 secondes
4. Lancer l'attaque

**Résultat attendu** :
- Credentials trouvés : `root:target2025`, `admin:admin2025`
- Statistiques : tentatives, succès, échecs

### Test 4 : SQLMap (injection SQL)

1. Onglet **"Attaque des services"**
2. Service HTTP (port 80) : cliquer **"SQLMap"**
3. Configurer : Level 2, Risk 1, Forms activé
4. Lancer le scan

**Résultat attendu** :
- Injections SQL détectées sur `/api/users` et `/api/login`
- Bases de données découvertes : `webapp`
- Tables : `users`, `articles`, `settings`

### Test 5 : Mapping MITRE ATT&CK

1. Onglet **"MITRE ATT&CK"**

**Résultat attendu** :
- Techniques associées aux services détectés
- Tactiques : Reconnaissance, Initial Access, Credential Access

### Test 6 : Génération de rapport

1. Cliquer sur **"Rapport"**
2. Télécharger le fichier `.doc`

**Résultat attendu** :
- Document Word avec 7 sections :
  1. Informations machine
  2. Services découverts
  3. Vulnérabilités
  4. Credentials trouvés
  5. SQLMap - Injections SQL
  6. Cyber Kill Chain
  7. MITRE ATT&CK détail

---

## Résultats attendus

### Dashboard

```
Hôtes découverts : 1
Ports ouverts : 3
Vulnérabilités : 15+
Techniques MITRE : 10+
```

### Host `target-lab`

| Paramètre | Valeur |
|-----------|--------|
| IP | 172.19.0.2 |
| Hostname | target-lab |
| OS | Ubuntu 22.04 |
| Ports | 22 (SSH), 80 (HTTP), 3306 (MySQL) |

### Services détectés

| Port | Service | Version |
|------|---------|---------|
| 22 | SSH | OpenSSH 8.9 |
| 80 | HTTP | Nginx 1.18 + Flask |
| 3306 | MySQL | MySQL 8.0 |

### Credentials valides

| Utilisateur | Mot de passe | Rôle |
|-------------|--------------|------|
| root | target2025 | Admin SSH |
| admin | admin2025 | Admin webapp |
| deploy | deploy2025 | Utilisateur |
| webapp | webapp2025 | Utilisateur |

### Vulnérabilités SQL détectées

| Endpoint | Type | Paramètre |
|----------|------|-----------|
| `/api/users?search=` | SQL Injection | `search` |
| `/api/login` | SQL Injection | `username`, `password` |

---

## Commandes Docker utiles

```bash
# Démarrer
docker compose up -d

# Arrêter
docker compose down

# Rebuild complet
docker compose up -d --build

# Voir les logs
docker compose logs -f backend
docker compose logs -f target-lab

# Vérifier les conteneurs
docker compose ps

# Accéder à un conteneur
docker exec -it target-lab bash
docker exec -it networkrecon-backend bash
```

---

## Structure du projet

```
NetworkRecon/
├── backend/                    # API FastAPI (Python)
│   ├── app/
│   │   ├── main.py            # Point d'entrée
│   │   ├── models/            # Modèles Pydantic
│   │   ├── routes/            # Routes API
│   │   ├── services/          # Logique métier
│   │   └── scanners/          # Modules nmap
│   ├── tests/                 # Tests unitaires
│   └── Dockerfile
├── frontend/                   # SPA ( vanilla JS + Tailwind)
│   ├── src/
│   │   ├── index.html
│   │   └── js/                # Modules JS
│   └── Dockerfile
├── target-machine/             # Machine cible vulnérable
│   ├── app/                   # Flask (API vulnérable)
│   ├── mysql/                 # Seed BDD
│   ├── ssh/                   # Config SSH
│   └── Dockerfile
├── docker-compose.yml          # Orchestration 4 services
└── .env                        # Configuration
```

---

## Technologies utilisées

| Composant | Technologie | Version |
|-----------|-------------|---------|
| Backend | Python + FastAPI | 3.11 |
| Frontend | Vanilla JS + Tailwind CSS | - |
| Base de données | MongoDB | 4.4 |
| Scan réseau | nmap | 7.95 |
| SQL injection | SQLMap | 1.10 |
| Machine cible | Ubuntu + Flask + MySQL | 22.04 |
| Conteneurisation | Docker + Docker Compose | - |

---

## Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

## Auteurs

- **Lucash** — Développeur principal
