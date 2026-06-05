# Guide de contribution — NetworkRecon

Merci de vouloir contribuer à NetworkRecon ! Ce document explique le processus de contribution.

---

## Branches Git

| Branche | Usage |
|---------|-------|
| `main` | Branche de production, toujours stable |
| `develop` | Branche de développement, intégration des features |
| `feature/*` | Nouvelles fonctionnalités |
| `bugfix/*` | Corrections de bugs |
| `hotfix/*` | Corrections urgentes sur production |

### Workflow

```
main ◄──── hotfix/* ◄──── develop ◄──── feature/*
                              │
                              └──► bugfix/*
```

### Créer une branche

```bash
# Feature
git checkout develop
git pull origin develop
git checkout -b feature/nouvelle-fonctionnalite

# Bugfix
git checkout develop
git pull origin develop
git checkout -b bugfix/correction-bug
```

---

## Convention de commits

Nous utilisons les [Conventional Commits](https://www.conventionalcommits.org/).

### Format

```
<type>(<scope>): <description>

[corps optionnel]

[footer optionnel]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | Nouvelle fonctionnalité |
| `fix` | Correction de bug |
| `docs` | Documentation |
| `style` | Formatage (sans changement de logique) |
| `refactor` | Refactorisation |
| `perf` | Amélioration de performance |
| `test` | Ajout/modification de tests |
| `build` | Dépendances, Dockerfile |
| `ci` | CI/CD |
| `chore` | Maintenance |

### Scope

| Scope | Description |
|-------|-------------|
| `api` | Routes API |
| `models` | Modèles Pydantic |
| `services` | Logique métier |
| `scanners` | Modules de scan |
| `frontend` | Interface web |
| `docker` | Conteneurisation |
| `docs` | Documentation |

### Exemples

```bash
# Feature
git commit -m "feat(api): add endpoint for network range management"

# Bugfix
git commit -m "fix(services): handle timeout in vulnerability scanner"

# Documentation
git commit -m "docs(api): add examples for scan creation endpoint"

# Refactor
git commit -m "refactor(services): extract MITRE mapping to separate module"
```

---

## Processus de Pull Request

### 1. Préparer

```bash
# Synchroniser avec develop
git checkout develop
git pull origin develop

# Créer la branche
git checkout -b feature/ma-fonctionnalite

# Développer
# ...

# Linter et tester
cd backend
ruff check app/
pytest tests/
```

### 2. Committer

```bash
git add .
git commit -m "feat(api): add my new feature"
git push origin feature/ma-fonctionnalite
```

### 3. Créer la PR

- **Titre** : Description concise en English ou Français
- **Corps** : Détails du changement, motivation, impacts
- **Labels** : `feature`, `bugfix`, `documentation`, etc.
- **Assignee** : Vous-même
- **Reviewers** : l'équipe

### 4. Template de PR

```markdown
## Description
Description concise du changement.

## Type de changement
- [ ] Nouvelle fonctionnalité
- [ ] Correction de bug
- [ ] Documentation
- [ ] Refactorisation
- [ ] Autre

## Comment tester
Étapes pour tester les changements.

## Capture d'écran (si applicable)
Ajouter des captures pour les changements visuels.

## Checklist
- [ ] Code conform au style du projet
- [ ] Tests ajoutés/modifiés
- [ ] Documentation mise à jour
- [ ] Pas de secrets ou clés API commités
```

---

## Tests requis

### Backend

```bash
cd backend

# Tous les tests
pytest

# Tests avec couverture
pytest --cov=app --cov-report=html

# Tests spécifiques
pytest tests/test_vulnerability_scanner.py
pytest tests/test_mitre_mapper.py
pytest tests/test_auth_tester.py
pytest tests/test_report_generator.py
```

### Linting

```bash
# Ruff (linter + formatter)
ruff check app/
ruff format app/

# Vérification de type (si configuré)
mypy app/
```

### Frontend

```bash
# Pas de test automatisé pour l'instant
# Vérifier manuellement dans le navigateur
```

---

## Code style

### Python (Backend)

- **Formatter** : Ruff (compatible Black)
- **Line length** : 88 caractères
- **Import ordering** : stdlib → third-party → local
- **Type hints** : Obligatoires sur les fonctions publiques
- **Docstrings** : Format Google/Numpy pour les fonctions et classes

```python
async def get_host_by_ip(
    ip: str,
    user: Optional[str] = Depends(get_current_user),
) -> HostInfo:
    """Récupère les informations d'un hôte par son adresse IP.

    Args:
        ip: Adresse IP de l'hôte à rechercher.
        user: Utilisateur authentifié (optionnel).

    Returns:
        Informations complètes de l'hôte.

    Raises:
        HTTPException: Si l'hôte n'existe pas (404).
    """
    db = await get_database()
    doc = await db.hosts.find_one({"ip_address": ip})
    if not doc:
        raise HTTPException(status_code=404, detail=f"Hôte {ip} non trouvé")
    doc["_id"] = str(doc["_id"])
    return HostInfo(**doc)
```

### JavaScript (Frontend)

- **Style** : ES6+
- **Formatage** : Prettier (si configuré)
- **Nomenclature** : camelCase pour les variables/fonctions, PascalCase pour les classes

```javascript
// Bon
async function fetchCampaigns(limit = 50) {
  const response = await api.get('/api/scans/', { limit });
  return response.data;
}

// À éviter
async function Fetch_Campaigns() { ... }
```

### Git

- **Messages** : Conventional Commits (voir ci-dessus)
- **Branches** : Noms en kebab-case (`feature/add-auth`)
- **Fichiers** : snake_case pour Python, kebab-case pour le frontend

---

## Structure des fichiers

```
backend/
├── app/
│   ├── models/      # Un fichier par entité
│   ├── routes/      # Un fichier par groupe d'endpoints
│   ├── services/    # Un fichier par service métier
│   ├── scanners/    # Un fichier par type de scan
│   └── utils/       # Utilitaires partagés
└── tests/           # Un test par service/route
    ├── test_<service>.py
    └── ...
```

---

## Développement local

### Prérequis

```bash
# Python 3.11+
python3.11 --version

# MongoDB (via Docker)
docker run -d -p 27017:27017 mongo:7
```

### Setup

```bash
git clone https://github.com/lucash/networkrecon.git
cd NetworkRecon/backend

python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Lancer le serveur de développement
uvicorn app.main:app --reload --port 8000
```

### Tester

```bash
# Tous les tests
pytest

# Un seul fichier
pytest tests/test_mitre_mapper.py -v

# Avec couverture
pytest --cov=app --cov-report=term-missing
```

---

## Questions ?

Ouvrez une [issue](https://github.com/lucash/networkrecon/issues) pour toute question ou suggestion.
