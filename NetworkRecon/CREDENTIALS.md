# Identifiants et Accès - NetworkRecon Lab

## Machine cible (192.168.2.100)

### SSH (port 22 / 2222 depuis localhost)
| Utilisateur | Mot de passe       | Privilèges |
|-------------|--------------------|------------|
| root        | target2025         | root       |
| admin       | admin2025          | sudo       |
| deploy      | deploy2025         | sudo       |
| webapp      | webapp2025         | utilisateur |

### HTTP (port 80 / 8080 depuis localhost)
- URL: http://192.168.2.100
- Page d'accueil: http://192.168.2.100/
- API debug: http://192.168.2.100/info

### MySQL (port 3306 / 3307 depuis localhost)
| Utilisateur | Mot de passe        | Base de données |
|-------------|---------------------|-----------------|
| root        | rootpassword2025    | *               |
| webapp      | webapppass2025      | webapp          |

### API vulnérables (Flask)
- Requête: `GET /api/users?search=' OR 1=1--` (SQL injection)
- Requête: `POST /api/exec` avec `{"cmd": "id"}` (RCE)
- Requête: `GET /api/articles/1` (IDOR)
- Requête: `GET /api/settings` (secrets exposés)
- Requête: `POST /api/login` brute force (pas de rate limit)

---

## NetworkRecon Infrastructure

### MongoDB (container: networkrecon-mongo)
- Port: 27017 (interne uniquement, pas bindé à l'hôte)
- Base de données: `networkrecon`
- Authentification: Aucune (lab)
- Connexion: `mongodb://mongodb:27017/networkrecon`

### Backend API (container: networkrecon-backend)
- URL: http://localhost:8000
- Swagger: http://localhost:8000/docs
- Health: http://localhost:8000/api/health
- Workers: 4 (uvicorn)

### Frontend (container: networkrecon-frontend)
- URL: http://localhost:3000
- Serveur: nginx:alpine

---

## Réseau

| Service       | IP              | Port mapping       |
|---------------|-----------------|--------------------|
| Target SSH    | 192.168.2.100   | 2222 → 22          |
| Target HTTP   | 192.168.2.100   | 8080 → 80          |
| Target MySQL  | 192.168.2.100   | 3307 → 3306        |
| Backend API   | localhost       | 8000               |
| Frontend      | localhost       | 3000               |
| MongoDB       | interne         | 27017 (non exposé) |

### Interface macvlan (hôte)
- Interface: macvlan0
- IP: 192.168.2.99/32
- Route vers target: via macvlan0

---

## Credentials de scan (brute force)

### Default credentials (auth_tester.py)
```
lucash:Bonjour2025*
root:root
admin:admin
root:toor
admin:password
root:123456
...
```

### SSH cible testé
- Host: 192.168.2.141
- User: lucash
- Pass: Bonjour2025*
- Note: Connexion échoue (paramiko "Error reading SSH protocol banner")

---

## Git
- Repo: git@github.com:LucasH35/NetworkRecon.git
- Ancien nom: Scan-Bruteforce

---

*Dernière mise à jour: 2026-06-09*
