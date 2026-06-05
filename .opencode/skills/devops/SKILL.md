---
name: "devops"
description: "Directives pour la conteneurisation et l'isolation réseau."
---

# Compétences Infrastructure & Docker

- **Docker Compose :** Construis un `docker-compose.yml` multi-services. Il doit inclure le backend (FastAPI), la base de données (MongoDB) et le frontend (Nginx/Tailwind).
- **Isolation Réseau :** MongoDB doit se trouver sur un réseau Docker interne non exposé au réseau hôte (aucun port binding `27017:27017`), seul FastAPI doit pouvoir y accéder.
- **Optimisation :** Utilise des images Docker "Multi-stage build" et "distroless" ou "alpine" pour réduire la surface d'attaque et la taille de l'image de production.
