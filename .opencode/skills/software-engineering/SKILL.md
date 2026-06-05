---
name: "software-engineering"
description: "Directives de développement backend FastAPI et Async Python."
---

# Compétences de Développement (Application Réseau)

- **Architecture :** Implémente une architecture modulaire. Les routes API (FastAPI) doivent être séparées de la logique d'orchestration (scans).
- **Asynchronisme :** Les requêtes réseau (scan de ports, requêtes API externes) doivent impérativement utiliser `asyncio` pour ne pas bloquer l'Event Loop.
- **Base de données :** Utilise `Motor` (le driver asynchrone officiel MongoDB) pour interagir avec la base de données. Structure les modèles de données avec Pydantic.
