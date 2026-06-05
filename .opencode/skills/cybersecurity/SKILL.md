---
name: "cybersecurity"
description: "Règles métier pour l'analyse de vulnérabilités et MITRE ATT&CK."
---

# Compétences Cyber & Reconnaissance

- **Formatage CVE / MITRE :** Veille à ce que chaque service identifié soit formaté pour pouvoir être croisé avec des bases de données de type NVD (National Vulnerability Database).
- **Règles d'Engagement (Phase 2) :** Tout script effectuant une action de type "Validation d'accès" (brute-force ou test d'identifiants autorisés) doit inclure un système strict de "Rate Limiting" et vérifier si la cible est explicitement marquée comme `authorized: true` dans la base.
- **Sécurité des données :** Les mots de passe et identifiants stockés dans MongoDB pour les tests doivent être chiffrés.
