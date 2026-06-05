# Documentation API — NetworkRecon

Base URL : `http://localhost:8000`

---

## Authentification

L'API utilise un token Bearer optionnel dans l'en-tête `Authorization` :

```
Authorization: Bearer <token>
```

> **Note** : L'authentification est actuellement optionnelle. Tous les endpoints sont accessibles sans token en mode développement.

---

## Table des matières

- [Scans (Campagnes)](#scans-campagnes)
- [Hosts (Hôtes)](#hosts-hôtes)
- [Vulnérabilités](#vulnérabilités)
- [MITRE ATT&CK](#mitre-attck)
- [Auth Tests](#auth-tests)
- [Reports (Rapports)](#reports-rapports)
- [Dashboard](#dashboard)
- [Codes d'erreur](#codes-derreur)
- [Rate limiting](#rate-limiting)

---

## Scans (Campagnes)

### Lister les campagnes

```
GET /api/scans/
```

**Paramètres de requête :**

| Paramètre | Type | Description |
|-----------|------|-------------|
| `status` | string | Filtrer par statut : `pending`, `running`, `completed`, `failed`, `cancelled` |
| `limit` | integer | Nombre max de résultats (1-200, défaut: 50) |
| `offset` | integer | Décalage pour la pagination (défaut: 0) |

**Réponse 200 :**

```json
[
  {
    "_id": "507f1f77bcf86cd799439012",
    "name": "Scan réseau principal",
    "description": "Scan complet du réseau interne",
    "targets": [
      {
        "ip_range": "192.168.2.0/24",
        "authorized": true,
        "target_list": []
      }
    ],
    "config": {
      "scan_type": "full",
      "ports_range": "1-1024",
      "timeout": 600,
      "rate_limit": 1000
    },
    "results": [],
    "created_at": "2026-06-03T09:00:00Z",
    "status": "pending"
  }
]
```

### Créer une campagne

```
POST /api/scans/
```

**Paramètres de requête :**

| Paramètre | Type | Obligatoire | Description |
|-----------|------|-------------|-------------|
| `name` | string | Oui | Nom de la campagne |
| `description` | string | Non | Description |

**Corps de la requête (JSON) :**

```json
{
  "targets": [
    {
      "ip_range": "192.168.2.0/24",
      "authorized": true,
      "target_list": ["192.168.2.1", "192.168.2.100"]
    }
  ],
  "config": {
    "scan_type": "full",
    "ports_range": "1-1024,8080,8443",
    "timeout": 600,
    "rate_limit": 1000
  }
}
```

**Types de scan disponibles :**

| `scan_type` | Description |
|-------------|-------------|
| `quick` | Scan rapide — hôtes up + ports communs |
| `full` | Scan complet — tous les ports (1-65535) |
| `stealth` | Scan discret — SYN half-open |

**Réponse 201 :**

```json
{
  "_id": "507f1f77bcf86cd799439012",
  "name": "Scan réseau principal",
  "description": "Scan complet du réseau interne",
  "targets": [
    {
      "ip_range": "192.168.2.0/24",
      "authorized": true,
      "target_list": []
    }
  ],
  "config": {
    "scan_type": "full",
    "ports_range": "1-1024",
    "timeout": 600,
    "rate_limit": 1000
  },
  "results": [],
  "created_at": "2026-06-03T09:00:00Z",
  "status": "pending"
}
```

### Récupérer une campagne

```
GET /api/scans/{campaign_id}
```

**Réponse 200 :** Objet `Campaign` complet.

**Réponse 404 :**

```json
{
  "detail": "Campagne non trouvée"
}
```

### Statut temps réel

```
GET /api/scans/{campaign_id}/status
```

**Réponse 200 :**

```json
{
  "campaign_id": "507f1f77bcf86cd799439012",
  "status": "running",
  "progress": 45.2,
  "hosts_found": 12,
  "results_count": 3
}
```

### Mettre en pause

```
POST /api/scans/{campaign_id}/pause
```

**Réponse 200 :**

```json
{
  "message": "Campagne mise en pause avec succès",
  "status": "paused"
}
```

### Reprendre

```
POST /api/scans/{campaign_id}/resume
```

**Réponse 200 :**

```json
{
  "message": "Campagne reprise avec succès",
  "status": "running"
}
```

### Annuler

```
POST /api/scans/{campaign_id}/cancel
```

**Réponse 200 :**

```json
{
  "message": "Campagne annulée avec succès",
  "status": "cancelled"
}
```

### Supprimer

```
DELETE /api/scans/{campaign_id}
```

**Réponse 204 :** Aucun contenu.

---

## Hosts (Hôtes)

### Lister les hôtes

```
GET /api/hosts/
```

**Paramètres de requête :**

| Paramètre | Type | Description |
|-----------|------|-------------|
| `status` | string | Filtrer : `up`, `down` |
| `scan_id` | string | Filtrer par scan |
| `campaign_id` | string | Filtrer par campagne |
| `limit` | integer | Max résultats (1-500, défaut: 50) |
| `offset` | integer | Décalage pagination |

**Réponse 200 :**

```json
[
  {
    "ip_address": "192.168.2.1",
    "hostname": "routeur.local",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "os_detection": "Linux 5.4 (RouterOS)",
    "status": "up",
    "ports": [
      {
        "number": 22,
        "protocol": "tcp",
        "state": "open",
        "service": "ssh",
        "version": "OpenSSH 8.9",
        "banner": "SSH-2.0-OpenSSH_8.9p1"
      },
      {
        "number": 80,
        "protocol": "tcp",
        "state": "open",
        "service": "http",
        "version": "nginx 1.18",
        "banner": "HTTP/1.1 200 OK"
      }
    ],
    "last_seen": "2026-06-03T10:00:00Z",
    "first_seen": "2026-06-03T09:00:00Z"
  }
]
```

### Récupérer un hôte par IP

```
GET /api/hosts/{ip}
```

**Exemple :** `GET /api/hosts/192.168.2.100`

**Réponse 200 :** Objet `HostInfo` complet.

**Réponse 404 :**

```json
{
  "detail": "Hôte 192.168.2.100 non trouvé"
}
```

### Ports d'un hôte

```
GET /api/hosts/{ip}/ports
```

**Réponse 200 :**

```json
[
  {
    "number": 22,
    "protocol": "tcp",
    "state": "open",
    "service": "ssh",
    "version": "OpenSSH 8.9",
    "banner": "SSH-2.0-OpenSSH_8.9p1"
  },
  {
    "number": 443,
    "protocol": "tcp",
    "state": "open",
    "service": "https",
    "version": "nginx 1.18",
    "banner": "HTTP/1.1 200 OK"
  }
]
```

### Vulnérabilités d'un hôte

```
GET /api/hosts/{ip}/vulnerabilities
```

**Réponse 200 :** Liste de objets `Vulnerability`.

### Mappings MITRE d'un hôte

```
GET /api/hosts/{ip}/mitre
```

**Réponse 200 :**

```json
[
  {
    "technique_id": "T1021.004",
    "technique_name": "Remote Services: SSH",
    "tactic": "Lateral Movement",
    "description": "Utilisation du protocole SSH pour se déplacer latéralement...",
    "url": "https://attack.mitre.org/techniques/T1021.004/"
  }
]
```

### Résultats d'authentification d'un hôte

```
GET /api/hosts/{ip}/auth-results
```

**Réponse 200 :** Liste de objets `AuthTestResult`.

---

## Vulnérabilités

### Résumé par sévérité

```
GET /api/vulnerabilities/summary
```

**Réponse 200 :**

```json
{
  "total": 42,
  "by_severity": {
    "critical": 5,
    "high": 12,
    "medium": 15,
    "low": 8,
    "info": 2
  },
  "affected_hosts": 8,
  "top_cves": [
    {
      "cve_id": "CVE-2023-1234",
      "count": 5,
      "severity": "critical"
    },
    {
      "cve_id": "CVE-2023-5678",
      "count": 3,
      "severity": "high"
    }
  ]
}
```

### Lister les vulnérabilités

```
GET /api/vulnerabilities/
```

**Paramètres de requête :**

| Paramètre | Type | Description |
|-----------|------|-------------|
| `severity` | string | Filtrer : `critical`, `high`, `medium`, `low`, `info` |
| `host_ip` | string | Filtrer par IP hôte |
| `service` | string | Filtrer par service |
| `limit` | integer | Max résultats (1-500, défaut: 50) |
| `offset` | integer | Décalage pagination |

**Réponse 200 :**

```json
[
  {
    "host_ip": "192.168.2.100",
    "port": 443,
    "service": "https",
    "cve": {
      "cve_id": "CVE-2023-1234",
      "description": "Vulnérabilité critique dans Apache Log4j",
      "severity": "critical",
      "cvss_score": 9.8,
      "affected_products": ["Apache Log4j 2.0-2.14.1"]
    },
    "mitre_mapping": {
      "technique_id": "T1190",
      "technique_name": "Exploit Public-Facing Application",
      "tactic": "Initial Access",
      "description": "Exploitation d'une application exposée publiquement",
      "url": "https://attack.mitre.org/techniques/T1190/"
    },
    "remediation": "Mettre à jour Log4j vers la version 2.17.0 ou supérieure"
  }
]
```

### Détail d'une CVE

```
GET /api/vulnerabilities/{cve_id}
```

**Exemple :** `GET /api/vulnerabilities/CVE-2023-1234`

**Réponse 200 :**

```json
{
  "cve_id": "CVE-2023-1234",
  "description": "Vulnérabilité de type injection SQL dans le composant XYZ",
  "severity": "critical",
  "cvss_score": 9.8,
  "affected_products": ["Apache Log4j 2.0-2.14.1", "Log4j 2.15.0"]
}
```

### Recherche de CVE par service

```
POST /api/vulnerabilities/lookup?service=ssh&version=8.9
```

**Paramètres de requête :**

| Paramètre | Type | Obligatoire | Description |
|-----------|------|-------------|-------------|
| `service` | string | Oui | Nom du service (ex: `ssh`, `http`) |
| `version` | string | Non | Version du service |

**Réponse 200 :** Liste de objets `CVE`.

---

## MITRE ATT&CK

### Lister les tactiques

```
GET /api/mitre/tactics
```

**Réponse 200 :**

```json
[
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact"
]
```

### Lister les techniques

```
GET /api/mitre/techniques
```

**Paramètres de requête :**

| Paramètre | Type | Description |
|-----------|------|-------------|
| `tactic` | string | Filtrer par tactique (ex: `Initial Access`) |
| `service` | string | Filtrer par service (ex: `ssh`) |

**Réponse 200 :**

```json
[
  {
    "technique_id": "T1021.004",
    "technique_name": "Remote Services: SSH",
    "tactic": "Lateral Movement",
    "description": "Utilisation du protocole SSH pour se déplacer latéralement...",
    "url": "https://attack.mitre.org/techniques/T1021.004/"
  }
]
```

### Détail d'une technique

```
GET /api/mitre/techniques/{technique_id}
```

**Exemple :** `GET /api/mitre/techniques/T1190`

**Réponse 200 :**

```json
{
  "technique_id": "T1190",
  "technique_name": "Exploit Public-Facing Application",
  "tactic": "Initial Access",
  "description": "Exploitation de vulnérabilités dans une application web exposée publiquement",
  "url": "https://attack.mitre.org/techniques/T1190/",
  "related_services": ["http", "https"]
}
```

### Parcours d'attaque identifiés

```
GET /api/mitre/attack-paths
```

**Paramètres de requête :**

| Paramètre | Type | Description |
|-----------|------|-------------|
| `campaign_id` | string | Filtrer par campagne |

**Réponse 200 :**

```json
[
  {
    "path_id": "path_001",
    "name": "Initial Access via T1190",
    "description": "Parcours d'attaque utilisant la technique T1190",
    "techniques": ["T1190"],
    "hosts": ["192.168.2.100", "192.168.2.101"],
    "count": 5
  }
]
```

### Export STIX 2.1

```
GET /api/mitre/export/stix
```

**Réponse 200 :** Bundle STIX 2.1

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
      "description": "Exploitation de vulnérabilités dans une application web exposée publiquement",
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

## Auth Tests

### Lancer une campagne

```
POST /api/auth-tests/
```

**Paramètres de requête :**

| Paramètre | Type | Obligatoire | Description |
|-----------|------|-------------|-------------|
| `name` | string | Oui | Nom de la campagne |
| `targets` | list[string] | Oui | IPs cibles |
| `service_type` | string | Non | Type de service (défaut: `ssh`) |
| `credentials_file` | string | Non | Nom du fichier credentials |

**Types de services supportés :**

`ssh`, `ftp`, `smb`, `rdp`, `http`, `https`, `mysql`, `postgresql`, `redis`, `mongodb`

**Réponse 201 :**

```json
{
  "_id": "507f1f77bcf86cd799439014",
  "name": "Test d'authentification SSH",
  "targets": ["192.168.2.100", "192.168.2.101"],
  "config": {
    "service_type": "ssh",
    "credentials_file": null,
    "max_attempts": 5,
    "delay_between": 1.0
  },
  "results": [],
  "status": "pending",
  "created_at": "2026-06-03T09:00:00Z"
}
```

### Lister les campagnes

```
GET /api/auth-tests/
```

**Paramètres de requête :**

| Paramètre | Type | Description |
|-----------|------|-------------|
| `status` | string | Filtrer par statut |
| `limit` | integer | Max résultats |
| `offset` | integer | Décalage |

### Résultats d'une campagne

```
GET /api/auth-tests/{campaign_id}
```

### Résultats par hôte

```
GET /api/auth-tests/host/{ip}
```

**Réponse 200 :**

```json
[
  {
    "host_ip": "192.168.2.100",
    "port": 22,
    "service": "ssh",
    "credential_used": "admin:***",
    "success": true,
    "timestamp": "2026-06-03T10:00:00Z",
    "error_message": null
  }
]
```

### Uploader un fichier de credentials

```
POST /api/auth-tests/credentials
```

**Corps :** `multipart/form-data`

| Champ | Type | Description |
|-------|------|-------------|
| `file` | file | Fichier au format `username:password` (un par ligne) |
| `name` | string | Nom personnalisé |

**Formats acceptés :** `.txt`, `.csv`, `.lst`

**Réponse 200 :**

```json
{
  "message": "Fichier uploadé avec succès",
  "filename": "ssh_credentials.txt",
  "credentials_count": 150
}
```

---

## Reports (Rapports)

### Générer un rapport

```
POST /api/reports/generate
```

**Paramètres de requête :**

| Paramètre | Type | Obligatoire | Description |
|-----------|------|-------------|-------------|
| `campaign_id` | string | Oui | ID de la campagne |
| `export_format` | string | Non | `json` (défaut), `csv`, `html`, `pdf` |

**Réponse 201 :**

```json
{
  "_id": "507f1f77bcf86cd799439015",
  "campaign_id": "507f1f77bcf86cd799439012",
  "generated_at": "2026-06-03T10:30:00Z",
  "summary": {
    "total_hosts": 25,
    "total_services": 150,
    "total_vulnerabilities": 42,
    "by_severity": {
      "critical": 5,
      "high": 12,
      "medium": 15,
      "low": 8,
      "info": 2
    },
    "scan_duration": 3600.5
  },
  "content": {
    "hosts": [
      {
        "ip": "192.168.2.100",
        "hostname": "webserver.local",
        "services": 8,
        "vulnerabilities": 3
      }
    ],
    "top_vulnerabilities": [
      {
        "cve_id": "CVE-2023-1234",
        "severity": "critical",
        "affected_hosts": 5
      }
    ],
    "recommendations": [
      "Mettre à jour Log4j sur 5 serveurs",
      "Configurer le pare-feu pour le port 3389"
    ]
  },
  "export_format": "json",
  "title": "Rapport de scan réseau - Juin 2026",
  "description": "Rapport complet du scan du réseau interne",
  "generated_by": "admin@networkrecon.local"
}
```

### Récupérer un rapport

```
GET /api/reports/{report_id}
```

### Exporter un rapport

```
GET /api/reports/{report_id}/export/{format}
```

**Formats :** `pdf`, `csv`, `json`, `html`

**Réponse :** Fichier en streaming avec headers `Content-Disposition`.

### Rapports d'une campagne

```
GET /api/reports/campaign/{campaign_id}
```

### Supprimer un rapport

```
DELETE /api/reports/{report_id}
```

**Réponse 204 :** Aucun contenu.

---

## Dashboard

### Statistiques globales

```
GET /api/dashboard/stats
```

**Réponse 200 :**

```json
{
  "total_campaigns": 15,
  "running_campaigns": 2,
  "total_hosts": 128,
  "total_vulnerabilities": 42,
  "critical_vulns": 5,
  "high_vulns": 12,
  "medium_vulns": 15,
  "low_vulns": 8,
  "auth_tests_completed": 7
}
```

### Répartition par sévérité

```
GET /api/dashboard/severity-distribution
```

**Réponse 200 :**

```json
{
  "critical": 5,
  "high": 12,
  "medium": 15,
  "low": 8,
  "info": 2,
  "total": 42
}
```

### Top vulnérabilités

```
GET /api/dashboard/top-vulns
```

**Paramètres de requête :**

| Paramètre | Type | Description |
|-----------|------|-------------|
| `limit` | integer | Nombre de vulns (défaut: 10) |

**Réponse 200 :**

```json
[
  {
    "cve_id": "CVE-2023-1234",
    "severity": "critical",
    "count": 5,
    "affected_hosts": ["192.168.2.100", "192.168.2.101"]
  }
]
```

### Vue réseau

```
GET /api/dashboard/network-overview
```

**Réponse 200 :**

```json
{
  "total_hosts": 25,
  "hosts_up": 20,
  "hosts_down": 5,
  "top_services": [
    {"service": "ssh", "count": 15},
    {"service": "http", "count": 12},
    {"service": "https", "count": 10}
  ],
  "os_distribution": [
    {"os": "Linux", "count": 18},
    {"os": "Windows", "count": 5},
    {"os": "Unknown", "count": 2}
  ]
}
```

### Dernières campagnes

```
GET /api/dashboard/recent-campaigns
```

**Paramètres de requête :**

| Paramètre | Type | Description |
|-----------|------|-------------|
| `limit` | integer | Nombre de campagnes (défaut: 5) |

---

## Codes d'erreur

| Code | Description |
|------|-------------|
| `200` | Succès |
| `201` | Créé avec succès |
| `204` | Succès (sans contenu) |
| `400` | Requête invalide (format CVE, paramètres manquants) |
| `404` | Ressource non trouvée |
| `422` | Erreur de validation Pydantic |
| `500` | Erreur interne du serveur |
| `503` | Service indisponible (API NVD, MongoDB) |

**Format d'erreur :**

```json
{
  "detail": "Description de l'erreur"
}
```

---

## Rate limiting

| Endpoint | Limite | Fenêtre |
|----------|--------|---------|
| `/api/scans/` (POST) | 10 requêtes | Par minute |
| `/api/vulnerabilities/lookup` | 30 requêtes | Par minute |
| `/api/auth-tests/` (POST) | 5 requêtes | Par minute |
| Autres endpoints | 100 requêtes | Par minute |

> En cas de dépassement, l'API retourne un code `429 Too Many Requests`.
