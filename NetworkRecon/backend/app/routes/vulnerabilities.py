"""Routes API pour la gestion des vulnérabilités réseau."""

from typing import Optional, Dict, List

from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.models.vulnerability import CVE, Vulnerability, VulnerabilityScanResult, Severity
from app.services.vulnerability_scanner import VulnerabilityScanner
from app.utils.database import get_database

router = APIRouter()
security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[str]:
    """Extrait l'utilisateur actuel depuis le token Bearer."""
    if credentials is None:
        return None
    return credentials.credentials


@router.get(
    "/summary",
    response_model=dict,
    summary="Résumé des vulnérabilités par sévérité",
    description="Retourne un résumé global des vulnérabilités regroupées par niveau de sévérité.",
    tags=["vulnerabilities"],
)
async def get_vulnerability_summary(
    user: Optional[str] = Depends(get_current_user),
):
    """Retourne un résumé global des vulnérabilités par sévérité."""
    db = await get_database()
    col = db["archived_vulnerabilities"]

    # Compter par sévérité
    severity_pipeline = [
        {"$group": {"_id": "$cve.severity", "count": {"$sum": 1}}},
    ]
    severity_counts = {}
    async for doc in col.aggregate(severity_pipeline):
        severity_counts[doc["_id"]] = doc["count"]

    # Compter les hôtes affectés
    hosts_pipeline = [
        {"$group": {"_id": "$host_ip"}},
        {"$count": "total"},
    ]
    hosts_count = 0
    async for doc in col.aggregate(hosts_pipeline):
        hosts_count = doc.get("total", 0)

    # Top CVEs
    cve_pipeline = [
        {"$group": {
            "_id": "$cve.cve_id",
            "count": {"$sum": 1},
            "severity": {"$first": "$cve.severity"},
        }},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    top_cves = []
    async for doc in col.aggregate(cve_pipeline):
        top_cves.append({
            "cve_id": doc["_id"],
            "count": doc["count"],
            "severity": doc["severity"],
        })

    total = sum(severity_counts.values())

    return {
        "total": total,
        "by_severity": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "info": severity_counts.get("info", 0),
        },
        "affected_hosts": hosts_count,
        "top_cves": top_cves,
    }


@router.post(
    "/lookup",
    response_model=list[CVE],
    summary="Recherche de CVE par service/version",
    description="Recherche les CVE connues pour un service et une version spécifiques.",
    tags=["vulnerabilities"],
)
async def lookup_cve(
    service: str = Query(..., description="Nom du service (ex: ssh, http)"),
    version: str = Query("", description="Version du service (ex: 8.9)"),
    user: Optional[str] = Depends(get_current_user),
):
    """Recherche les CVE connues pour un service et une version."""
    db = await get_database()
    scanner = VulnerabilityScanner(db)
    cves = await scanner.lookup_cve(service, version)
    return cves


@router.get(
    "/{cve_id}",
    response_model=CVE,
    summary="Détail d'une CVE",
    description="Retourne les informations détaillées d'une CVE spécifique.",
    tags=["vulnerabilities"],
)
async def get_cve_details(
    cve_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Récupère les détails complets d'une CVE via l'API NVD."""
    import re
    pattern = r"^CVE-\d{4}-\d{4,}$"
    if not re.match(pattern, cve_id):
        raise HTTPException(status_code=400, detail=f"Format CVE invalide: {cve_id}")

    db = await get_database()
    scanner = VulnerabilityScanner(db)

    try:
        cve = await scanner.get_vulnerability_details(cve_id)
        return cve
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get(
    "/",
    response_model=list[Vulnerability],
    summary="Lister toutes les vulnérabilités",
    description="Retourne la liste de toutes les vulnérabilités détectées avec pagination.",
    tags=["vulnerabilities"],
)
async def list_vulnerabilities(
    severity: Optional[Severity] = Query(None, description="Filtrer par sévérité"),
    host_ip: Optional[str] = Query(None, description="Filtrer par IP d'hôte"),
    service: Optional[str] = Query(None, description="Filtrer par service"),
    campaign_id: Optional[str] = Query(None, description="Filtrer par campagne"),
    limit: int = Query(50, ge=1, le=500, description="Nombre maximum de résultats"),
    offset: int = Query(0, ge=0, description="Décalage pour la pagination"),
    user: Optional[str] = Depends(get_current_user),
):
    """Liste toutes les vulnérabilités détectées."""
    db = await get_database()
    col = db["archived_vulnerabilities"]

    query = {}
    if host_ip:
        query["host_ip"] = host_ip
    if severity:
        query["cve.severity"] = severity.value
    if service:
        query["service"] = service
    if campaign_id:
        query["campaign_id"] = campaign_id

    all_vulns = []
    cursor = col.find(query).sort("archived_at", -1).skip(offset).limit(limit)
    async for doc in cursor:
        try:
            # Remove MongoDB internal fields
            doc.pop("_id", None)
            doc.pop("campaign_id", None)
            doc.pop("archived_at", None)
            vuln = Vulnerability(**doc)
            all_vulns.append(vuln)
        except Exception:
            continue

        if len(all_vulns) >= limit:
            break

    return all_vulns
