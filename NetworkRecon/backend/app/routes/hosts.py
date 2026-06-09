"""Routes API pour la gestion des hôtes réseau."""

from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.models.host import Host, HostCreate, HostUpdate, HostInfo, PortInfo
from app.models.vulnerability import Vulnerability, MitreMapping
from app.models.auth_test import AuthTestResult
from app.services.host_service import HostService
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
    "/",
    response_model=list[HostInfo],
    summary="Lister tous les hôtes découverts",
    description="Retourne la liste des hôtes réseau découverts avec pagination et filtrage.",
    tags=["hosts"],
)
async def list_hosts(
    status: Optional[str] = Query(None, description="Filtrer par statut (up/down)"),
    scan_id: Optional[str] = Query(None, description="Filtrer par scan_id"),
    campaign_id: Optional[str] = Query(None, description="Filtrer par campagne"),
    limit: int = Query(50, ge=1, le=500, description="Nombre maximum de résultats"),
    offset: int = Query(0, ge=0, description="Décalage pour la pagination"),
    user: Optional[str] = Depends(get_current_user),
):
    """Liste tous les hôtes réseau découverts."""
    db = await get_database()
    query = {}
    if status:
        query["status"] = status
    if scan_id:
        query["scan_id"] = scan_id
    if campaign_id:
        query["campaign_id"] = campaign_id

    cursor = db.hosts.find(query).sort("last_seen", -1).skip(offset).limit(limit)
    hosts = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        hosts.append(HostInfo(**doc))
    return hosts


@router.get(
    "/{ip}",
    response_model=HostInfo,
    summary="Récupérer un hôte par IP",
    description="Retourne les informations détaillées d'un hôte réseau par son adresse IP.",
    tags=["hosts"],
)
async def get_host_by_ip(
    ip: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Récupère les informations d'un hôte par son adresse IP."""
    db = await get_database()
    doc = await db.hosts.find_one({"ip_address": ip})
    if not doc:
        raise HTTPException(status_code=404, detail=f"Hôte {ip} non trouvé")
    doc["_id"] = str(doc["_id"])
    return HostInfo(**doc)


@router.get(
    "/{ip}/ports",
    response_model=list[PortInfo],
    summary="Récupérer les ports d'un hôte",
    description="Retourne la liste des ports ouverts et services détectés sur un hôte.",
    tags=["hosts"],
)
async def get_host_ports(
    ip: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Récupère les ports ouverts d'un hôte spécifique."""
    db = await get_database()
    doc = await db.hosts.find_one({"ip_address": ip})
    if not doc:
        raise HTTPException(status_code=404, detail=f"Hôte {ip} non trouvé")
    return [PortInfo(**port) for port in doc.get("ports", [])]


@router.get(
    "/{ip}/vulnerabilities",
    response_model=list[Vulnerability],
    summary="Vulnérabilités d'un hôte",
    description="Retourne toutes les vulnérabilités détectées sur un hôte spécifique.",
    tags=["hosts"],
)
async def get_host_vulnerabilities(
    ip: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Récupère toutes les vulnérabilités détectées sur un hôte."""
    db = await get_database()
    scanner = VulnerabilityScanner(db)
    vulns = await scanner.get_vulnerabilities_by_host(ip)
    return vulns


@router.get(
    "/{ip}/mitre",
    response_model=list[MitreMapping],
    summary="Mappings MITRE d'un hôte",
    description="Retourne les mappings MITRE ATT&CK associés aux services et vulnérabilités d'un hôte.",
    tags=["hosts"],
)
async def get_host_mitre_mappings(
    ip: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Récupère les mappings MITRE ATT&CK pour un hôte spécifique."""
    db = await get_database()
    from app.services.mitre_mapper import MitreMapper

    mapper = MitreMapper()
    host = await db.hosts.find_one({"ip_address": ip})
    if not host:
        raise HTTPException(status_code=404, detail=f"Hôte {ip} non trouvé")

    all_mappings = []
    seen_ids = set()

    # Mapper chaque service de l'hôte
    for port_info in host.get("ports", []):
        service = port_info.get("service")
        version = port_info.get("version", "")
        if service:
            mappings = await mapper.map_service_to_mitre(service, version)
            for m in mappings:
                if m.technique_id not in seen_ids:
                    all_mappings.append(m)
                    seen_ids.add(m.technique_id)

    # Enrichir avec les CVE
    from app.services.vulnerability_scanner import VulnerabilityScanner

    scanner = VulnerabilityScanner(db)
    vulns = await scanner.get_vulnerabilities_by_host(ip)
    for vuln in vulns:
        if vuln.mitre_mapping and vuln.mitre_mapping.technique_id not in seen_ids:
            all_mappings.append(vuln.mitre_mapping)
            seen_ids.add(vuln.mitre_mapping.technique_id)

    return all_mappings


@router.get(
    "/{ip}/auth-results",
    response_model=list[AuthTestResult],
    summary="Résultats d'authentification d'un hôte",
    description="Retourne les résultats des tests d'authentification effectués sur un hôte.",
    tags=["hosts"],
)
async def get_host_auth_results(
    ip: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Récupère les résultats des tests d'authentification pour un hôte."""
    db = await get_database()
    # Les résultats sont stockés imbriqués dans auth_test_campaigns.results
    results = []
    cursor = db.auth_test_campaigns.find(
        {"results.host_ip": ip},
        {"results": 1, "_id": 0},
    )
    async for doc in cursor:
        for r in doc.get("results", []):
            if r.get("host_ip") == ip:
                try:
                    # Retirer les champs non modèles
                    r.pop("campaign_id", None)
                    if "_id" in r:
                        r["_id"] = str(r["_id"])
                    results.append(AuthTestResult(**r))
                except Exception:
                    pass
    # Trier par timestamp décroissant
    results.sort(key=lambda x: x.timestamp, reverse=True)
    return results
