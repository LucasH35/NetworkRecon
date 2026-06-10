"""Routes API pour le tableau de bord."""

from typing import Optional

from fastapi import APIRouter, Query, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

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
    "/stats",
    response_model=dict,
    summary="Statistiques globales",
    description="Retourne les statistiques globales du système.",
    tags=["dashboard"],
)
async def get_global_stats(
    user: Optional[str] = Depends(get_current_user),
):
    """Retourne les statistiques globales du système."""
    db = await get_database()

    # Compter les campagnes
    total_campaigns = await db.campaigns.count_documents({})
    running_campaigns = await db.campaigns.count_documents({"status": "running"})

    # Compter les hôtes
    total_hosts = await db.hosts.count_documents({})

    # Compter les vulnérabilités depuis archived_vulnerabilities
    total_vulns = await db.archived_vulnerabilities.count_documents({})

    # Compter par sévérité (archived_vulnerabilities: chaque doc = 1 CVE, champ cve.severity)
    severity_pipeline = [
        {"$group": {"_id": "$cve.severity", "count": {"$sum": 1}}},
    ]
    severity_counts = {}
    async for doc in db.archived_vulnerabilities.aggregate(severity_pipeline):
        severity_counts[doc["_id"]] = doc["count"]

    # Compter les tests d'authentification
    auth_tests_completed = await db.auth_test_campaigns.count_documents({"status": "completed"})

    return {
        "total_campaigns": total_campaigns,
        "running_campaigns": running_campaigns,
        "total_hosts": total_hosts,
        "total_vulnerabilities": total_vulns,
        "critical_vulns": severity_counts.get("critical", 0),
        "high_vulns": severity_counts.get("high", 0),
        "medium_vulns": severity_counts.get("medium", 0),
        "low_vulns": severity_counts.get("low", 0),
        "auth_tests_completed": auth_tests_completed,
    }


@router.get(
    "/recent-campaigns",
    response_model=list[dict],
    summary="5 dernières campagnes",
    description="Retourne les 5 dernières campagnes de scan créées.",
    tags=["dashboard"],
)
async def get_recent_campaigns(
    limit: int = Query(5, ge=1, le=20, description="Nombre de campagnes"),
    user: Optional[str] = Depends(get_current_user),
):
    """Retourne les dernières campagnes créées."""
    db = await get_database()
    cursor = db.campaigns.find().sort("created_at", -1).limit(limit)
    campaigns = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        # Compter les hôtes trouvés
        hosts_count = sum(len(r.get("hosts_found", [])) for r in doc.get("results", []))
        campaigns.append(
            {
                "id": doc["_id"],
                "name": doc.get("name"),
                "status": doc.get("status"),
                "created_at": doc.get("created_at"),
                "hosts_found": hosts_count,
            }
        )
    return campaigns


@router.get(
    "/severity-distribution",
    response_model=dict,
    summary="Répartition par sévérité",
    description="Retourne la répartition des vulnérabilités par niveau de sévérité.",
    tags=["dashboard"],
)
async def get_severity_distribution(
    user: Optional[str] = Depends(get_current_user),
):
    """Retourne la répartition des vulnérabilités par sévérité."""
    db = await get_database()

    pipeline = [
        {"$group": {"_id": "$cve.severity", "count": {"$sum": 1}}},
    ]

    distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    async for doc in db.archived_vulnerabilities.aggregate(pipeline):
        severity = doc["_id"]
        if severity in distribution:
            distribution[severity] = doc["count"]

    distribution["total"] = sum(distribution.values())

    return distribution


@router.get(
    "/top-vulns",
    response_model=list[dict],
    summary="Top 10 vulnérabilités",
    description="Retourne les 10 vulnérabilités les plus fréquentes.",
    tags=["dashboard"],
)
async def get_top_vulnerabilities(
    limit: int = Query(10, ge=1, le=50, description="Nombre de vulnérabilités"),
    user: Optional[str] = Depends(get_current_user),
):
    """Retourne les vulnérabilités les plus fréquentes."""
    db = await get_database()

    pipeline = [
        {
            "$group": {
                "_id": {
                    "cve_id": "$cve.cve_id",
                    "severity": "$cve.severity",
                },
                "count": {"$sum": 1},
                "affected_hosts": {"$addToSet": "$host_ip"},
            }
        },
        {"$sort": {"count": -1}},
        {"$limit": limit},
    ]

    top_vulns = []
    async for doc in db.archived_vulnerabilities.aggregate(pipeline):
        top_vulns.append(
            {
                "cve_id": doc["_id"]["cve_id"],
                "severity": doc["_id"]["severity"],
                "count": doc["count"],
                "affected_hosts": doc["affected_hosts"],
            }
        )

    return top_vulns


@router.get(
    "/network-overview",
    response_model=dict,
    summary="Vue d'ensemble du réseau",
    description="Retourne une vue d'ensemble du réseau avec les services les plus courants.",
    tags=["dashboard"],
)
async def get_network_overview(
    user: Optional[str] = Depends(get_current_user),
):
    """Retourne une vue d'ensemble du réseau."""
    db = await get_database()

    # Compter les hôtes par statut
    total_hosts = await db.hosts.count_documents({})
    hosts_up = await db.hosts.count_documents({"status": "up"})
    hosts_down = total_hosts - hosts_up

    # Top services
    services_pipeline = [
        {"$unwind": "$ports"},
        {"$group": {"_id": "$ports.service", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    top_services = []
    async for doc in db.hosts.aggregate(services_pipeline):
        if doc["_id"]:
            top_services.append({"service": doc["_id"], "count": doc["count"]})

    # Distribution OS
    os_pipeline = [
        {"$group": {"_id": "$os_detection", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    os_distribution = []
    async for doc in db.hosts.aggregate(os_pipeline):
        os_name = doc["_id"] or "Unknown"
        # Simplifier le nom de l'OS
        if "linux" in os_name.lower():
            os_name = "Linux"
        elif "windows" in os_name.lower():
            os_name = "Windows"
        os_distribution.append({"os": os_name, "count": doc["count"]})

    # Fusionner les OS similaires
    merged_os = {}
    for item in os_distribution:
        os_name = item["os"]
        if os_name in merged_os:
            merged_os[os_name] += item["count"]
        else:
            merged_os[os_name] = item["count"]

    os_distribution_final = [
        {"os": k, "count": v} for k, v in sorted(merged_os.items(), key=lambda x: -x[1])
    ]

    return {
        "total_hosts": total_hosts,
        "hosts_up": hosts_up,
        "hosts_down": hosts_down,
        "top_services": top_services,
        "os_distribution": os_distribution_final,
    }
