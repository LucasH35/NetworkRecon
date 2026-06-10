"""Routes API pour la réinitialisation des données."""

from fastapi import APIRouter, HTTPException
from app.utils.database import get_database

router = APIRouter()


@router.delete(
    "/",
    summary="Réinitialiser toutes les données",
    description="Supprime toutes les collections de la base de données (irréversible).",
    tags=["reset"],
)
async def reset_all_data():
    """Supprime toutes les données de la base de données."""
    db = await get_database()

    # Liste de toutes les collections à supprimer
    collections_to_drop = [
        "campaigns",
        "hosts",
        "vulnerabilities",
        "vulnerability_scans",
        "archived_vulnerabilities",
        "archived_hosts",
        "auth_test_campaigns",
        "auth_test_results",
        "campaign_progress",
        "sqlmap_campaigns",
        "reports",
        "mitre_techniques",
    ]

    dropped = []
    for coll_name in collections_to_drop:
        try:
            coll = db[coll_name]
            result = await coll.drop()
            dropped.append(coll_name)
        except Exception:
            pass

    return {
        "status": "ok",
        "message": "Toutes les données ont été réinitialisées",
        "dropped": dropped,
    }
