"""
Routes API pour SQLMap.
Gère les campagnes de test d'injection SQL.
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from app.utils.database import get_database
from app.models.sqlmap import (
    SqlmapCampaign,
    SqlmapCampaignCreate,
    SqlmapConfig,
    SqlmapStatus,
)
from app.services.sqlmap_scanner import SqlmapError, SqlmapScanner

logger = logging.getLogger(__name__)

router = APIRouter(tags=["sqlmap"])

# Stockage temporaire des tâches en cours
_running_campaigns: dict[str, asyncio.Task] = {}


def _get_scanner(db) -> SqlmapScanner:
    """Crée une instance du scanner SQLMap."""
    return SqlmapScanner(db)


async def get_current_user():
    """Retourne l'utilisateur courant (pas d'auth pour le lab)."""
    return "lab-user"


# ===================== Endpoints CRUD =====================


@router.get(
    "/",
    response_model=list[SqlmapCampaign],
    summary="Lister les campagnes SQLMap",
    description="Retourne toutes les campagnes SQLMap triées par date décroissante.",
)
async def list_campaigns(
    limit: int = 50,
    user: Optional[str] = Depends(get_current_user),
):
    """Liste les campagnes SQLMap."""
    db = await get_database()
    scanner = _get_scanner(db)
    return await scanner.list_campaigns(limit=limit)


@router.post(
    "/",
    response_model=SqlmapCampaign,
    status_code=201,
    summary="Créer et lancer une campagne SQLMap",
    description="Crée une nouvelle campagne et lance l'exécution en arrière-plan.",
)
async def create_campaign(
    payload: SqlmapCampaignCreate,
    background_tasks: BackgroundTasks,
    user: Optional[str] = Depends(get_current_user),
):
    """Crée et lance une campagne SQLMap."""
    db = await get_database()
    scanner = _get_scanner(db)

    # Construire la configuration
    config = SqlmapConfig(
        target_url=payload.target_url,
        data=payload.data,
        cookie=payload.cookie,
        level=payload.level,
        risk=payload.risk,
        techniques=payload.techniques,
        dbms=payload.dbms,
        tamper=payload.tamper,
        threads=payload.threads,
        depth_crawl=payload.depth_crawl,
        forms=payload.forms,
        random_agent=payload.random_agent,
    )

    # Créer la campagne
    from bson import ObjectId
    campaign_id = str(ObjectId())

    campaign = SqlmapCampaign(
        id=campaign_id,
        name=payload.name,
        target_url=payload.target_url,
        config=config,
        status=SqlmapStatus.PENDING,
        total_urls=1,
    )

    # Sauvegarder en DB
    doc = campaign.model_dump(by_alias=True)
    await db.sqlmap_campaigns.insert_one(doc)

    # Lancer en arrière-plan
    async def _run():
        try:
            await scanner.run_campaign(campaign)
        except Exception as e:
            logger.error("Erreur campagne SQLMap %s: %s", campaign.id, e)

    task = asyncio.create_task(_run())
    _running_campaigns[campaign.id] = task

    return campaign


@router.get(
    "/{campaign_id}",
    response_model=SqlmapCampaign,
    summary="Détails d'une campagne SQLMap",
    description="Retourne les détails complets d'une campagne.",
)
async def get_campaign(
    campaign_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Récupère une campagne par son ID."""
    db = await get_database()
    scanner = _get_scanner(db)
    campaign = await scanner.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campagne non trouvée")
    return campaign


@router.delete(
    "/{campaign_id}",
    summary="Supprimer une campagne SQLMap",
    description="Supprime une campagne et ses résultats.",
)
async def delete_campaign(
    campaign_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Supprime une campagne SQLMap."""
    db = await get_database()
    scanner = _get_scanner(db)

    # Annuler la tâche si en cours
    if campaign_id in _running_campaigns:
        task = _running_campaigns.pop(campaign_id)
        task.cancel()

    deleted = await scanner.delete_campaign(campaign_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Campagne non trouvée")

    return {"status": "deleted", "campaign_id": campaign_id}


@router.post(
    "/{campaign_id}/cancel",
    summary="Annuler une campagne SQLMap",
    description="Annule une campagne en cours d'exécution.",
)
async def cancel_campaign(
    campaign_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Annule une campagne en cours."""
    if campaign_id in _running_campaigns:
        task = _running_campaigns.pop(campaign_id)
        task.cancel()

    db = await get_database()
    await db.sqlmap_campaigns.update_one(
        {"_id": campaign_id},
        {
            "$set": {
                "status": SqlmapStatus.FAILED.value,
                "error_message": "Annulé par l'utilisateur",
                "completed_at": datetime.utcnow(),
            }
        },
    )

    return {"status": "cancelled", "campaign_id": campaign_id}
