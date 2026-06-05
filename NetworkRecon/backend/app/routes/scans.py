"""Routes API pour la gestion des campagnes de scan réseau."""

import asyncio
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Query, Depends, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.models.scan import (
    Campaign,
    CampaignStatus,
    ScanConfig,
    ScanResult,
    ScanScanType,
    ScanTarget,
)
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
    response_model=list[Campaign],
    summary="Lister toutes les campagnes de scan",
    description="Retourne la liste des campagnes de scan avec pagination et filtrage optionnel par statut.",
    tags=["scans"],
)
async def list_campaigns(
    status: Optional[CampaignStatus] = Query(None, description="Filtrer par statut"),
    limit: int = Query(50, ge=1, le=200, description="Nombre maximum de résultats"),
    offset: int = Query(0, ge=0, description="Décalage pour la pagination"),
    user: Optional[str] = Depends(get_current_user),
):
    """Liste toutes les campagnes de scan avec pagination et filtrage."""
    db = await get_database()
    query = {}
    if status:
        query["status"] = status.value

    cursor = db.campaigns.find(query).sort("created_at", -1).skip(offset).limit(limit)
    campaigns = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        campaigns.append(Campaign(**doc))
    return campaigns


@router.post(
    "/",
    response_model=Campaign,
    status_code=201,
    summary="Créer et lancer une campagne de scan",
    description="Crée une nouvelle campagne de scan pour le réseau 192.168.2.0/24.",
    tags=["scans"],
)
async def create_campaign(
    name: str = Body(..., description="Nom de la campagne"),
    description: Optional[str] = Body(default=None, description="Description de la campagne"),
    scan_type: str = Body(default="full", description="Type de scan: full, quick, stealth"),
    ports_range: Optional[str] = Body(default=None, description="Plage de ports (ex: 22,80,443)"),
    user: Optional[str] = Depends(get_current_user),
):
    """Crée et lance une nouvelle campagne de scan pour 192.168.2.0/24."""
    from app.models.scan import ScanTarget, ScanConfig

    db = await get_database()

    # Cible fixe : réseau 192.168.2.0/24, toujours autorisé
    targets_list = [
        ScanTarget(
            ip_range="192.168.2.0/24",
            authorized=True,
            target_list=[],
        )
    ]

    scan_config = ScanConfig(
        scan_type=scan_type,
        ports_range=ports_range,
    )

    campaign = Campaign(
        name=name,
        description=description,
        targets=targets_list,
        config=scan_config,
        status=CampaignStatus.PENDING,
    )

    # Générer un ID string et le stocker comme _id dans MongoDB
    from bson import ObjectId
    oid = ObjectId()
    campaign_id = str(oid)
    campaign.id = campaign_id

    campaign_doc = campaign.model_dump(by_alias=True, exclude={"id"})
    campaign_doc["_id"] = campaign_id
    await db.campaigns.insert_one(campaign_doc)

    # Lancer le scan en arrière-plan via l'orchestrateur
    from app.services.scan_orchestrator import ScanOrchestrator
    orchestrator = ScanOrchestrator(db)
    asyncio.create_task(orchestrator.run_full_scan(campaign))

    return campaign


@router.get(
    "/{campaign_id}",
    response_model=Campaign,
    summary="Récupérer une campagne",
    description="Retourne les détails complets d'une campagne de scan par son identifiant.",
    tags=["scans"],
)
async def get_campaign(
    campaign_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Récupère les détails d'une campagne par son identifiant."""
    db = await get_database()
    doc = await db.campaigns.find_one({"_id": campaign_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Campagne non trouvée")
    doc["_id"] = str(doc["_id"])
    return Campaign(**doc)


@router.get(
    "/{campaign_id}/status",
    response_model=dict,
    summary="Statut en temps réel d'une campagne",
    description="Retourne le statut en temps réel d'une campagne de scan en cours.",
    tags=["scans"],
)
async def get_campaign_status(
    campaign_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Retourne le statut en temps réel d'une campagne."""
    db = await get_database()
    doc = await db.campaigns.find_one({"_id": campaign_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Campagne non trouvée")

    doc["_id"] = str(doc["_id"])
    campaign = Campaign(**doc)

    # Calculer la progression
    total_targets = sum(len(t.target_list) or 1 for t in campaign.targets)
    scanned_hosts = sum(len(r.hosts_found) for r in campaign.results)
    progress = (scanned_hosts / total_targets * 100) if total_targets > 0 else 0

    return {
        "campaign_id": campaign.id,
        "status": campaign.status,
        "progress": round(progress, 1),
        "hosts_found": scanned_hosts,
        "results_count": len(campaign.results),
    }


@router.post(
    "/{campaign_id}/pause",
    response_model=dict,
    summary="Mettre en pause une campagne",
    description="Met en pause une campagne de scan en cours.",
    tags=["scans"],
)
async def pause_campaign(
    campaign_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Met en pause une campagne de scan."""
    db = await get_database()
    doc = await db.campaigns.find_one({"_id": campaign_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Campagne non trouvée")

    if doc["status"] != CampaignStatus.RUNNING.value:
        raise HTTPException(
            status_code=400,
            detail="Seules les campagnes en cours peuvent être mises en pause",
        )

    await db.campaigns.update_one(
        {"_id": campaign_id},
        {"$set": {"status": CampaignStatus.PAUSED.value}},
    )
    return {"message": "Campagne mise en pause avec succès", "status": "paused"}


@router.post(
    "/{campaign_id}/resume",
    response_model=dict,
    summary="Reprendre une campagne",
    description="Reprend une campagne de scan mise en pause.",
    tags=["scans"],
)
async def resume_campaign(
    campaign_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Reprend une campagne de scan mise en pause."""
    db = await get_database()
    doc = await db.campaigns.find_one({"_id": campaign_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Campagne non trouvée")

    if doc["status"] != CampaignStatus.PAUSED.value:
        raise HTTPException(
            status_code=400,
            detail="Seules les campagnes en pause peuvent être reprises",
        )

    await db.campaigns.update_one(
        {"_id": campaign_id},
        {"$set": {"status": CampaignStatus.RUNNING.value}},
    )
    return {"message": "Campagne reprise avec succès", "status": "running"}


@router.post(
    "/{campaign_id}/cancel",
    response_model=dict,
    summary="Annuler une campagne",
    description="Annule une campagne de scan en cours ou en attente.",
    tags=["scans"],
)
async def cancel_campaign(
    campaign_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Annule une campagne de scan."""
    db = await get_database()
    doc = await db.campaigns.find_one({"_id": campaign_id})
    if not doc:
        raise HTTPException(
            status_code=404,
            detail="Campagne non trouvée",
        )

    if doc["status"] in (CampaignStatus.COMPLETED.value, CampaignStatus.FAILED.value, CampaignStatus.CANCELLED.value):
        raise HTTPException(
            status_code=400,
            detail="La campagne est déjà terminée et ne peut pas être annulée",
        )

    await db.campaigns.update_one(
        {"_id": campaign_id},
        {"$set": {"status": CampaignStatus.CANCELLED.value}},
    )
    return {"message": "Campagne annulée avec succès", "status": "cancelled"}


@router.delete(
    "/{campaign_id}",
    status_code=204,
    summary="Supprimer une campagne",
    description="Supprime une campagne et tous ses résultats associés.",
    tags=["scans"],
)
async def delete_campaign(
    campaign_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Supprime une campagne et ses résultats."""
    db = await get_database()
    result = await db.campaigns.delete_one({"_id": campaign_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Campagne non trouvée")
