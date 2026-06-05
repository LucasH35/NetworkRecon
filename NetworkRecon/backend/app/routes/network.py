"""Routes API pour la gestion des plages réseau."""

from fastapi import APIRouter, HTTPException, Query

from app.models.network import NetworkRange, NetworkRangeCreate
from app.services.network_service import NetworkService

router = APIRouter()
network_service = NetworkService()


@router.get("/", response_model=list[NetworkRange])
async def list_network_ranges(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Liste toutes les plages réseau configurées."""
    return await network_service.list_ranges(limit=limit, offset=offset)


@router.post("/", response_model=NetworkRange, status_code=201)
async def create_network_range(range_data: NetworkRangeCreate):
    """Ajoute une nouvelle plage réseau."""
    return await network_service.create_range(range_data)


@router.get("/{range_id}", response_model=NetworkRange)
async def get_network_range(range_id: str):
    """Récupère les détails d'une plage réseau."""
    net_range = await network_service.get_range(range_id)
    if not net_range:
        raise HTTPException(status_code=404, detail="Plage réseau non trouvée")
    return net_range


@router.delete("/{range_id}", status_code=204)
async def delete_network_range(range_id: str):
    """Supprime une plage réseau."""
    deleted = await network_service.delete_range(range_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Plage réseau non trouvée")
