"""Routes API pour la génération et gestion des rapports."""

import asyncio
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.models.report import Report, ExportFormat
from app.services.report_generator import ReportGenerator
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


@router.post(
    "/generate",
    response_model=Report,
    status_code=201,
    summary="Générer un rapport",
    description="Génère un rapport complet pour une campagne donnée.",
    tags=["reports"],
)
async def generate_report(
    campaign_id: str = Query(..., description="ID de la campagne"),
    export_format: ExportFormat = Query(ExportFormat.JSON, description="Format de sortie"),
    user: Optional[str] = Depends(get_current_user),
):
    """Génère un rapport pour une campagne."""
    db = await get_database()

    # Vérifier que la campagne existe
    campaign = await db.campaigns.find_one({"_id": campaign_id})
    if not campaign:
        raise HTTPException(status_code=404, detail="Campagne non trouvée")

    # Générer le rapport via le service
    generator = ReportGenerator(db)
    try:
        report = await generator.generate_report(campaign_id, export_format.value)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors de la génération: {str(e)}")


@router.get(
    "/{report_id}",
    response_model=Report,
    summary="Récupérer un rapport",
    description="Retourne les métadonnées d'un rapport généré.",
    tags=["reports"],
)
async def get_report(
    report_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Récupère les métadonnées d'un rapport."""
    db = await get_database()
    doc = await db.reports.find_one({"_id": report_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Rapport non trouvé")
    doc["_id"] = str(doc["_id"])
    return Report(**doc)


@router.get(
    "/{report_id}/export/{format}",
    summary="Exporter un rapport",
    description="Télécharge le rapport dans le format spécifié.",
    tags=["reports"],
)
async def export_report(
    report_id: str,
    format: ExportFormat,
    user: Optional[str] = Depends(get_current_user),
):
    """Exporte un rapport dans le format spécifié."""
    db = await get_database()
    doc = await db.reports.find_one({"_id": report_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Rapport non trouvé")

    # Générer le contenu selon le format
    generator = ReportGenerator(db)
    content = await generator.export_report(report_id, format.value)

    # Définir les headers selon le format
    media_types = {
        ExportFormat.PDF: "application/pdf",
        ExportFormat.CSV: "text/csv",
        ExportFormat.JSON: "application/json",
        ExportFormat.HTML: "text/html",
    }

    filename = f"report_{report_id}.{format.value}"

    return StreamingResponse(
        iter([content]),
        media_type=media_types.get(format, "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/campaign/{campaign_id}",
    response_model=list[Report],
    summary="Rapports d'une campagne",
    description="Retourne tous les rapports générés pour une campagne spécifique.",
    tags=["reports"],
)
async def list_reports_by_campaign(
    campaign_id: str,
    limit: int = Query(20, ge=1, le=100, description="Nombre maximum de résultats"),
    user: Optional[str] = Depends(get_current_user),
):
    """Liste tous les rapports d'une campagne."""
    db = await get_database()
    cursor = db.reports.find({"campaign_id": campaign_id}).sort("generated_at", -1).limit(limit)
    reports = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        reports.append(Report(**doc))
    return reports


@router.delete(
    "/{report_id}",
    status_code=204,
    summary="Supprimer un rapport",
    description="Supprime un rapport et son fichier associé.",
    tags=["reports"],
)
async def delete_report(
    report_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Supprime un rapport."""
    db = await get_database()
    result = await db.reports.delete_one({"_id": report_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Rapport non trouvé")
