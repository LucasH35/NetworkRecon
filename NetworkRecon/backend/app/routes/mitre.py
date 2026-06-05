"""Routes API pour MITRE ATT&CK."""

import json
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.models.mitre import MitreMapping, ServiceToMitre
from app.models.vulnerability import CVE
from app.services.mitre_mapper import MitreMapper, MITRE_TACTICS
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
    "/tactics",
    response_model=list[str],
    summary="Lister les tactiques MITRE ATT&CK",
    description="Retourne la liste de toutes les tactiques du framework MITRE ATT&CK.",
    tags=["mitre"],
)
async def list_tactics(
    user: Optional[str] = Depends(get_current_user),
):
    """Retourne la liste de toutes les tactiques MITRE ATT&CK."""
    return MITRE_TACTICS


@router.get(
    "/techniques",
    response_model=list[MitreMapping],
    summary="Lister toutes les techniques MITRE ATT&CK",
    description="Retourne toutes les techniques MITRE ATT&CK connues dans la base de données.",
    tags=["mitre"],
)
async def list_techniques(
    tactic: Optional[str] = Query(None, description="Filtrer par tactique"),
    service: Optional[str] = Query(None, description="Filtrer par service"),
    user: Optional[str] = Depends(get_current_user),
):
    """Retourne toutes les techniques MITRE ATT&CK."""
    mapper = MitreMapper()
    all_techniques = []
    seen_ids = set()

    # Récupérer les techniques depuis la base de mapping statique
    for svc, techniques in mapper._service_db.items():
        if service and svc != service.lower():
            continue
        for tech in techniques:
            if tactic and tech["tactic"] != tactic:
                continue
            if tech["technique_id"] not in seen_ids:
                url = f"https://attack.mitre.org/techniques/{tech['technique_id']}/"
                mapping = MitreMapping(
                    technique_id=tech["technique_id"],
                    technique_name=tech["technique_name"],
                    tactic=tech["tactic"],
                    description=tech.get("description", ""),
                    url=url,
                )
                all_techniques.append(mapping)
                seen_ids.add(tech["technique_id"])

    return all_techniques


@router.get(
    "/techniques/{technique_id}",
    response_model=dict,
    summary="Détail d'une technique MITRE",
    description="Retourne les informations détaillées d'une technique MITRE ATT&CK spécifique.",
    tags=["mitre"],
)
async def get_technique_details(
    technique_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Récupère les détails d'une technique MITRE ATT&CK."""
    import re
    pattern = r"^T\d{4}(\.\d{3})?$"
    if not re.match(pattern, technique_id):
        raise HTTPException(
            status_code=400,
            detail=f"Format de technique invalide: {technique_id}",
        )

    mapper = MitreMapper()

    # Chercher dans la base de mapping statique
    for svc, techniques in mapper._service_db.items():
        for tech in techniques:
            if tech["technique_id"] == technique_id:
                url = f"https://attack.mitre.org/techniques/{technique_id}/"
                return {
                    "technique_id": technique_id,
                    "technique_name": tech["technique_name"],
                    "tactic": tech["tactic"],
                    "description": tech.get("description", ""),
                    "url": url,
                    "related_services": [svc],
                }

    # Si non trouvé, retourner les informations de base
    raise HTTPException(
        status_code=404,
        detail=f"Technique {technique_id} non trouvée dans la base",
    )


@router.get(
    "/attack-paths",
    response_model=list[dict],
    summary="Parcours d'attaque identifiés",
    description="Retourne les parcours d'attaque identifiés lors des scans précédents.",
    tags=["mitre"],
)
async def get_attack_paths(
    campaign_id: Optional[str] = Query(None, description="Filtrer par campagne"),
    user: Optional[str] = Depends(get_current_user),
):
    """Retourne les parcours d'attaque identifiés."""
    db = await get_database()

    # Construire les parcours d'attaque depuis les mappings MITRE
    pipeline = [
        {"$unwind": "$vulnerabilities"},
        {"$match": {"vulnerabilities.mitre_mapping": {"$ne": None}}},
        {
            "$group": {
                "_id": {
                    "tactic": "$vulnerabilities.mitre_mapping.tactic",
                    "technique": "$vulnerabilities.mitre_mapping.technique_id",
                },
                "hosts": {"$addToSet": "$vulnerabilities.host_ip"},
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"count": -1}},
    ]

    paths = []
    path_id = 1
    async for doc in db.vulnerability_scans.aggregate(pipeline):
        paths.append({
            "path_id": f"path_{path_id:03d}",
            "name": f"{doc['_id']['tactic']} via {doc['_id']['technique']}",
            "description": f"Parcours d'attaque utilisant la technique {doc['_id']['technique']}",
            "techniques": [doc["_id"]["technique"]],
            "hosts": doc["hosts"],
            "count": doc["count"],
        })
        path_id += 1

    return paths


@router.get(
    "/export/stix",
    response_model=dict,
    summary="Export STIX 2.1",
    description="Exporte les données MITRE ATT&CK au format STIX 2.1.",
    tags=["mitre"],
)
async def export_stix(
    user: Optional[str] = Depends(get_current_user),
):
    """Exporte les données MITRE ATT&CK au format STIX 2.1."""
    mapper = MitreMapper()

    objects = []
    seen_ids = set()

    # Convertir les techniques en objets STIX
    for svc, techniques in mapper._service_db.items():
        for tech in techniques:
            if tech["technique_id"] not in seen_ids:
                stix_obj = {
                    "type": "attack-pattern",
                    "id": f"attack-pattern--{tech['technique_id']}",
                    "spec_version": "2.1",
                    "created": "2026-01-01T00:00:00.000Z",
                    "modified": "2026-01-01T00:00:00.000Z",
                    "name": tech["technique_name"],
                    "description": tech.get("description", ""),
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": tech["technique_id"],
                            "url": f"https://attack.mitre.org/techniques/{tech['technique_id']}/",
                        }
                    ],
                }
                objects.append(stix_obj)
                seen_ids.add(tech["technique_id"])

    bundle = {
        "type": "bundle",
        "id": "bundle--networkrecon-mitre-attack",
        "spec_version": "2.1",
        "objects": objects,
    }

    return bundle
