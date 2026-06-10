"""Routes API pour les tests d'authentification."""

import asyncio
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Query, Depends, UploadFile, File, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from app.models.auth_test import (
    AuthCampaign,
    AuthTestResult,
    AuthCampaignStatus,
    AttackSuggestion,
)
from app.services.auth_tester import AuthTester
from app.services.attack_suggester import AttackSuggestionService
from app.utils.database import get_database

router = APIRouter()
security = HTTPBearer(auto_error=False)

# Liste globale pour garder les références des tâches en cours
_running_tasks: list = []


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[str]:
    """Extrait l'utilisateur actuel depuis le token Bearer."""
    if credentials is None:
        return None
    return credentials.credentials


@router.post(
    "/",
    response_model=AuthCampaign,
    status_code=201,
    summary="Lancer une campagne de tests d'authentification",
    description="Crée et lance une nouvelle campagne de tests d'authentification en arrière-plan.",
    tags=["auth-tests"],
)
async def launch_auth_test_campaign(
    name: str = Query(..., description="Nom de la campagne"),
    targets: List[str] = Query(..., description="Liste des IPs à tester"),
    service_type: str = Query("ssh", description="Type de service à tester"),
    credentials_file: Optional[str] = Query(None, description="Nom du fichier de credentials"),
    background_tasks: BackgroundTasks = None,
    user: Optional[str] = Depends(get_current_user),
):
    """Lance une campagne de tests d'authentification en arrière-plan."""
    from app.models.auth_test import AuthTestConfig, ServiceType

    db = await get_database()

    config = AuthTestConfig(
        service_type=ServiceType(service_type),
        credentials_file=credentials_file,
    )

    campaign = AuthCampaign(
        name=name,
        targets=targets,
        config=config,
        status=AuthCampaignStatus.PENDING,
    )

    # Générer un ID string et le stocker comme _id dans MongoDB
    from bson import ObjectId
    oid = ObjectId()
    campaign_id = str(oid)
    campaign.id = campaign_id

    campaign_doc = campaign.model_dump(by_alias=True, exclude={"id"})
    campaign_doc["_id"] = campaign_id
    await db.auth_test_campaigns.insert_one(campaign_doc)

    # Lancer les tests en arrière-plan
    async def _run():
        try:
            tester = AuthTester(db)
            await tester.run_auth_campaign(campaign)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Erreur campagne {campaign.id}: {e}")

    task = asyncio.ensure_future(_run())
    # Garder une référence pour éviter le garbage collection
    _running_tasks.append(task)

    return campaign


@router.get(
    "/",
    response_model=list[AuthCampaign],
    summary="Lister toutes les campagnes de tests d'authentification",
    description="Retourne la liste des campagnes de tests d'authentification.",
    tags=["auth-tests"],
)
async def list_auth_test_campaigns(
    status: Optional[AuthCampaignStatus] = Query(None, description="Filtrer par statut"),
    limit: int = Query(50, ge=1, le=200, description="Nombre maximum de résultats"),
    offset: int = Query(0, ge=0, description="Décalage pour la pagination"),
    user: Optional[str] = Depends(get_current_user),
):
    """Liste toutes les campagnes de tests d'authentification."""
    db = await get_database()
    query = {}
    if status:
        query["status"] = status.value

    cursor = db.auth_test_campaigns.find(query).sort("created_at", -1).skip(offset).limit(limit)
    campaigns = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        campaigns.append(AuthCampaign(**doc))
    return campaigns


# ── Suggestions d'attaques (AVANT /{campaign_id} pour éviter le matching) ──


@router.get(
    "/suggestions",
    response_model=list[AttackSuggestion],
    summary="Suggestions d'attaques brute force basées sur les CVE",
    description=(
        "Analyse les hôtes découverts et les CVE trouvées pour suggérer "
        "des attaques brute force prioritaires."
    ),
    tags=["auth-tests"],
)
async def get_attack_suggestions(
    campaign_id: Optional[str] = Query(None, description="Filtrer par campagne"),
    host_ip: Optional[str] = Query(None, description="Filtrer par IP d'hôte"),
    user: Optional[str] = Depends(get_current_user),
):
    """Retourne des suggestions d'attaques basées sur les CVE découvertes."""
    db = await get_database()
    service = AttackSuggestionService(db)
    suggestions = await service.get_suggestions(
        campaign_id=campaign_id,
        host_ip=host_ip,
    )
    return suggestions


@router.post(
    "/launch-suggestion",
    response_model=AuthCampaign,
    status_code=201,
    summary="Lancer une attaque depuis une suggestion",
    description="Lance une campagne brute force basée sur une suggestion d'attaque.",
    tags=["auth-tests"],
)
async def launch_from_suggestion(
    host_ip: str = Query(..., description="IP de la cible"),
    service_type: str = Query(..., description="Type de service"),
    port: int = Query(..., description="Port du service"),
    credentials_file: Optional[UploadFile] = File(None, description="Fichier JSON de credentials personnalisé ([{\"user\":\"...\",\"pass\":\"...\"}])"),
    background_tasks: BackgroundTasks = None,
    user: Optional[str] = Depends(get_current_user),
):
    """Lance une campagne brute force basée sur une suggestion."""
    from app.models.auth_test import AuthTestConfig, ServiceType
    import tempfile, os, json

    db = await get_database()

    # Valider le type de service
    try:
        svc = ServiceType(service_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Type de service non supporté: {service_type}",
        )

    # Traiter le fichier de credentials uploadé
    saved_cred_path = None
    if credentials_file and credentials_file.filename:
        try:
            content = await credentials_file.read()
            data = json.loads(content.decode('utf-8'))

            # Accepte les formats: {"user":"x","pass":"y"} OU {"username":"x","password":"y"}
            normalized = []
            for item in data:
                username = item.get("username") or item.get("user") or ""
                password = item.get("password") or item.get("pass") or ""
                if username and password:
                    normalized.append({"username": username, "password": password})

            if not normalized:
                raise HTTPException(status_code=400, detail="Aucun credential valide trouvé dans le fichier")

            # Sauvegarder dans un fichier temporaire
            tmp = tempfile.NamedTemporaryFile(
                mode='w', suffix='.json', delete=False, dir='/tmp'
            )
            json.dump(normalized, tmp)
            tmp.close()
            saved_cred_path = tmp.name

        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Le fichier n'est pas un JSON valide")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Erreur lecture fichier: {e}")

    config = AuthTestConfig(
        service_type=svc,
        max_attempts=5,
        delay_between=1.0,
        credentials_file=saved_cred_path,
    )

    campaign = AuthCampaign(
        name=f"Brute force {svc.value.upper()} sur {host_ip}:{port}",
        targets=[host_ip],
        config=config,
        status=AuthCampaignStatus.PENDING,
    )

    # Générer un ID
    from bson import ObjectId
    oid = ObjectId()
    campaign_id = str(oid)
    campaign.id = campaign_id

    campaign_doc = campaign.model_dump(by_alias=True, exclude={"id"})
    campaign_doc["_id"] = campaign_id
    campaign_doc["target_port"] = port
    await db.auth_test_campaigns.insert_one(campaign_doc)

    # Lancer les tests en arrière-plan
    async def _run():
        try:
            tester = AuthTester(db)
            await tester.run_auth_campaign(campaign)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Erreur campagne {campaign.id}: {e}")
        finally:
            # Nettoyer le fichier temporaire
            if saved_cred_path and os.path.exists(saved_cred_path):
                os.unlink(saved_cred_path)

    task = asyncio.ensure_future(_run())
    _running_tasks.append(task)

    return campaign


# ── Routes avec path parameters (APrès les routes statiques) ──


@router.get(
    "/host/{ip}",
    response_model=list[AuthTestResult],
    summary="Résultats d'authentification par hôte",
    description="Retourne tous les résultats de tests d'authentification pour un hôte spécifique.",
    tags=["auth-tests"],
)
async def get_auth_results_by_host(
    ip: str,
    limit: int = Query(100, ge=1, le=500, description="Nombre maximum de résultats"),
    user: Optional[str] = Depends(get_current_user),
):
    """Récupère les résultats de tests d'authentification pour un hôte."""
    db = await get_database()
    cursor = db.auth_test_results.find({"host_ip": ip}).sort("timestamp", -1).limit(limit)
    results = []
    async for doc in cursor:
        if "_id" in doc:
            doc["_id"] = str(doc["_id"])
        results.append(AuthTestResult(**doc))
    return results


@router.post(
    "/credentials",
    response_model=dict,
    summary="Uploader un fichier de credentials",
    description="Upload un fichier de credentials au format username:password (un par ligne).",
    tags=["auth-tests"],
)
async def upload_credentials_file(
    file: UploadFile = File(..., description="Fichier de credentials"),
    name: Optional[str] = Query(None, description="Nom personnalisé pour le fichier"),
    user: Optional[str] = Depends(get_current_user),
):
    """Upload un fichier de credentials personnalisé."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Nom de fichier manquant")

    # Vérifier le type de fichier
    allowed_extensions = [".txt", ".csv", ".lst"]
    file_ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Type de fichier non supporté. Utilisez: {', '.join(allowed_extensions)}",
        )

    # Lire et valider le contenu
    content = await file.read()
    try:
        text_content = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Le fichier doit être encodé en UTF-8")

    lines = [line.strip() for line in text_content.splitlines() if line.strip()]
    valid_lines = []
    for line in lines:
        if ":" in line:
            valid_lines.append(line)

    if not valid_lines:
        raise HTTPException(
            status_code=400,
            detail="Aucun credential valide trouvé. Format attendu: username:password",
        )

    # Sauvegarder le fichier
    db = await get_database()
    filename = name or file.filename
    await db.credentials_files.insert_one(
        {
            "filename": filename,
            "original_filename": file.filename,
            "content": "\n".join(valid_lines),
            "credentials_count": len(valid_lines),
            "uploaded_at": __import__("datetime").datetime.utcnow(),
        }
    )

    return {
        "message": "Fichier uploadé avec succès",
        "filename": filename,
        "credentials_count": len(valid_lines),
    }


@router.get(
    "/{campaign_id}",
    response_model=AuthCampaign,
    summary="Résultats d'une campagne de tests d'authentification",
    description="Retourne les résultats détaillés d'une campagne de tests.",
    tags=["auth-tests"],
)
async def get_auth_test_campaign(
    campaign_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Récupère les résultats d'une campagne de tests d'authentification."""
    db = await get_database()
    doc = await db.auth_test_campaigns.find_one({"_id": campaign_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Campagne non trouvée")
    doc["_id"] = str(doc["_id"])
    return AuthCampaign(**doc)


@router.delete(
    "/{campaign_id}",
    summary="Supprimer une campagne de tests d'authentification",
    description="Supprime une campagne et sa progression associée.",
    tags=["auth-tests"],
)
async def delete_auth_test_campaign(
    campaign_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Supprime une campagne de tests d'authentification."""
    db = await get_database()
    result = await db.auth_test_campaigns.delete_one({"_id": campaign_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Campagne non trouvée")
    # Supprimer aussi la progression associée
    await db.campaign_progress.delete_one({"_id": campaign_id})
    return {"status": "deleted", "campaign_id": campaign_id}


@router.get(
    "/{campaign_id}/progress",
    response_model=dict,
    summary="Progression d'une campagne en cours",
    description="Retourne le pourcentage et les détails de progression d'une campagne.",
    tags=["auth-tests"],
)
async def get_campaign_progress(
    campaign_id: str,
    user: Optional[str] = Depends(get_current_user),
):
    """Retourne la progression en temps réel d'une campagne brute force."""
    db = await get_database()
    
    # Récupérer la progression depuis campaign_progress
    progress = await db["campaign_progress"].find_one({"_id": campaign_id})
    
    if not progress:
        # Vérifier si la campagne existe dans auth_test_campaigns
        campaign = await db["auth_test_campaigns"].find_one({"_id": campaign_id})
        if not campaign:
            raise HTTPException(status_code=404, detail="Campagne non trouvée")
        
        # Retourner un état par défaut
        return {
            "campaign_id": campaign_id,
            "status": campaign.get("status", "pending"),
            "percentage": 0 if campaign.get("status") != "completed" else 100,
            "current_target": None,
            "total_targets": len(campaign.get("targets", [])),
            "tests_completed": 0,
            "total_tests": 0,
            "successes": 0,
            "failures": 0,
            "updated_at": campaign.get("created_at"),
        }
    
    # Calculer le pourcentage
    total_tests = progress.get("total_tests", 0)
    tests_completed = progress.get("tests_completed", 0)
    percentage = round((tests_completed / total_tests * 100), 1) if total_tests > 0 else 0
    
    # Si la campagne est terminée, forcer 100%
    status = progress.get("status", "running")
    if status == "completed":
        percentage = 100
    elif status == "failed":
        percentage = -1  # Indiquer une erreur
    
    return {
        "campaign_id": campaign_id,
        "status": status,
        "percentage": percentage,
        "current_target": progress.get("current_target"),
        "total_targets": progress.get("total_targets", 0),
        "current_target_index": progress.get("current_target_index", 0),
        "tests_completed": tests_completed,
        "total_tests": total_tests,
        "successes": progress.get("successes", 0),
        "failures": progress.get("failures", 0),
        "updated_at": progress.get("updated_at"),
    }


# ── SSH Terminal ──


class SSHExecRequest(BaseModel):
    host_ip: str
    port: int = 22
    username: str
    password: str
    command: str


class SSHExecResponse(BaseModel):
    stdout: str
    stderr: str
    exit_code: int


@router.post(
    "/ssh-exec",
    response_model=SSHExecResponse,
    summary="Exécuter une commande SSH",
    description="Exécute une commande SSH sur une cible avec les identifiants fournis.",
)
async def ssh_exec(
    payload: SSHExecRequest,
    user: Optional[str] = Depends(get_current_user),
):
    """Exécute une commande SSH sur la cible."""
    import paramiko

    def _exec():
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=payload.host_ip,
                port=payload.port,
                username=payload.username,
                password=payload.password,
                timeout=10,
                auth_timeout=10,
                banner_timeout=30,
            )
            stdin, stdout, stderr = client.exec_command(payload.command, timeout=30)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            client.close()
            return SSHExecResponse(stdout=out, stderr=err, exit_code=exit_code)
        except Exception as e:
            return SSHExecResponse(stdout="", stderr=str(e), exit_code=-1)

    return await asyncio.to_thread(_exec)
