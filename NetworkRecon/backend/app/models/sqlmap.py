"""
Modèles Pydantic pour les campagnes SQLMap.
Gère les configurations, résultats et campagnes de test d'injection SQL.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class SqlmapStatus(str, Enum):
    """Statuts possibles d'une campagne SQLMap."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SqlmapTechnique(str, Enum):
    """Techniques d'injection SQL supportées par SQLMap."""
    BOOLEAN = "B"   # Boolean-based blind
    UNION = "U"     # UNION query-based
    ERROR = "E"     # Error-based
    STACKED = "S"   # Stacked queries
    TIME = "T"      # Time-based blind
    INLINE = "I"    # Inline query


class SqlmapLevel(int, Enum):
    """Niveau de test SQLMap (1-5)."""
    LEVEL_1 = 1
    LEVEL_2 = 2
    LEVEL_3 = 3
    LEVEL_4 = 4
    LEVEL_5 = 5


class SqlmapRisk(int, Enum):
    """Niveau de risque SQLMap (1-3)."""
    RISK_1 = 1
    RISK_2 = 2
    RISK_3 = 3


class SqlmapConfig(BaseModel):
    """Configuration d'une campagne SQLMap."""
    target_url: str = Field(..., description="URL cible à tester")
    data: Optional[str] = Field(None, description="Données POST à envoyer")
    cookie: Optional[str] = Field(None, description="Cookie HTTP")
    level: int = Field(1, ge=1, le=5, description="Niveau de test (1-5)")
    risk: int = Field(1, ge=1, le=3, description="Niveau de risque (1-3)")
    techniques: str = Field(
        "BEUST",
        description="Techniques: B=Boolean, E=Error, U=Union, S=Stacked, T=Time, I=Inline"
    )
    dbms: Optional[str] = Field(None, description="Forcer le DBMS (mysql, postgresql, etc.)")
    tamper: Optional[str] = Field(None, description="Scripts tamper séparés par des virgules")
    threads: int = Field(1, ge=1, le=10, description="Nombre de threads")
    depth_crawl: int = Field(1, ge=0, le=5, description="Profondeur de crawl (0=désactivé)")
    forms: bool = Field(False, description="Tester les formulaires HTML")
    random_agent: bool = Field(True, description="User-Agent aléatoire")
    verbose: int = Field(0, ge=0, le=3, description="Verbosité (0-3)")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "target_url": "http://192.168.2.100/page?id=1",
                    "level": 2,
                    "risk": 1,
                    "techniques": "BEUST",
                    "forms": True,
                }
            ]
        }
    }


class SqlmapVulnerability(BaseModel):
    """Une vulnérabilité SQL injection découverte."""
    parameter: str = Field(..., description="Paramètre vulnérable")
    injection_type: str = Field(..., description="Type d'injection (GET, POST, Cookie, etc.)")
    title: str = Field(..., description="Titre de la vulnérabilité")
    dbms: Optional[str] = Field(None, description="DBMS détecté")
    payload: Optional[str] = Field(None, description="Payload utilisé")
    payload_title: Optional[str] = Field(None, description="Titre du payload")
    data: Optional[str] = Field(None, description="Données extraites")
    is_empty: bool = Field(False, description="Si True, pas de données extraites")


class SqlmapDatabase(BaseModel):
    """Base de données découverte."""
    name: str = Field(..., description="Nom de la base de données")
    tables_count: int = Field(0, description="Nombre de tables")
    tables: list[str] = Field(default_factory=list, description="Liste des tables")


class SqlmapResult(BaseModel):
    """Résultat complet d'un test SQLMap sur une URL."""
    target_url: str = Field(..., description="URL testée")
    parameter: Optional[str] = Field(None, description="Paramètre vulnérable")
    injection_type: Optional[str] = Field(None, description="Type d'injection")
    title: Optional[str] = Field(None, description="Titre de la vulnérabilité")
    dbms: Optional[str] = Field(None, description="DBMS détecté")
    os: Optional[str] = Field(None, description="OS du serveur")
    vulnerabilities: list[SqlmapVulnerability] = Field(
        default_factory=list, description="Vulnérabilités trouvées"
    )
    databases: list[SqlmapDatabase] = Field(
        default_factory=list, description="Bases de données découvertes"
    )
    error_message: Optional[str] = Field(None, description="Message d'erreur si échec")
    raw_output: Optional[str] = Field(None, description="Sortie brute de sqlmap")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SqlmapCampaign(BaseModel):
    """Campagne SQLMap complète."""
    id: Optional[str] = Field(None, alias="_id")
    name: str = Field(..., description="Nom de la campagne")
    target_url: str = Field(..., description="URL cible principale")
    config: SqlmapConfig = Field(..., description="Configuration SQLMap")
    status: SqlmapStatus = Field(SqlmapStatus.PENDING, description="Statut de la campagne")
    results: list[SqlmapResult] = Field(default_factory=list, description="Résultats des tests")
    total_urls: int = Field(0, description="Nombre total d'URLs à tester")
    urls_completed: int = Field(0, description="Nombre d'URLs testées")
    vulnerabilities_count: int = Field(0, description="Nombre total de vulnérabilités")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = Field(None, description="Date de fin")
    error_message: Optional[str] = Field(None, description="Message d'erreur global")

    model_config = {
        "populate_by_name": True,
        "json_schema_extra": {
            "examples": [
                {
                    "name": "Test injection SQL - Site interne",
                    "target_url": "http://192.168.2.100/",
                    "config": {
                        "target_url": "http://192.168.2.100/",
                        "level": 2,
                        "risk": 1,
                        "forms": True,
                    }
                }
            ]
        }
    }


class SqlmapCampaignCreate(BaseModel):
    """Modèle pour créer une campagne SQLMap."""
    name: str = Field(..., min_length=1, max_length=200, description="Nom de la campagne")
    target_url: str = Field(..., description="URL cible à tester")
    data: Optional[str] = Field(None, description="Données POST")
    cookie: Optional[str] = Field(None, description="Cookie HTTP")
    level: int = Field(1, ge=1, le=5)
    risk: int = Field(1, ge=1, le=3)
    techniques: str = Field("BEUST")
    dbms: Optional[str] = Field(None)
    tamper: Optional[str] = Field(None)
    threads: int = Field(1, ge=1, le=10)
    depth_crawl: int = Field(1, ge=0, le=5)
    forms: bool = Field(False)
    random_agent: bool = Field(True)
