"""Modèles Pydantic pour les rapports."""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator


class ExportFormat(str, Enum):
    """Format d'exportation des rapports."""
    PDF = "pdf"
    CSV = "csv"
    JSON = "json"
    HTML = "html"


class ReportSummary(BaseModel):
    """Résumé d'un rapport de scan."""
    total_hosts: int = Field(default=0, ge=0, description="Nombre total d'hôtes découverts")
    total_services: int = Field(default=0, ge=0, description="Nombre total de services détectés")
    total_vulnerabilities: int = Field(default=0, ge=0, description="Nombre total de vulnérabilités")
    by_severity: Dict[str, int] = Field(
        default_factory=lambda: {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        },
        description="Répartition par sévérité"
    )
    scan_duration: Optional[float] = Field(None, ge=0, description="Durée du scan en secondes")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "total_hosts": 25,
                    "total_services": 150,
                    "total_vulnerabilities": 42,
                    "by_severity": {
                        "critical": 5,
                        "high": 12,
                        "medium": 15,
                        "low": 8,
                        "info": 2
                    },
                    "scan_duration": 3600.5
                }
            ]
        }
    }

    @field_validator("by_severity")
    @classmethod
    def validate_by_severity(cls, v: Dict[str, int]) -> Dict[str, int]:
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for key in v.keys():
            if key not in valid_severities:
                raise ValueError(f"Sévérité invalide: {key}. Doit être l'une des: {valid_severities}")
        return v


class Report(BaseModel):
    """Rapport complet de scan."""
    id: Optional[str] = Field(None, alias="_id", description="Identifiant MongoDB")
    campaign_id: str = Field(..., description="Identifiant de la campagne associée")
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Date de génération du rapport")
    summary: ReportSummary = Field(..., description="Résumé du rapport")
    content: Dict[str, Any] = Field(default_factory=dict, description="Contenu détaillé du rapport")
    export_format: ExportFormat = Field(default=ExportFormat.JSON, description="Format d'exportation")
    title: Optional[str] = Field(None, description="Titre du rapport")
    description: Optional[str] = Field(None, description="Description du rapport")
    generated_by: Optional[str] = Field(None, description="Utilisateur ou service ayant généré le rapport")

    model_config = {
        "populate_by_name": True,
        "json_schema_extra": {
            "examples": [
                {
                    "_id": "507f1f77bcf86cd799439015",
                    "campaign_id": "507f1f77bcf86cd799439012",
                    "generated_at": "2026-06-03T10:30:00Z",
                    "summary": {
                        "total_hosts": 25,
                        "total_services": 150,
                        "total_vulnerabilities": 42,
                        "by_severity": {
                            "critical": 5,
                            "high": 12,
                            "medium": 15,
                            "low": 8,
                            "info": 2
                        },
                        "scan_duration": 3600.5
                    },
                    "content": {
                        "hosts": [
                            {
                                "ip": "192.168.1.100",
                                "hostname": "webserver.local",
                                "services": 8,
                                "vulnerabilities": 3
                            }
                        ],
                        "top_vulnerabilities": [
                            {
                                "cve_id": "CVE-2023-1234",
                                "severity": "critical",
                                "affected_hosts": 5
                            }
                        ],
                        "recommendations": [
                            "Mettre à jour Log4j sur 5 serveurs",
                            "Configurer le pare-feu pour le port 3389"
                        ]
                    },
                    "export_format": "json",
                    "title": "Rapport de scan réseau - Juin 2026",
                    "description": "Rapport complet du scan du réseau interne",
                    "generated_by": "admin@networkrecon.local"
                }
            ]
        }
    }

    @field_validator("campaign_id")
    @classmethod
    def validate_campaign_id(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("L'identifiant de campagne ne peut pas être vide")
        return v