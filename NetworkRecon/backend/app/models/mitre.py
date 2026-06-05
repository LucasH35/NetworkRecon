"""Modèles Pydantic pour MITRE ATT&CK."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class MitreMapping(BaseModel):
    """Mapping vers une technique MITRE ATT&CK."""
    technique_id: str = Field(..., description="Identifiant de technique (ex: T1190)")
    technique_name: str = Field(..., description="Nom de la technique")
    tactic: str = Field(..., description="Tactique MITRE (ex: Initial Access)")
    description: Optional[str] = Field(None, description="Description de la technique")
    url: Optional[str] = Field(None, description="URL vers la documentation MITRE")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "technique_id": "T1190",
                    "technique_name": "Exploit Public-Facing Application",
                    "tactic": "Initial Access",
                    "description": "Exploitation d'une application exposée publiquement",
                    "url": "https://attack.mitre.org/techniques/T1190/"
                }
            ]
        }
    }

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, v: str) -> str:
        import re
        pattern = r"^T\d{4}(\.\d{3})?$"
        if not re.match(pattern, v):
            raise ValueError(f"Format de technique MITRE invalide: {v}")
        return v

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not v.startswith(("http://", "https://")):
            raise ValueError("L'URL doit commencer par http:// ou https://")
        return v


class ServiceToMitre(BaseModel):
    """Mapping d'un service vers les techniques MITRE ATT&CK."""
    service_name: str = Field(..., description="Nom du service (ex: ssh, http, smb)")
    version: Optional[str] = Field(None, description="Version du service")
    mappings: List[MitreMapping] = Field(default_factory=list, description="Liste des mappings MITRE")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "service_name": "ssh",
                    "version": "OpenSSH 8.9",
                    "mappings": [
                        {
                            "technique_id": "T1021",
                            "technique_name": "Remote Services",
                            "tactic": "Lateral Movement",
                            "description": "Utilisation de services distants pour le mouvement latéral",
                            "url": "https://attack.mitre.org/techniques/T1021/"
                        },
                        {
                            "technique_id": "T1078",
                            "technique_name": "Valid Accounts",
                            "tactic": "Initial Access",
                            "description": "Utilisation de comptes valides pour l'accès initial",
                            "url": "https://attack.mitre.org/techniques/T1078/"
                        }
                    ]
                }
            ]
        }
    }

    @field_validator("service_name")
    @classmethod
    def validate_service_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Le nom du service ne peut pas être vide")
        return v.strip().lower()