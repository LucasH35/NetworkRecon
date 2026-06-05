"""Modèles Pydantic pour les tests d'authentification."""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class ServiceType(str, Enum):
    """Type de service pour les tests d'authentification."""
    SSH = "ssh"
    FTP = "ftp"
    SMB = "smb"
    RDP = "rdp"
    HTTP = "http"
    HTTPS = "https"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    REDIS = "redis"
    MONGODB = "mongodb"


class AuthTestConfig(BaseModel):
    """Configuration pour un test d'authentification."""
    service_type: ServiceType = Field(..., description="Type de service à tester")
    credentials_file: Optional[str] = Field(None, description="Chemin vers le fichier de credentials")
    max_attempts: int = Field(default=5, ge=1, le=100, description="Nombre maximum de tentatives")
    delay_between: float = Field(default=1.0, ge=0.1, le=60.0, description="Délai entre les tentatives (secondes)")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "service_type": "ssh",
                    "credentials_file": "/path/to/credentials.txt",
                    "max_attempts": 10,
                    "delay_between": 2.0
                }
            ]
        }
    }

    @field_validator("credentials_file")
    @classmethod
    def validate_credentials_file(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.strip():
            raise ValueError("Le chemin du fichier de credentials ne peut pas être vide")
        return v


class AuthTestResult(BaseModel):
    """Résultat d'un test d'authentification."""
    host_ip: str = Field(..., description="Adresse IP de l'hôte testé")
    port: int = Field(..., ge=1, le=65535, description="Port du service")
    service: ServiceType = Field(..., description="Type de service testé")
    credential_used: str = Field(..., description="Credential utilisé (masqué dans les logs)")
    success: bool = Field(..., description="Succès ou échec de l'authentification")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Horodatage du test")
    error_message: Optional[str] = Field(None, description="Message d'erreur en cas d'échec")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "host_ip": "192.168.1.100",
                    "port": 22,
                    "service": "ssh",
                    "credential_used": "admin:***",
                    "success": True,
                    "timestamp": "2026-06-03T10:00:00Z",
                    "error_message": None
                }
            ]
        }
    }

    @field_validator("host_ip")
    @classmethod
    def validate_host_ip(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Adresse IP invalide: {v}")
        return v

    @field_validator("credential_used")
    @classmethod
    def validate_credential_used(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Le credential utilisé ne peut pas être vide")
        return v


class AuthCampaignStatus(str, Enum):
    """Statut d'une campagne de test d'authentification."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AuthCampaign(BaseModel):
    """Campagne de test d'authentification complète."""
    id: Optional[str] = Field(None, alias="_id", description="Identifiant MongoDB")
    name: str = Field(..., description="Nom de la campagne")
    targets: List[str] = Field(..., description="Liste des IPs cibles")
    config: AuthTestConfig = Field(..., description="Configuration des tests")
    results: List[AuthTestResult] = Field(default_factory=list, description="Résultats des tests")
    status: AuthCampaignStatus = Field(default=AuthCampaignStatus.PENDING, description="Statut de la campagne")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Date de création")
    completed_at: Optional[datetime] = Field(None, description="Date de complétion")

    model_config = {
        "populate_by_name": True,
        "json_schema_extra": {
            "examples": [
                {
                    "_id": "507f1f77bcf86cd799439014",
                    "name": "Test d'authentification SSH",
                    "targets": ["192.168.1.100", "192.168.1.101", "192.168.1.102"],
                    "config": {
                        "service_type": "ssh",
                        "credentials_file": "/path/to/ssh_credentials.txt",
                        "max_attempts": 5,
                        "delay_between": 1.0
                    },
                    "results": [],
                    "status": "pending",
                    "created_at": "2026-06-03T09:00:00Z",
                    "completed_at": None
                }
            ]
        }
    }

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: List[str]) -> List[str]:
        import ipaddress
        for ip in v:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ValueError(f"Adresse IP invalide dans les cibles: {ip}")
        return v


# ── Modèles pour les suggestions d'attaque ──────────────────────────────


class AttackSeverity(str, Enum):
    """Niveau de priorité d'une attaque suggérée."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AttackSuggestion(BaseModel):
    """Suggestion d'attaque brute force basée sur les CVE/services découverts."""
    host_ip: str = Field(..., description="IP de la cible")
    hostname: Optional[str] = Field(None, description="Hostname de la cible")
    service: ServiceType = Field(..., description="Service à attaquer")
    port: int = Field(..., ge=1, le=65535, description="Port du service")
    severity: AttackSeverity = Field(..., description="Priorité de l'attaque")
    reason: str = Field(..., description="Raison de la suggestion (ex: CVE trouvée)")
    cve_ids: List[str] = Field(default_factory=list, description="CVE associées à cette attaque")
    description: str = Field(..., description="Description de l'attaque suggérée")
    recommended_wordlist: Optional[str] = Field(None, description="Wordlist recommandée")
    estimated_duration: Optional[str] = Field(None, description="Durée estimée de l'attaque")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "host_ip": "192.168.1.100",
                    "hostname": "webserver",
                    "service": "ssh",
                    "port": 22,
                    "severity": "high",
                    "reason": "OpenSSH 8.9 détecté - vulnérable à CVE-2023-38408",
                    "cve_ids": ["CVE-2023-38408"],
                    "description": "Test de brute force SSH sur OpenSSH avec CVE critique",
                    "recommended_wordlist": "rockyou.txt",
                    "estimated_duration": "~5 minutes"
                }
            ]
        }
    }