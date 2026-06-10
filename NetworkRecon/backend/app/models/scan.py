"""Modèles Pydantic pour les scans réseau."""

from datetime import datetime
from enum import Enum
from typing import Optional, Any

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    """Statut d'un scan."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, Enum):
    """Type de scan réseau."""
    PORT_SCAN = "port_scan"
    HOST_DISCOVERY = "host_discovery"
    OS_DETECTION = "os_detection"
    SERVICE_SCAN = "service_scan"
    FULL_SCAN = "full_scan"


# Ancien modèle conservé pour rétrocompatibilité
class ScanResultLegacy(BaseModel):
    """Résultat détaillé d'un scan (ancien format)."""
    hosts_found: int = 0
    ports_open: int = 0
    services_detected: list[dict[str, Any]] = []
    raw_output: Optional[str] = None


class ScanCreate(BaseModel):
    """Modèle pour la création d'un scan."""
    target: str = Field(..., description="Cible du scan (IP, CIDR, ou hostname)")
    scan_type: ScanType = ScanType.FULL_SCAN
    ports: Optional[list[int]] = Field(None, description="Ports spécifiques à scanner")
    options: dict[str, Any] = Field(default_factory=dict)


class Scan(BaseModel):
    """Modèle complet d'un scan avec identifiant MongoDB."""
    id: Optional[str] = Field(None, alias="_id")
    target: str
    scan_type: ScanType
    status: ScanStatus = ScanStatus.PENDING
    ports: Optional[list[int]] = None
    options: dict[str, Any] = {}
    result: Optional[ScanResultLegacy] = None
    error_message: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    model_config = {"populate_by_name": True}


# ===================== Nouveaux modèles pour NetworkRecon =====================

from enum import Enum
from typing import List, Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class ScanScanType(str, Enum):
    """Type de scan réseau (nouveau)."""
    QUICK = "quick"
    FULL = "full"
    STEALTH = "stealth"


class CampaignStatus(str, Enum):
    """Statut d'une campagne de scan."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanTarget(BaseModel):
    """Cible de scan réseau."""
    ip_range: str = Field(..., description="Plage IP (CIDR) ou nom de domaine (ex: 192.168.2.0/24 ou example.com)")
    authorized: bool = Field(default=False, description="Autorisation de scan obtenue")
    target_list: List[str] = Field(default_factory=list, description="Liste d'IPs spécifiques")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "ip_range": "192.168.2.0/24",
                    "authorized": True,
                    "target_list": ["192.168.2.1", "192.168.2.100"]
                }
            ]
        }
    }

    @field_validator("ip_range")
    @classmethod
    def validate_ip_range(cls, v: str) -> str:
        import ipaddress
        import re
        # Accepte un domaine (ex: example.com, sub.example.com)
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', v):
            return v
        # Accepte une plage IP CIDR
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"Cible invalide: {v} — attendu une plage IP (CIDR) ou un nom de domaine")
        return v


class ScanConfig(BaseModel):
    """Configuration d'un scan réseau."""
    scan_type: ScanScanType = Field(default=ScanScanType.FULL, description="Type de scan")
    ports_range: Optional[str] = Field(None, description="Plage de ports (ex: 1-1024, 80,443)")
    timeout: int = Field(default=300, ge=1, le=3600, description="Timeout en secondes")
    rate_limit: int = Field(default=1000, ge=1, le=10000, description="Limite de paquets/seconde")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "scan_type": "full",
                    "ports_range": "1-1024,8080,8443",
                    "timeout": 600,
                    "rate_limit": 500
                }
            ]
        }
    }

    @field_validator("ports_range")
    @classmethod
    def validate_ports_range(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        import re
        # Format: "1-1024,80,443" ou "1-1024" ou "80"
        pattern = r"^(\d{1,5}(-\d{1,5})?)(,\d{1,5}(-\d{1,5})?)*$"
        if not re.match(pattern, v):
            raise ValueError(f"Format de ports invalide: {v}")
        return v


class ScanResult(BaseModel):
    """Résultat d'un scan réseau."""
    scan_id: str = Field(..., description="Identifiant du scan")
    target: str = Field(..., description="Cible scannée")
    start_time: datetime = Field(default_factory=datetime.utcnow, description="Heure de début")
    end_time: Optional[datetime] = Field(None, description="Heure de fin")
    hosts_found: List[str] = Field(default_factory=list, description="Liste des IPs découvertes")
    status: ScanStatus = Field(default=ScanStatus.PENDING, description="Statut du scan")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "scan_id": "507f1f77bcf86cd799439011",
                    "target": "192.168.2.0/24",
                    "start_time": "2026-06-03T10:00:00Z",
                    "end_time": "2026-06-03T10:05:00Z",
                    "hosts_found": ["192.168.2.1", "192.168.2.100", "192.168.2.200"],
                    "status": "completed"
                }
            ]
        }
    }


class Campaign(BaseModel):
    """Campagne de scan complète."""
    id: Optional[str] = Field(None, alias="_id", description="Identifiant MongoDB")
    name: str = Field(..., description="Nom de la campagne")
    description: Optional[str] = Field(None, description="Description de la campagne")
    targets: List[ScanTarget] = Field(..., description="Liste des cibles")
    config: ScanConfig = Field(default_factory=ScanConfig, description="Configuration du scan")
    results: List[ScanResult] = Field(default_factory=list, description="Résultats des scans")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Date de création")
    status: CampaignStatus = Field(default=CampaignStatus.PENDING, description="Statut de la campagne")
    progress: Optional[float] = Field(default=0.0, description="Pourcentage de progression (0-100)")

    model_config = {
        "populate_by_name": True,
        "json_schema_extra": {
            "examples": [
                {
                    "_id": "507f1f77bcf86cd799439012",
                    "name": "Scan réseau principal",
                    "description": "Scan complet du réseau interne",
                    "targets": [
                        {
                            "ip_range": "192.168.2.0/24",
                            "authorized": True,
                            "target_list": []
                        }
                    ],
                    "config": {
                        "scan_type": "full",
                        "ports_range": "1-1024",
                        "timeout": 600,
                        "rate_limit": 1000
                    },
                    "results": [],
                    "created_at": "2026-06-03T09:00:00Z",
                    "status": "pending"
                }
            ]
        }
    }
