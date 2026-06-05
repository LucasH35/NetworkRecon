"""Modèles Pydantic pour les hôtes réseau."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class HostStatus(str, Enum):
    """Statut d'un hôte."""
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class Port(BaseModel):
    """Représentation d'un port ouvert."""
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None


class HostBase(BaseModel):
    """Modèle de base pour un hôte."""
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    os_guess: Optional[str] = None
    status: HostStatus = HostStatus.UNKNOWN


class HostCreate(HostBase):
    """Modèle pour la création d'un hôte."""
    pass


class HostUpdate(BaseModel):
    """Modèle pour la mise à jour d'un hôte."""
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    os_guess: Optional[str] = None
    status: Optional[HostStatus] = None
    ports: Optional[list[Port]] = None


class Host(HostBase):
    """Modèle complet d'un hôte avec identifiant MongoDB."""
    id: Optional[str] = Field(None, alias="_id")
    ports: list[Port] = []
    scan_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"populate_by_name": True}


# ===================== Nouveaux modèles pour NetworkRecon =====================

from enum import Enum
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class Protocol(str, Enum):
    """Protocole réseau."""
    TCP = "tcp"
    UDP = "udp"


class PortState(str, Enum):
    """État d'un port."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class PortInfo(BaseModel):
    """Information détaillée sur un port."""
    number: int = Field(..., ge=1, le=65535, description="Numéro du port (1-65535)")
    protocol: Protocol = Field(default=Protocol.TCP, description="Protocole (tcp/udp)")
    state: PortState = Field(default=PortState.OPEN, description="État du port (open/closed/filtered)")
    service: Optional[str] = Field(None, description="Nom du service détecté")
    version: Optional[str] = Field(None, description="Version du service")
    banner: Optional[str] = Field(None, description="Banner du service")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "number": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "version": "OpenSSH 8.9",
                    "banner": "SSH-2.0-OpenSSH_8.9p1"
                }
            ]
        }
    }

    @field_validator("number")
    @classmethod
    def validate_port_number(cls, v: int) -> int:
        if not 1 <= v <= 65535:
            raise ValueError("Le numéro de port doit être entre 1 et 65535")
        return v


class HostInfo(BaseModel):
    """Information complète sur un hôte réseau."""
    ip_address: str = Field(..., description="Adresse IP de l'hôte")
    hostname: Optional[str] = Field(None, description="Nom d'hôte (DNS)")
    mac_address: Optional[str] = Field(None, description="Adresse MAC")
    os_detection: Optional[str] = Field(None, description="Système d'exploitation détecté")
    status: str = Field(default="up", description="Statut de l'hôte (up/down)")
    ports: List[PortInfo] = Field(default_factory=list, description="Liste des ports scannés")
    last_seen: datetime = Field(default_factory=datetime.utcnow, description="Dernière détection")
    first_seen: datetime = Field(default_factory=datetime.utcnow, description="Première détection")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "ip_address": "192.168.1.100",
                    "hostname": "webserver.local",
                    "mac_address": "AA:BB:CC:DD:EE:FF",
                    "os_detection": "Linux 5.4",
                    "status": "up",
                    "ports": [
                        {
                            "number": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "ssh",
                            "version": "OpenSSH 8.9",
                            "banner": "SSH-2.0-OpenSSH_8.9p1"
                        },
                        {
                            "number": 80,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "http",
                            "version": "nginx 1.18",
                            "banner": "HTTP/1.1 200 OK"
                        }
                    ],
                    "last_seen": "2026-06-03T10:00:00Z",
                    "first_seen": "2026-06-03T09:00:00Z"
                }
            ]
        }
    }

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Adresse IP invalide: {v}")
        return v

    @field_validator("mac_address")
    @classmethod
    def validate_mac_address(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        import re
        mac_pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        if not re.match(mac_pattern, v):
            raise ValueError(f"Adresse MAC invalide: {v}")
        return v


class HostCreate(BaseModel):
    """Modèle pour la création d'un hôte via API."""
    ip_address: str = Field(..., description="Adresse IP de l'hôte")
    hostname: Optional[str] = Field(None, description="Nom d'hôte (DNS)")
    mac_address: Optional[str] = Field(None, description="Adresse MAC")
    os_detection: Optional[str] = Field(None, description="Système d'exploitation détecté")
    ports: List[PortInfo] = Field(default_factory=list, description="Liste des ports scannés")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "ip_address": "192.168.1.100",
                    "hostname": "webserver.local",
                    "mac_address": "AA:BB:CC:DD:EE:FF",
                    "os_detection": "Linux 5.4",
                    "ports": [
                        {
                            "number": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "ssh",
                            "version": "OpenSSH 8.9"
                        }
                    ]
                }
            ]
        }
    }


class HostResponse(BaseModel):
    """Modèle de réponse pour un hôte."""
    id: str = Field(..., alias="_id", description="Identifiant MongoDB")
    ip_address: str = Field(..., description="Adresse IP de l'hôte")
    hostname: Optional[str] = Field(None, description="Nom d'hôte (DNS)")
    mac_address: Optional[str] = Field(None, description="Adresse MAC")
    os_detection: Optional[str] = Field(None, description="Système d'exploitation détecté")
    status: str = Field(default="up", description="Statut de l'hôte (up/down)")
    ports: List[PortInfo] = Field(default_factory=list, description="Liste des ports scannés")
    last_seen: datetime = Field(default_factory=datetime.utcnow, description="Dernière détection")
    first_seen: datetime = Field(default_factory=datetime.utcnow, description="Première détection")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Date de création")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Date de mise à jour")

    model_config = {
        "populate_by_name": True,
        "json_schema_extra": {
            "examples": [
                {
                    "_id": "507f1f77bcf86cd799439011",
                    "ip_address": "192.168.1.100",
                    "hostname": "webserver.local",
                    "mac_address": "AA:BB:CC:DD:EE:FF",
                    "os_detection": "Linux 5.4",
                    "status": "up",
                    "ports": [
                        {
                            "number": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "ssh",
                            "version": "OpenSSH 8.9",
                            "banner": "SSH-2.0-OpenSSH_8.9p1"
                        }
                    ],
                    "last_seen": "2026-06-03T10:00:00Z",
                    "first_seen": "2026-06-03T09:00:00Z",
                    "created_at": "2026-06-03T09:00:00Z",
                    "updated_at": "2026-06-03T10:00:00Z"
                }
            ]
        }
    }
