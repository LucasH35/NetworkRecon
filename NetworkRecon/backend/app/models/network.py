"""Modèles Pydantic pour les plages réseau."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class NetworkRangeCreate(BaseModel):
    """Modèle pour la création d'une plage réseau."""
    name: str
    cidr: str = Field(..., description="Plage CIDR (ex: 192.168.1.0/24)")
    description: Optional[str] = None


class NetworkRange(BaseModel):
    """Modèle complet d'une plage réseau."""
    id: Optional[str] = Field(None, alias="_id")
    name: str
    cidr: str
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"populate_by_name": True}
