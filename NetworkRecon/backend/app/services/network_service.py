"""Service de gestion des plages réseau."""

from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.network import NetworkRange, NetworkRangeCreate
from app.utils.database import get_database


class NetworkService:
    """Service CRUD pour les plages réseau."""

    async def _get_db(self) -> AsyncIOMotorDatabase:
        return await get_database()

    async def list_ranges(self, limit: int = 50, offset: int = 0) -> list[NetworkRange]:
        """Liste les plages réseau."""
        db = await self._get_db()
        cursor = db.network_ranges.find().sort("created_at", -1).skip(offset).limit(limit)
        ranges = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            ranges.append(NetworkRange(**doc))
        return ranges

    async def create_range(self, range_data: NetworkRangeCreate) -> NetworkRange:
        """Crée une nouvelle plage réseau."""
        db = await self._get_db()
        net_range = NetworkRange(**range_data.model_dump())
        result = await db.network_ranges.insert_one(
            net_range.model_dump(by_alias=True, exclude={"id"})
        )
        net_range.id = str(result.inserted_id)
        return net_range

    async def get_range(self, range_id: str) -> Optional[NetworkRange]:
        """Récupère une plage réseau par son ID."""
        db = await self._get_db()
        doc = await db.network_ranges.find_one({"_id": range_id})
        if doc:
            doc["_id"] = str(doc["_id"])
            return NetworkRange(**doc)
        return None

    async def delete_range(self, range_id: str) -> bool:
        """Supprime une plage réseau."""
        db = await self._get_db()
        result = await db.network_ranges.delete_one({"_id": range_id})
        return result.deleted_count > 0
