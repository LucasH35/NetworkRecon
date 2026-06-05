"""Service de gestion des hôtes réseau."""

from datetime import datetime
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.host import Host, HostCreate, HostUpdate
from app.utils.database import get_database


class HostService:
    """Service CRUD pour les hôtes réseau."""

    async def _get_db(self) -> AsyncIOMotorDatabase:
        return await get_database()

    async def list_hosts(
        self,
        status: Optional[str] = None,
        scan_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Host]:
        """Liste les hôtes avec filtrage et pagination."""
        db = await self._get_db()
        query = {}
        if status:
            query["status"] = status
        if scan_id:
            query["scan_id"] = scan_id

        cursor = db.hosts.find(query).sort("created_at", -1).skip(offset).limit(limit)
        hosts = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            hosts.append(Host(**doc))
        return hosts

    async def create_host(self, host_data: HostCreate) -> Host:
        """Crée un nouvel hôte."""
        db = await self._get_db()
        host = Host(**host_data.model_dump())
        result = await db.hosts.insert_one(host.model_dump(by_alias=True, exclude={"id"}))
        host.id = str(result.inserted_id)
        return host

    async def get_host(self, host_id: str) -> Optional[Host]:
        """Récupère un hôte par son ID."""
        db = await self._get_db()
        doc = await db.hosts.find_one({"_id": host_id})
        if doc:
            doc["_id"] = str(doc["_id"])
            return Host(**doc)
        return None

    async def update_host(self, host_id: str, update_data: HostUpdate) -> Optional[Host]:
        """Met à jour un hôte."""
        db = await self._get_db()
        update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
        update_dict["updated_at"] = datetime.utcnow()

        result = await db.hosts.update_one({"_id": host_id}, {"$set": update_dict})
        if result.modified_count > 0:
            return await self.get_host(host_id)
        return None

    async def delete_host(self, host_id: str) -> bool:
        """Supprime un hôte."""
        db = await self._get_db()
        result = await db.hosts.delete_one({"_id": host_id})
        return result.deleted_count > 0
