"""Service de gestion des scans réseau."""

import asyncio
from datetime import datetime
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.config import settings
from app.models.scan import Scan, ScanCreate, ScanStatus
from app.scanners.nmap_scanner import NmapScanner
from app.utils.database import get_database


class ScanService:
    """Service orchestrateur pour les scans réseau."""

    def __init__(self):
        self._scanner = NmapScanner()
        self._active_tasks: dict[str, asyncio.Task] = {}

    async def _get_db(self) -> AsyncIOMotorDatabase:
        return await get_database()

    async def list_scans(
        self,
        status: Optional[ScanStatus] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Scan]:
        """Liste les scans avec filtrage et pagination."""
        db = await self._get_db()
        query = {}
        if status:
            query["status"] = status.value

        cursor = db.scans.find(query).sort("created_at", -1).skip(offset).limit(limit)
        scans = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            scans.append(Scan(**doc))
        return scans

    async def create_scan(self, scan_data: ScanCreate) -> Scan:
        """Crée et lance un nouveau scan."""
        db = await self._get_db()
        scan_doc = Scan(
            target=scan_data.target,
            scan_type=scan_data.scan_type,
            ports=scan_data.ports,
            options=scan_data.options,
            status=ScanStatus.PENDING,
        )

        result = await db.scans.insert_one(scan_doc.model_dump(by_alias=True, exclude={"id"}))
        scan_doc.id = str(result.inserted_id)

        # Lancer le scan en arrière-plan
        task = asyncio.create_task(self._run_scan(scan_doc))
        self._active_tasks[scan_doc.id] = task

        return scan_doc

    async def _run_scan(self, scan: Scan) -> None:
        """Exécute un scan en arrière-plan."""
        db = await self._get_db()
        try:
            await db.scans.update_one(
                {"_id": scan.id},
                {"$set": {"status": ScanStatus.RUNNING.value, "started_at": datetime.utcnow()}},
            )

            result = await self._scanner.execute(scan)

            await db.scans.update_one(
                {"_id": scan.id},
                {"$set": {
                    "status": ScanStatus.COMPLETED.value,
                    "result": result.model_dump(),
                    "completed_at": datetime.utcnow(),
                }},
            )
        except asyncio.CancelledError:
            await db.scans.update_one(
                {"_id": scan.id},
                {"$set": {"status": ScanStatus.CANCELLED.value}},
            )
        except Exception as e:
            await db.scans.update_one(
                {"_id": scan.id},
                {"$set": {
                    "status": ScanStatus.FAILED.value,
                    "error_message": str(e),
                    "completed_at": datetime.utcnow(),
                }},
            )
        finally:
            self._active_tasks.pop(scan.id, None)

    async def get_scan(self, scan_id: str) -> Optional[Scan]:
        """Récupère un scan par son ID."""
        db = await self._get_db()
        doc = await db.scans.find_one({"_id": scan_id})
        if doc:
            doc["_id"] = str(doc["_id"])
            return Scan(**doc)
        return None

    async def cancel_scan(self, scan_id: str) -> bool:
        """Annule un scan en cours."""
        task = self._active_tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            return True
        return False

    async def delete_scan(self, scan_id: str) -> bool:
        """Supprime un scan."""
        db = await self._get_db()
        result = await db.scans.delete_one({"_id": scan_id})
        return result.deleted_count > 0
