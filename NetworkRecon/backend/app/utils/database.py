"""Gestion de la connexion à MongoDB avec Motor."""

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.config import settings

_client: AsyncIOMotorClient | None = None


async def get_database() -> AsyncIOMotorDatabase:
    """Retourne une instance de la base de données MongoDB."""
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(settings.MONGO_URI)
    return _client[settings.MONGO_DB_NAME]


async def close_database() -> None:
    """Ferme la connexion à MongoDB."""
    global _client
    if _client is not None:
        _client.close()
        _client = None
