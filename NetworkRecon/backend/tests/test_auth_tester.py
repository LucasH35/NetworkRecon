"""Tests unitaires pour le module auth_tester.

Ce module contient des tests mockés pour la classe AuthTester,
couvrant les fonctionnalités principales :
- Vérification d'autorisation
- Tests d'authentification SSH, FTP, SMB
- Gestion des credentials
- Stockage et récupération des résultats
- Campagnes de test
"""

import json
import os
import tempfile
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.fernet import Fernet

from app.models.auth_test import (
    AuthCampaign,
    AuthCampaignStatus,
    AuthTestConfig,
    AuthTestResult,
    ServiceType,
)
from app.services.auth_tester import (
    AuthTestError,
    AuthTester,
    UnauthorizedTargetError,
)


# Helper: async iterator mock for Motor cursors
class AsyncIterator:
    """Wrapper pour simuler un async iterator (comme un cursor Motor)."""

    def __init__(self, items):
        self._items = items
        self._index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._index >= len(self._items):
            raise StopAsyncIteration
        item = self._items[self._index]
        self._index += 1
        return item


@pytest.fixture
def mock_db():
    """Fixture pour une base de données mockée."""
    db = AsyncMock()
    db.hosts = AsyncMock()
    db.auth_test_results = AsyncMock()
    db.campaign_progress = AsyncMock()
    db.campaign_progress.update_one = AsyncMock()
    return db


@pytest.fixture
def auth_tester(mock_db):
    """Fixture pour un AuthTester avec une base de données mockée."""
    return AuthTester(mock_db)


@pytest.fixture
def single_credential():
    """Fixture pour un seul identifiant de test."""
    return [
        {"username": "admin", "password": "test123"},
    ]


@pytest.fixture
def sample_credentials():
    """Fixture pour des identifiants de test."""
    return [
        {"username": "admin", "password": "test123"},
        {"username": "root", "password": "password456"},
    ]


@pytest.fixture
def sample_auth_test_result():
    """Fixture pour un résultat de test d'authentification."""
    return AuthTestResult(
        host_ip="192.168.1.100",
        port=22,
        service=ServiceType.SSH,
        credential_used="admin:***",
        success=True,
        timestamp=datetime.now(timezone.utc),
        error_message=None,
    )


@pytest.fixture
def sample_auth_test_config():
    """Fixture pour une configuration de test."""
    return AuthTestConfig(
        service_type=ServiceType.SSH,
        max_attempts=3,
        delay_between=1.0,
    )


@pytest.fixture
def sample_auth_campaign():
    """Fixture pour une campagne de test."""
    return AuthCampaign(
        name="Test Campagne",
        targets=["192.168.1.100", "192.168.1.101"],
        config=AuthTestConfig(
            service_type=ServiceType.SSH,
            credentials_file=None,
            max_attempts=2,
            delay_between=0.5,
        ),
    )


class TestAuthTester:
    """Classe de tests pour AuthTester."""

    def test_init(self, mock_db):
        """Teste l'initialisation de AuthTester."""
        tester = AuthTester(mock_db)
        assert tester.db == mock_db
        assert tester._fernet is not None

    # ======================== verify_authorization ========================

    @pytest.mark.asyncio
    async def test_verify_authorization_authorized(self, auth_tester, mock_db):
        """Teste la vérification d'autorisation pour un hôte autorisé."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        result = await auth_tester.verify_authorization("192.168.1.100")
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_authorization_unauthorized(self, auth_tester, mock_db):
        """Teste la vérification d'autorisation pour un hôte non autorisé."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": False,
        })

        with pytest.raises(UnauthorizedTargetError):
            await auth_tester.verify_authorization("192.168.1.100")

    @pytest.mark.asyncio
    async def test_verify_authorization_not_found(self, auth_tester, mock_db):
        """Teste la vérification d'autorisation pour un hôte inexistant."""
        mock_db.hosts.find_one = AsyncMock(return_value=None)

        with pytest.raises(UnauthorizedTargetError):
            await auth_tester.verify_authorization("192.168.1.100")

    @pytest.mark.asyncio
    async def test_verify_authorization_db_error(self, auth_tester, mock_db):
        """Teste la vérification d'autorisation avec erreur de base de données."""
        mock_db.hosts.find_one = AsyncMock(side_effect=Exception("Erreur DB"))

        with pytest.raises(AuthTestError):
            await auth_tester.verify_authorization("192.168.1.100")

    # ======================== load_credentials ========================

    def test_load_credentials(self, auth_tester):
        """Teste le chargement des identifiants depuis un fichier JSON."""
        credentials = [
            {"username": "admin", "password": "test123"},
            {"username": "root", "password": "password456"},
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(credentials, f)
            temp_path = f.name

        try:
            loaded = auth_tester.load_credentials(temp_path)
            assert len(loaded) == 2
            assert loaded[0]["username"] == "admin"
            assert loaded[1]["password"] == "password456"
        finally:
            os.unlink(temp_path)

    def test_load_credentials_invalid_file(self, auth_tester):
        """Teste le chargement avec un fichier inexistant."""
        with pytest.raises(FileNotFoundError):
            auth_tester.load_credentials("/nonexistent/file.json")

    def test_load_credentials_invalid_json(self, auth_tester):
        """Teste le chargement avec un fichier JSON invalide."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not json")
            temp_path = f.name

        try:
            with pytest.raises(AuthTestError):
                auth_tester.load_credentials(temp_path)
        finally:
            os.unlink(temp_path)

    def test_load_credentials_invalid_format(self, auth_tester):
        """Teste le chargement avec un format de données invalide."""
        credentials = {"invalid": "format"}

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(credentials, f)
            temp_path = f.name

        try:
            with pytest.raises(AuthTestError):
                auth_tester.load_credentials(temp_path)
        finally:
            os.unlink(temp_path)

    def test_load_credentials_missing_fields(self, auth_tester):
        """Teste le chargement avec des champs manquants."""
        credentials = [{"username": "admin"}]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(credentials, f)
            temp_path = f.name

        try:
            with pytest.raises(AuthTestError):
                auth_tester.load_credentials(temp_path)
        finally:
            os.unlink(temp_path)

    # ======================== encryption ========================

    def test_encrypt_decrypt_password(self, auth_tester):
        """Teste le chiffrement et déchiffrement des mots de passe."""
        password = "test123"
        encrypted = auth_tester._encrypt_password(password)

        assert encrypted != password
        decrypted = auth_tester._decrypt_password(encrypted)
        assert decrypted == password

    def test_mask_credential(self, auth_tester):
        """Teste le masquage des identifiants."""
        masked = auth_tester._mask_credential("admin", "test123")
        assert masked == "admin:***"

    # ======================== test_ssh ========================

    @pytest.mark.asyncio
    async def test_test_ssh_success_single_credential(self, auth_tester, mock_db, single_credential):
        """Teste un test SSH réussi avec un seul identifiant."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        with patch.object(auth_tester, '_ssh_auth_attempt') as mock_ssh:
            mock_ssh.return_value = AuthTestResult(
                host_ip="192.168.1.100",
                port=22,
                service=ServiceType.SSH,
                credential_used="admin:***",
                success=True,
            )

            results = await auth_tester.test_ssh(
                ip="192.168.1.100",
                port=22,
                credentials=single_credential,
                max_attempts=1,
                delay=0.1,
            )

            assert len(results) == 1
            assert results[0].success is True

    @pytest.mark.asyncio
    async def test_test_ssh_success_multiple_credentials(self, auth_tester, mock_db, sample_credentials):
        """Teste un test SSH avec deux identifiants : les deux sont testés, le premier réussit."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        with patch.object(auth_tester, '_ssh_auth_attempt') as mock_ssh:
            mock_ssh.return_value = AuthTestResult(
                host_ip="192.168.1.100",
                port=22,
                service=ServiceType.SSH,
                credential_used="admin:***",
                success=True,
            )

            results = await auth_tester.test_ssh(
                ip="192.168.1.100",
                port=22,
                credentials=sample_credentials,
                max_attempts=1,
                delay=0.1,
            )

            # Les deux credentials sont testés individuellement
            assert len(results) == 2
            assert all(r.success is True for r in results)

    @pytest.mark.asyncio
    async def test_test_ssh_unauthorized(self, auth_tester, mock_db, sample_credentials):
        """Teste un test SSH avec cible non autorisée."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": False,
        })

        with pytest.raises(UnauthorizedTargetError):
            await auth_tester.test_ssh(
                ip="192.168.1.100",
                port=22,
                credentials=sample_credentials,
            )

    @pytest.mark.asyncio
    async def test_test_ssh_first_fails_second_succeeds(self, auth_tester, mock_db):
        """Teste SSH : premier credential échoue, second réussit."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        credentials = [
            {"username": "bad", "password": "wrong"},
            {"username": "admin", "password": "test123"},
        ]

        with patch.object(auth_tester, '_ssh_auth_attempt') as mock_ssh:
            mock_ssh.side_effect = [
                AuthTestResult(
                    host_ip="192.168.1.100", port=22,
                    service=ServiceType.SSH, credential_used="bad:***",
                    success=False, error_message="Auth failed",
                ),
                AuthTestResult(
                    host_ip="192.168.1.100", port=22,
                    service=ServiceType.SSH, credential_used="admin:***",
                    success=True,
                ),
            ]

            results = await auth_tester.test_ssh(
                ip="192.168.1.100",
                port=22,
                credentials=credentials,
                max_attempts=1,
                delay=0.1,
            )

            assert len(results) == 2
            assert results[0].success is False
            assert results[1].success is True

    # ======================== test_ftp ========================

    @pytest.mark.asyncio
    async def test_test_ftp_success(self, auth_tester, mock_db, single_credential):
        """Teste un test FTP réussi."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        with patch.object(auth_tester, '_ftp_auth_attempt') as mock_ftp:
            mock_ftp.return_value = AuthTestResult(
                host_ip="192.168.1.100",
                port=21,
                service=ServiceType.FTP,
                credential_used="admin:***",
                success=True,
            )

            results = await auth_tester.test_ftp(
                ip="192.168.1.100",
                port=21,
                credentials=single_credential,
                max_attempts=1,
                delay=0.1,
            )

            assert len(results) == 1
            assert results[0].success is True

    # ======================== test_smb ========================

    @pytest.mark.asyncio
    async def test_test_smb_success(self, auth_tester, mock_db, single_credential):
        """Teste un test SMB réussi."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        with patch.object(auth_tester, '_smb_auth_attempt') as mock_smb:
            mock_smb.return_value = AuthTestResult(
                host_ip="192.168.1.100",
                port=445,
                service=ServiceType.SMB,
                credential_used="admin:***",
                success=True,
            )

            results = await auth_tester.test_smb(
                ip="192.168.1.100",
                port=445,
                credentials=single_credential,
                max_attempts=1,
                delay=0.1,
            )

            assert len(results) == 1
            assert results[0].success is True

    # ======================== test_telnet ========================

    @pytest.mark.asyncio
    async def test_test_telnet_success(self, auth_tester, mock_db, single_credential):
        """Teste un test Telnet réussi."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        with patch.object(auth_tester, '_telnet_auth_attempt') as mock_telnet:
            mock_telnet.return_value = AuthTestResult(
                host_ip="192.168.1.100",
                port=23,
                service=ServiceType.SSH,  # Telnet n'est pas dans ServiceType
                credential_used="admin:***",
                success=True,
            )

            results = await auth_tester.test_telnet(
                ip="192.168.1.100",
                port=23,
                credentials=single_credential,
                max_attempts=1,
                delay=0.1,
            )

            assert len(results) == 1
            assert results[0].success is True

    # ======================== test_rdp ========================

    @pytest.mark.asyncio
    async def test_test_rdp_stub(self, auth_tester, mock_db, single_credential):
        """Teste le stub RDP."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        results = await auth_tester.test_rdp(
            ip="192.168.1.100",
            port=3389,
            credentials=single_credential,
            max_attempts=1,
        )

        assert len(results) == 1
        assert results[0].success is False
        assert "WARNING" in results[0].error_message

    @pytest.mark.asyncio
    async def test_test_rdp_stub_multiple_credentials(self, auth_tester, mock_db, sample_credentials):
        """Teste le stub RDP avec plusieurs identifiants."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        results = await auth_tester.test_rdp(
            ip="192.168.1.100",
            port=3389,
            credentials=sample_credentials,
            max_attempts=1,
        )

        # Un résultat par credential
        assert len(results) == 2
        assert all(r.success is False for r in results)
        assert all("WARNING" in r.error_message for r in results)

    # ======================== test_service routing ========================

    @pytest.mark.asyncio
    async def test_test_service_ssh(self, auth_tester, mock_db, sample_credentials, sample_auth_test_config):
        """Teste la routage vers le test SSH."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        with patch.object(auth_tester, 'test_ssh') as mock_ssh:
            mock_ssh.return_value = [
                AuthTestResult(
                    host_ip="192.168.1.100",
                    port=22,
                    service=ServiceType.SSH,
                    credential_used="admin:***",
                    success=True,
                )
            ]

            results = await auth_tester.test_service(
                ip="192.168.1.100",
                port=22,
                service_type=ServiceType.SSH,
                credentials=sample_credentials,
                config=sample_auth_test_config,
            )

            assert len(results) == 1
            mock_ssh.assert_called_once()

    @pytest.mark.asyncio
    async def test_test_service_ftp(self, auth_tester, mock_db, sample_credentials, sample_auth_test_config):
        """Teste la routage vers le test FTP."""
        sample_auth_test_config.service_type = ServiceType.FTP
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        with patch.object(auth_tester, 'test_ftp') as mock_ftp:
            mock_ftp.return_value = []

            results = await auth_tester.test_service(
                ip="192.168.1.100",
                port=21,
                service_type=ServiceType.FTP,
                credentials=sample_credentials,
                config=sample_auth_test_config,
            )

            mock_ftp.assert_called_once()

    @pytest.mark.asyncio
    async def test_test_service_smb(self, auth_tester, mock_db, sample_credentials, sample_auth_test_config):
        """Teste la routage vers le test SMB."""
        sample_auth_test_config.service_type = ServiceType.SMB
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        with patch.object(auth_tester, 'test_smb') as mock_smb:
            mock_smb.return_value = []

            results = await auth_tester.test_service(
                ip="192.168.1.100",
                port=445,
                service_type=ServiceType.SMB,
                credentials=sample_credentials,
                config=sample_auth_test_config,
            )

            mock_smb.assert_called_once()

    @pytest.mark.asyncio
    async def test_test_service_rdp(self, auth_tester, mock_db, sample_credentials, sample_auth_test_config):
        """Teste la routage vers le test RDP."""
        sample_auth_test_config.service_type = ServiceType.RDP
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        with patch.object(auth_tester, 'test_rdp') as mock_rdp:
            mock_rdp.return_value = []

            results = await auth_tester.test_service(
                ip="192.168.1.100",
                port=3389,
                service_type=ServiceType.RDP,
                credentials=sample_credentials,
                config=sample_auth_test_config,
            )

            mock_rdp.assert_called_once()

    @pytest.mark.asyncio
    async def test_test_service_unsupported(self, auth_tester, mock_db, sample_credentials):
        """Teste la routage vers un service non supporté."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        with pytest.raises(AuthTestError):
            await auth_tester.test_service(
                ip="192.168.1.100",
                port=3306,
                service_type=ServiceType.MYSQL,
                credentials=sample_credentials,
            )

    @pytest.mark.asyncio
    async def test_test_service_unsupported_redis(self, auth_tester, mock_db, sample_credentials):
        """Teste la routage vers Redis (non supporté)."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        with pytest.raises(AuthTestError):
            await auth_tester.test_service(
                ip="192.168.1.100",
                port=6379,
                service_type=ServiceType.REDIS,
                credentials=sample_credentials,
            )

    # ======================== run_auth_campaign ========================

    @pytest.mark.asyncio
    async def test_run_auth_campaign(self, auth_tester, mock_db, sample_auth_campaign):
        """Teste l'exécution d'une campagne de test."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        # Création d'un fichier temporaire de credentials
        credentials = [{"username": "admin", "password": "test123"}]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(credentials, f)
            temp_path = f.name

        try:
            sample_auth_campaign.config.credentials_file = temp_path

            with patch.object(auth_tester, 'test_service_with_progress') as mock_test:
                mock_test.return_value = [
                    AuthTestResult(
                        host_ip="192.168.1.100",
                        port=22,
                        service=ServiceType.SSH,
                        credential_used="admin:***",
                        success=True,
                    )
                ]

                result = await auth_tester.run_auth_campaign(sample_auth_campaign)

                assert result.status == AuthCampaignStatus.COMPLETED
                assert len(result.results) == 2  # 1 résultat par cible
                assert result.completed_at is not None
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_run_auth_campaign_with_unauthorized_target(self, auth_tester, mock_db, sample_auth_campaign):
        """Teste l'exécution d'une campagne avec une cible non autorisée."""
        # Première cible autorisée, seconde non autorisée
        mock_db.hosts.find_one = AsyncMock(side_effect=[
            {"ip_address": "192.168.1.100", "authorized": True},
            {"ip_address": "192.168.1.101", "authorized": False},
        ])

        credentials = [{"username": "admin", "password": "test123"}]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(credentials, f)
            temp_path = f.name

        try:
            sample_auth_campaign.config.credentials_file = temp_path

            with patch.object(auth_tester, 'test_service_with_progress') as mock_test:
                mock_test.return_value = [
                    AuthTestResult(
                        host_ip="192.168.1.100",
                        port=22,
                        service=ServiceType.SSH,
                        credential_used="admin:***",
                        success=True,
                    )
                ]

                result = await auth_tester.run_auth_campaign(sample_auth_campaign)

                assert result.status == AuthCampaignStatus.COMPLETED
                assert len(result.results) == 1  # Seulement la première cible
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_run_auth_campaign_no_credentials_file(self, auth_tester, mock_db, sample_auth_campaign):
        """Teste l'exécution d'une campagne sans fichier de credentials utilise les credentials par défaut."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })
        sample_auth_campaign.config.credentials_file = None

        with patch.object(auth_tester, 'test_service_with_progress') as mock_test:
            mock_test.return_value = [
                AuthTestResult(
                    host_ip="192.168.1.100",
                    port=22,
                    service=ServiceType.SSH,
                    credential_used="admin:***",
                    success=False,
                )
            ]

            result = await auth_tester.run_auth_campaign(sample_auth_campaign)

            assert result.status == AuthCampaignStatus.COMPLETED
            assert len(result.results) == 2  # 1 résultat par cible (credentials par défaut)

    # ======================== store_results ========================

    @pytest.mark.asyncio
    async def test_store_results(self, auth_tester, mock_db):
        """Teste le stockage des résultats."""
        results = [
            AuthTestResult(
                host_ip="192.168.1.100",
                port=22,
                service=ServiceType.SSH,
                credential_used="admin:***",
                success=True,
            )
        ]

        mock_db.auth_test_results.insert_many = AsyncMock()

        await auth_tester.store_results("campaign123", results)

        mock_db.auth_test_results.insert_many.assert_called_once()

    @pytest.mark.asyncio
    async def test_store_results_empty(self, auth_tester, mock_db):
        """Teste le stockage de résultats vides."""
        mock_db.auth_test_results.insert_many = AsyncMock()

        await auth_tester.store_results("campaign123", [])

        mock_db.auth_test_results.insert_many.assert_not_called()

    # ======================== get_results_by_host ========================

    @pytest.mark.asyncio
    async def test_get_results_by_host(self, auth_tester, mock_db):
        """Teste la récupération des résultats par hôte."""
        doc = {
            "_id": "result1",
            "host_ip": "192.168.1.100",
            "port": 22,
            "service": "ssh",
            "credential_used": "admin:***",
            "success": True,
            "timestamp": datetime.now(timezone.utc),
            "error_message": None,
            "campaign_id": "campaign123",
        }

        mock_cursor = AsyncIterator([doc])
        mock_find_result = MagicMock()
        mock_find_result.sort = MagicMock(return_value=mock_cursor)

        mock_db.auth_test_results.find = MagicMock(return_value=mock_find_result)

        results = await auth_tester.get_results_by_host("192.168.1.100")

        assert len(results) == 1
        assert results[0].host_ip == "192.168.1.100"
        assert results[0].service == ServiceType.SSH

    @pytest.mark.asyncio
    async def test_get_results_by_host_empty(self, auth_tester, mock_db):
        """Teste la récupération des résultats pour un hôte sans résultats."""
        mock_cursor = AsyncIterator([])
        mock_find_result = MagicMock()
        mock_find_result.sort = MagicMock(return_value=mock_cursor)

        mock_db.auth_test_results.find = MagicMock(return_value=mock_find_result)

        results = await auth_tester.get_results_by_host("192.168.1.100")

        assert len(results) == 0

    # ======================== _ssh_auth_attempt ========================

    @pytest.mark.asyncio
    async def test_ssh_auth_attempt_success(self, auth_tester):
        """Teste une tentative d'authentification SSH réussie."""
        with patch('paramiko.SSHClient') as mock_ssh:
            mock_client = MagicMock()
            mock_ssh.return_value = mock_client

            result = auth_tester._ssh_auth_attempt(
                ip="192.168.1.100",
                port=22,
                username="admin",
                password="test123",
                attempt=1,
            )

            assert result.success is True
            mock_client.connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_ssh_auth_attempt_failure(self, auth_tester):
        """Teste une tentative d'authentification SSH échouée."""
        import paramiko

        with patch('paramiko.SSHClient') as mock_ssh:
            mock_client = MagicMock()
            mock_ssh.return_value = mock_client
            mock_client.connect.side_effect = paramiko.AuthenticationException()

            result = auth_tester._ssh_auth_attempt(
                ip="192.168.1.100",
                port=22,
                username="admin",
                password="wrongpassword",
                attempt=1,
            )

            assert result.success is False
            assert "Authentification échouée" in result.error_message

    @pytest.mark.asyncio
    async def test_ssh_auth_attempt_exception(self, auth_tester):
        """Teste une tentative d'authentification SSH avec exception."""
        with patch('paramiko.SSHClient') as mock_ssh:
            mock_client = MagicMock()
            mock_ssh.return_value = mock_client
            mock_client.connect.side_effect = Exception("Erreur de connexion")

            result = auth_tester._ssh_auth_attempt(
                ip="192.168.1.100",
                port=22,
                username="admin",
                password="test123",
                attempt=1,
            )

            assert result.success is False
            assert "Erreur de connexion" in result.error_message

    @pytest.mark.asyncio
    async def test_ssh_auth_attempt_ssh_exception(self, auth_tester):
        """Teste une tentative d'authentification SSH avec SSHException."""
        import paramiko

        with patch('paramiko.SSHClient') as mock_ssh:
            mock_client = MagicMock()
            mock_ssh.return_value = mock_client
            mock_client.connect.side_effect = paramiko.SSHException("Protocol error")

            result = auth_tester._ssh_auth_attempt(
                ip="192.168.1.100",
                port=22,
                username="admin",
                password="test123",
                attempt=1,
            )

            assert result.success is False
            assert "Erreur SSH" in result.error_message

    # ======================== _ftp_auth_attempt ========================

    @pytest.mark.asyncio
    async def test_ftp_auth_attempt_success(self, auth_tester):
        """Teste une tentative d'authentification FTP réussie."""
        with patch('ftplib.FTP') as mock_ftp:
            mock_ftp_instance = MagicMock()
            mock_ftp.return_value = mock_ftp_instance

            result = auth_tester._ftp_auth_attempt(
                ip="192.168.1.100",
                port=21,
                username="admin",
                password="test123",
                attempt=1,
            )

            assert result.success is True
            mock_ftp_instance.login.assert_called_once()

    @pytest.mark.asyncio
    async def test_ftp_auth_attempt_failure(self, auth_tester):
        """Teste une tentative d'authentification FTP échouée."""
        with patch('ftplib.FTP') as mock_ftp:
            mock_ftp_instance = MagicMock()
            mock_ftp.return_value = mock_ftp_instance
            mock_ftp_instance.login.side_effect = Exception("530 Login incorrect")

            result = auth_tester._ftp_auth_attempt(
                ip="192.168.1.100",
                port=21,
                username="admin",
                password="wrongpassword",
                attempt=1,
            )

            assert result.success is False
            assert "Authentification échouée" in result.error_message

    @pytest.mark.asyncio
    async def test_ftp_auth_attempt_generic_exception(self, auth_tester):
        """Teste une tentative d'authentification FTP avec exception générique."""
        with patch('ftplib.FTP') as mock_ftp:
            mock_ftp_instance = MagicMock()
            mock_ftp.return_value = mock_ftp_instance
            mock_ftp_instance.login.side_effect = Exception("Connection timeout")

            result = auth_tester._ftp_auth_attempt(
                ip="192.168.1.100",
                port=21,
                username="admin",
                password="test123",
                attempt=1,
            )

            assert result.success is False
            assert "Erreur FTP" in result.error_message

    # ======================== _smb_auth_attempt ========================

    @pytest.mark.asyncio
    async def test_smb_auth_attempt_success(self, auth_tester):
        """Teste une tentative d'authentification SMB réussie."""
        with patch('app.services.auth_tester.SMBConnection') as mock_smb_cls:
            mock_smb_instance = MagicMock()
            mock_smb_cls.return_value = mock_smb_instance
            mock_smb_instance.connect.return_value = True

            result = auth_tester._smb_auth_attempt(
                ip="192.168.1.100",
                port=445,
                username="admin",
                password="test123",
                attempt=1,
            )

            assert result.success is True
            mock_smb_instance.connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_smb_auth_attempt_failure(self, auth_tester):
        """Teste une tentative d'authentification SMB échouée."""
        with patch('app.services.auth_tester.SMBConnection') as mock_smb_cls:
            mock_smb_instance = MagicMock()
            mock_smb_cls.return_value = mock_smb_instance
            mock_smb_instance.connect.side_effect = Exception("NT_STATUS_LOGON_FAILURE")

            result = auth_tester._smb_auth_attempt(
                ip="192.168.1.100",
                port=445,
                username="admin",
                password="wrongpassword",
                attempt=1,
            )

            assert result.success is False
            assert "Authentification échouée" in result.error_message

    @pytest.mark.asyncio
    async def test_smb_auth_attempt_connection_refused(self, auth_tester):
        """Teste une tentative d'authentification SMB avec connexion refusée."""
        with patch('app.services.auth_tester.SMBConnection') as mock_smb_cls:
            mock_smb_instance = MagicMock()
            mock_smb_cls.return_value = mock_smb_instance
            mock_smb_instance.connect.return_value = False

            result = auth_tester._smb_auth_attempt(
                ip="192.168.1.100",
                port=445,
                username="admin",
                password="test123",
                attempt=1,
            )

            assert result.success is False
            assert "Connexion SMB échouée" in result.error_message

    @pytest.mark.asyncio
    async def test_smb_auth_attempt_generic_exception(self, auth_tester):
        """Teste une tentative d'authentification SMB avec exception générique."""
        with patch('app.services.auth_tester.SMBConnection') as mock_smb_cls:
            mock_smb_instance = MagicMock()
            mock_smb_cls.return_value = mock_smb_instance
            mock_smb_instance.connect.side_effect = Exception("Connection reset")

            result = auth_tester._smb_auth_attempt(
                ip="192.168.1.100",
                port=445,
                username="admin",
                password="test123",
                attempt=1,
            )

            assert result.success is False
            assert "Erreur SMB" in result.error_message

    # ======================== _telnet_auth_attempt ========================

    @pytest.mark.asyncio
    async def test_telnet_auth_attempt_success(self, auth_tester):
        """Teste une tentative d'authentification Telnet réussie."""
        with patch('app.services.auth_tester.telnetlib') as mock_telnetlib:
            mock_telnet_instance = MagicMock()
            mock_telnetlib.Telnet.return_value = mock_telnet_instance
            mock_telnet_instance.read_until.side_effect = [
                b"login: ",
                b"Password: ",
                b"test",
            ]

            result = auth_tester._telnet_auth_attempt(
                ip="192.168.1.100",
                port=23,
                username="admin",
                password="test123",
                attempt=1,
            )

            assert result.success is True

    @pytest.mark.asyncio
    async def test_telnet_auth_attempt_exception(self, auth_tester):
        """Teste une tentative d'authentification Telnet avec exception."""
        with patch('app.services.auth_tester.telnetlib') as mock_telnetlib:
            mock_telnetlib.Telnet.side_effect = Exception("Connection refused")

            result = auth_tester._telnet_auth_attempt(
                ip="192.168.1.100",
                port=23,
                username="admin",
                password="test123",
                attempt=1,
            )

            assert result.success is False
            assert "Erreur Telnet" in result.error_message

    # ======================== Multi-attempts ========================

    @pytest.mark.asyncio
    async def test_test_ssh_multiple_attempts(self, auth_tester, mock_db):
        """Teste SSH avec plusieurs tentatives pour un même credential."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        with patch.object(auth_tester, '_ssh_auth_attempt') as mock_ssh:
            # Premier essai échoue, deuxième réussit
            mock_ssh.side_effect = [
                AuthTestResult(
                    host_ip="192.168.1.100",
                    port=22,
                    service=ServiceType.SSH,
                    credential_used="admin:***",
                    success=False,
                ),
                AuthTestResult(
                    host_ip="192.168.1.100",
                    port=22,
                    service=ServiceType.SSH,
                    credential_used="admin:***",
                    success=True,
                ),
            ]

            results = await auth_tester.test_ssh(
                ip="192.168.1.100",
                port=22,
                credentials=[{"username": "admin", "password": "test123"}],
                max_attempts=3,
                delay=0.1,
            )

            assert len(results) == 2
            assert results[0].success is False
            assert results[1].success is True

    @pytest.mark.asyncio
    async def test_test_ssh_exception_in_attempt(self, auth_tester, mock_db):
        """Teste SSH quand une tentative lève une exception."""
        mock_db.hosts.find_one = AsyncMock(return_value={
            "ip_address": "192.168.1.100",
            "authorized": True,
        })

        with patch.object(auth_tester, '_ssh_auth_attempt') as mock_ssh:
            mock_ssh.side_effect = Exception("Erreur inattendue")

            results = await auth_tester.test_ssh(
                ip="192.168.1.100",
                port=22,
                credentials=[{"username": "admin", "password": "test123"}],
                max_attempts=1,
                delay=0.1,
            )

            assert len(results) == 1
            assert results[0].success is False
            assert "Erreur inattendue" in results[0].error_message

    # ======================== Misc ========================

    def test_auth_tester_constants(self, auth_tester):
        """Teste que les constantes et configurations sont correctes."""
        assert hasattr(auth_tester, '_fernet')
        assert isinstance(auth_tester._fernet, Fernet)
