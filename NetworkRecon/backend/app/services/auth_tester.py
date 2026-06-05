"""Service de tests d'authentification autorisés pour NetworkRecon.

Ce module implémente des tests d'authentification pour divers services réseau
(SSH, FTP, SMB, Telnet, RDP) avec des mécanismes de sécurité stricts :
- Vérification d'autorisation obligatoire avant chaque test
- Chiffrement des mots de passe avant stockage
- Rate limiting configurable
- Logging complet de toutes les actions
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from motor.motor_asyncio import AsyncIOMotorDatabase

# telnetlib a été supprimé en Python 3.13+, import conditionnel
try:
    import telnetlib
except ImportError:
    telnetlib = None  # type: ignore

# pysmb pour SMB
try:
    from smb.SMBConnection import SMBConnection
except ImportError:
    SMBConnection = None  # type: ignore

from app.models.auth_test import (
    AuthCampaign,
    AuthCampaignStatus,
    AuthTestConfig,
    AuthTestResult,
    ServiceType,
)

logger = logging.getLogger(__name__)


class AuthTestError(Exception):
    """Exception personnalisée pour les erreurs de test d'authentification."""
    pass


class UnauthorizedTargetError(AuthTestError):
    """Exception levée lorsque la cible n'est pas autorisée."""
    pass


class AuthTester:
    """Service de tests d'authentification autorisés.
    
    Ce service implémente des tests d'authentification pour divers services réseau
    avec des mécanismes de sécurité stricts :
    - Vérification d'autorisation obligatoire avant chaque test
    - Chiffrement des mots de passe avant stockage
    - Rate limiting configurable
    - Logging complet de toutes les actions
    
    Attributes:
        db: Base de données Motor asynchrone
        _fernet: Instance Fernet pour le chiffrement des mots de passe
    """

    # ── Credentials par défaut pour les attaques brute force ──────────────
    DEFAULT_CREDENTIALS: list[dict] = [
        # Credentials ciblés
        {"username": "lucash", "password": "Bonjour2025*"},
        # Admin / root classiques
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": "123456"},
        {"username": "admin", "password": "admin123"},
        {"username": "admin", "password": "pass"},
        {"username": "root", "password": "root"},
        {"username": "root", "password": "toor"},
        {"username": "root", "password": "password"},
        {"username": "root", "password": "123456"},
        {"username": "root", "password": "admin"},
        {"username": "root", "password": "root123"},
        # Utilisateurs courants
        {"username": "user", "password": "user"},
        {"username": "user", "password": "password"},
        {"username": "test", "password": "test"},
        {"username": "test", "password": "password"},
        {"username": "guest", "password": "guest"},
        {"username": "guest", "password": "password"},
        {"username": "oracle", "password": "oracle"},
        {"username": "mysql", "password": "mysql"},
        {"username": "postgres", "password": "postgres"},
        {"username": "postgres", "password": "password"},
        {"username": "ftp", "password": "ftp"},
        {"username": "ftp", "password": "password"},
        {"username": "anonymous", "password": "anonymous"},
        {"username": "anonymous", "password": ""},
        # Mots de passe faibles courants
        {"username": "admin", "password": "qwerty"},
        {"username": "admin", "password": "letmein"},
        {"username": "admin", "password": "welcome"},
        {"username": "admin", "password": "monkey"},
        {"username": "admin", "password": "dragon"},
        {"username": "root", "password": "qwerty"},
        {"username": "root", "password": "letmein"},
        {"username": "root", "password": "changeme"},
        # Service-specific
        {"username": "sa", "password": "sa"},
        {"username": "sa", "password": ""},
        {"username": "sys", "password": "sys"},
        {"username": "administrator", "password": "administrator"},
        {"username": "administrator", "password": "password"},
        {"username": "backup", "password": "backup"},
        {"username": "deploy", "password": "deploy"},
        {"username": "service", "password": "service"},
    ]

    def __init__(self, db: AsyncIOMotorDatabase):
        """Initialise le service de test d'authentification.
        
        Args:
            db: Instance de base de données Motor asynchrone
        """
        self.db = db
        # Génération d'une clé de chiffrement pour les mots de passe
        # En production, cette clé devrait être stockée de manière sécurisée
        self._fernet = Fernet(Fernet.generate_key())
        logger.info("AuthTester initialisé avec succès")

    async def verify_authorization(self, host_ip: str) -> bool:
        """Vérifie que la cible est autorisée pour les tests d'authentification.
        
        Cette méthode est OBLIGATOIRE avant chaque test. Elle vérifie dans la
        base de données que l'hôte cible a le champ 'authorized: true'.
        
        Args:
            host_ip: Adresse IP de la cible à vérifier
            
        Returns:
            bool: True si la cible est autorisée, False sinon
            
        Raises:
            UnauthorizedTargetError: Si la cible n'est pas autorisée
        """
        try:
            # Recherche de l'hôte dans la base de données
            host = await self.db.hosts.find_one({"ip_address": host_ip})
            
            if host is None:
                logger.warning(f"Hôte {host_ip} non trouvé dans la base de données")
                raise UnauthorizedTargetError(
                    f"L'hôte {host_ip} n'existe pas dans la base de données. "
                    f"Seuls les hôtes autorisés peuvent être testés."
                )
            
            # Vérification du champ authorized
            if not host.get("authorized", False):
                logger.warning(f"Test d'authentification refusé pour {host_ip} : non autorisé")
                raise UnauthorizedTargetError(
                    f"L'hôte {host_ip} n'est pas autorisé pour les tests d'authentification. "
                    f"Le champ 'authorized' doit être défini sur true."
                )
            
            logger.info(f"Autorisation confirmée pour {host_ip}")
            return True
            
        except UnauthorizedTargetError:
            raise
        except Exception as e:
            logger.error(f"Erreur lors de la vérification d'autorisation pour {host_ip}: {e}")
            raise AuthTestError(
                f"Erreur lors de la vérification d'autorisation: {e}"
            )

    def load_credentials(self, file_path: str) -> list[dict]:
        """Charge les identifiants depuis un fichier JSON.
        
        Format attendu du fichier JSON :
        [
            {"username": "admin", "password": "test123"},
            {"username": "root", "password": "password456"}
        ]
        
        Args:
            file_path: Chemin vers le fichier JSON contenant les identifiants
            
        Returns:
            list[dict]: Liste des identifiants chargés
            
        Raises:
            FileNotFoundError: Si le fichier n'existe pas
            json.JSONDecodeError: Si le fichier n'est pas un JSON valide
            AuthTestError: Pour toute autre erreur lors du chargement
        """
        try:
            path = Path(file_path)
            
            if not path.exists():
                raise FileNotFoundError(f"Le fichier de credentials n'existe pas: {file_path}")
            
            if not path.suffix.lower() == '.json':
                logger.warning(f"Le fichier {file_path} n'a pas l'extension .json")
            
            with open(path, 'r', encoding='utf-8') as f:
                credentials = json.load(f)
            
            # Validation du format
            if not isinstance(credentials, list):
                raise AuthTestError("Le fichier JSON doit contenir un tableau d'identifiants")
            
            for i, cred in enumerate(credentials):
                if not isinstance(cred, dict):
                    raise AuthTestError(f"L'identifiant à l'index {i} n'est pas un objet")
                if "username" not in cred or "password" not in cred:
                    raise AuthTestError(
                        f"L'identifiant à l'index {i} doit contenir 'username' et 'password'"
                    )
            
            logger.info(f"Chargement de {len(credentials)} identifiants depuis {file_path}")
            return credentials
            
        except FileNotFoundError:
            raise
        except json.JSONDecodeError as e:
            raise AuthTestError(f"Erreur de décodage JSON dans {file_path}: {e}")
        except AuthTestError:
            raise
        except Exception as e:
            raise AuthTestError(f"Erreur lors du chargement des credentials: {e}")

    def _encrypt_password(self, password: str) -> str:
        """Chiffre un mot de passe en utilisant Fernet.
        
        Args:
            password: Mot de passe en clair à chiffrer
            
        Returns:
            str: Mot de passe chiffré (encodé en base64)
        """
        encrypted = self._fernet.encrypt(password.encode('utf-8'))
        return encrypted.decode('utf-8')

    def _decrypt_password(self, encrypted_password: str) -> str:
        """Déchiffre un mot de passe chiffré.
        
        Args:
            encrypted_password: Mot de passe chiffré
            
        Returns:
            str: Mot de passe en clair déchiffré
        """
        decrypted = self._fernet.decrypt(encrypted_password.encode('utf-8'))
        return decrypted.decode('utf-8')

    def _mask_credential(self, username: str, password: str) -> str:
        """Masque un credential pour les logs.
        
        Args:
            username: Nom d'utilisateur
            password: Mot de passe
            
        Returns:
            str: Credential masqué (ex: admin:***)
        """
        return f"{username}:***"

    async def test_ssh(
        self,
        ip: str,
        port: int,
        credentials: list[dict],
        max_attempts: int = 3,
        delay: float = 1.0,
    ) -> list[AuthTestResult]:
        """Teste l'authentification SSH avec paramiko.
        
        Args:
            ip: Adresse IP de la cible
            port: Port SSH (défaut: 22)
            credentials: Liste des identifiants à tester
            max_attempts: Nombre maximum de tentatives par identifiant
            delay: Délai entre chaque tentative (secondes)
            
        Returns:
            list[AuthTestResult]: Liste des résultats des tests
            
        Raises:
            UnauthorizedTargetError: Si la cible n'est pas autorisée
        """
        # Vérification d'autorisation OBLIGATOIRE
        await self.verify_authorization(ip)
        
        results = []
        
        for cred in credentials:
            username = cred["username"]
            password = cred["password"]
            masked_cred = self._mask_credential(username, password)
            
            logger.info(f"Test SSH sur {ip}:{port} avec {masked_cred}")
            
            for attempt in range(max_attempts):
                try:
                    # Exécution du test SSH dans un thread séparé
                    result = await asyncio.to_thread(
                        self._ssh_auth_attempt,
                        ip,
                        port,
                        username,
                        password,
                        attempt + 1,
                    )
                    results.append(result)
                    
                    if result.success:
                        logger.info(f"SSH authentification réussie sur {ip}:{port} avec {masked_cred}")
                        break
                    
                    logger.debug(
                        f"Tentative SSH {attempt + 1}/{max_attempts} échouée sur {ip}:{port}"
                    )
                    
                    # Rate limiting
                    if attempt < max_attempts - 1:
                        await asyncio.sleep(delay)
                        
                except Exception as e:
                    logger.error(f"Erreur lors du test SSH sur {ip}:{port}: {e}")
                    results.append(AuthTestResult(
                        host_ip=ip,
                        port=port,
                        service=ServiceType.SSH,
                        credential_used=masked_cred,
                        success=False,
                        error_message=str(e),
                    ))
                    break
        
        return results

    def _ssh_auth_attempt(
        self,
        ip: str,
        port: int,
        username: str,
        password: str,
        attempt: int,
    ) -> AuthTestResult:
        """Tente une authentification SSH (synchrone, exécutée dans un thread).
        
        Args:
            ip: Adresse IP de la cible
            port: Port SSH
            username: Nom d'utilisateur
            password: Mot de passe
            attempt: Numéro de la tentative
            
        Returns:
            AuthTestResult: Résultat de la tentative
        """
        import paramiko
        
        masked_cred = self._mask_credential(username, password)
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Tentative de connexion
            client.connect(
                hostname=ip,
                port=port,
                username=username,
                password=password,
                timeout=5,
                auth_timeout=5,
                banner_timeout=30,
            )
            
            client.close()
            
            return AuthTestResult(
                host_ip=ip,
                port=port,
                service=ServiceType.SSH,
                credential_used=masked_cred,
                success=True,
                error_message=None,
            )
            
        except paramiko.AuthenticationException:
            return AuthTestResult(
                host_ip=ip,
                port=port,
                service=ServiceType.SSH,
                credential_used=masked_cred,
                success=False,
                error_message="Authentification échouée",
            )
        except paramiko.SSHException as e:
            return AuthTestResult(
                host_ip=ip,
                port=port,
                service=ServiceType.SSH,
                credential_used=masked_cred,
                success=False,
                error_message=f"Erreur SSH: {e}",
            )
        except Exception as e:
            return AuthTestResult(
                host_ip=ip,
                port=port,
                service=ServiceType.SSH,
                credential_used=masked_cred,
                success=False,
                error_message=f"Erreur de connexion: {e}",
            )

    async def test_ftp(
        self,
        ip: str,
        port: int,
        credentials: list[dict],
        max_attempts: int = 3,
        delay: float = 1.0,
    ) -> list[AuthTestResult]:
        """Teste l'authentification FTP avec ftplib.
        
        Args:
            ip: Adresse IP de la cible
            port: Port FTP (défaut: 21)
            credentials: Liste des identifiants à tester
            max_attempts: Nombre maximum de tentatives par identifiant
            delay: Délai entre chaque tentative (secondes)
            
        Returns:
            list[AuthTestResult]: Liste des résultats des tests
            
        Raises:
            UnauthorizedTargetError: Si la cible n'est pas autorisée
        """
        # Vérification d'autorisation OBLIGATOIRE
        await self.verify_authorization(ip)
        
        results = []
        
        for cred in credentials:
            username = cred["username"]
            password = cred["password"]
            masked_cred = self._mask_credential(username, password)
            
            logger.info(f"Test FTP sur {ip}:{port} avec {masked_cred}")
            
            for attempt in range(max_attempts):
                try:
                    # Exécution du test FTP dans un thread séparé
                    result = await asyncio.to_thread(
                        self._ftp_auth_attempt,
                        ip,
                        port,
                        username,
                        password,
                        attempt + 1,
                    )
                    results.append(result)
                    
                    if result.success:
                        logger.info(f"FTP authentification réussie sur {ip}:{port} avec {masked_cred}")
                        break
                    
                    logger.debug(
                        f"Tentative FTP {attempt + 1}/{max_attempts} échouée sur {ip}:{port}"
                    )
                    
                    # Rate limiting
                    if attempt < max_attempts - 1:
                        await asyncio.sleep(delay)
                        
                except Exception as e:
                    logger.error(f"Erreur lors du test FTP sur {ip}:{port}: {e}")
                    results.append(AuthTestResult(
                        host_ip=ip,
                        port=port,
                        service=ServiceType.FTP,
                        credential_used=masked_cred,
                        success=False,
                        error_message=str(e),
                    ))
                    break
        
        return results

    def _ftp_auth_attempt(
        self,
        ip: str,
        port: int,
        username: str,
        password: str,
        attempt: int,
    ) -> AuthTestResult:
        """Tente une authentification FTP (synchrone, exécutée dans un thread).
        
        Args:
            ip: Adresse IP de la cible
            port: Port FTP
            username: Nom d'utilisateur
            password: Mot de passe
            attempt: Numéro de la tentative
            
        Returns:
            AuthTestResult: Résultat de la tentative
        """
        from ftplib import FTP
        
        masked_cred = self._mask_credential(username, password)
        
        try:
            ftp = FTP()
            ftp.connect(ip, port, timeout=10)
            ftp.login(username, password)
            ftp.quit()
            
            return AuthTestResult(
                host_ip=ip,
                port=port,
                service=ServiceType.FTP,
                credential_used=masked_cred,
                success=True,
                error_message=None,
            )
            
        except Exception as e:
            error_msg = str(e)
            if "530" in error_msg or "Login" in error_msg:
                return AuthTestResult(
                    host_ip=ip,
                    port=port,
                    service=ServiceType.FTP,
                    credential_used=masked_cred,
                    success=False,
                    error_message="Authentification échouée",
                )
            return AuthTestResult(
                host_ip=ip,
                port=port,
                service=ServiceType.FTP,
                credential_used=masked_cred,
                success=False,
                error_message=f"Erreur FTP: {e}",
            )

    async def test_smb(
        self,
        ip: str,
        port: int,
        credentials: list[dict],
        max_attempts: int = 3,
        delay: float = 1.0,
    ) -> list[AuthTestResult]:
        """Teste l'authentification SMB avec pysmb.
        
        Args:
            ip: Adresse IP de la cible
            port: Port SMB (défaut: 445)
            credentials: Liste des identifiants à tester
            max_attempts: Nombre maximum de tentatives par identifiant
            delay: Délai entre chaque tentative (secondes)
            
        Returns:
            list[AuthTestResult]: Liste des résultats des tests
            
        Raises:
            UnauthorizedTargetError: Si la cible n'est pas autorisée
        """
        # Vérification d'autorisation OBLIGATOIRE
        await self.verify_authorization(ip)
        
        results = []
        
        for cred in credentials:
            username = cred["username"]
            password = cred["password"]
            masked_cred = self._mask_credential(username, password)
            
            logger.info(f"Test SMB sur {ip}:{port} avec {masked_cred}")
            
            for attempt in range(max_attempts):
                try:
                    # Exécution du test SMB dans un thread séparé
                    result = await asyncio.to_thread(
                        self._smb_auth_attempt,
                        ip,
                        port,
                        username,
                        password,
                        attempt + 1,
                    )
                    results.append(result)
                    
                    if result.success:
                        logger.info(f"SMB authentification réussie sur {ip}:{port} avec {masked_cred}")
                        break
                    
                    logger.debug(
                        f"Tentative SMB {attempt + 1}/{max_attempts} échouée sur {ip}:{port}"
                    )
                    
                    # Rate limiting
                    if attempt < max_attempts - 1:
                        await asyncio.sleep(delay)
                        
                except Exception as e:
                    logger.error(f"Erreur lors du test SMB sur {ip}:{port}: {e}")
                    results.append(AuthTestResult(
                        host_ip=ip,
                        port=port,
                        service=ServiceType.SMB,
                        credential_used=masked_cred,
                        success=False,
                        error_message=str(e),
                    ))
                    break
        
        return results

    def _smb_auth_attempt(
        self,
        ip: str,
        port: int,
        username: str,
        password: str,
        attempt: int,
    ) -> AuthTestResult:
        """Tente une authentification SMB (synchrone, exécutée dans un thread).
        
        Args:
            ip: Adresse IP de la cible
            port: Port SMB
            username: Nom d'utilisateur
            password: Mot de passe
            attempt: Numéro de la tentative
            
        Returns:
            AuthTestResult: Résultat de la tentative
        """
        if SMBConnection is None:
            masked_cred = self._mask_credential(username, password)
            return AuthTestResult(
                host_ip=ip,
                port=port,
                service=ServiceType.SMB,
                credential_used=masked_cred,
                success=False,
                error_message="pysmb non installé. Installez-le avec: pip install pysmb",
            )
        
        masked_cred = self._mask_credential(username, password)
        
        try:
            smb = SMBConnection(
                username=username,
                password=password,
                my_name="networkrecon",
                remote_name=ip,
                use_ntlm_v2=True,
            )
            
            connected = smb.connect(ip, port, timeout=10)
            
            if connected:
                smb.close()
                return AuthTestResult(
                    host_ip=ip,
                    port=port,
                    service=ServiceType.SMB,
                    credential_used=masked_cred,
                    success=True,
                    error_message=None,
                )
            else:
                return AuthTestResult(
                    host_ip=ip,
                    port=port,
                    service=ServiceType.SMB,
                    credential_used=masked_cred,
                    success=False,
                    error_message="Connexion SMB échouée",
                )
            
        except Exception as e:
            error_msg = str(e)
            if "NT_STATUS_LOGON_FAILURE" in error_msg or "Access Denied" in error_msg:
                return AuthTestResult(
                    host_ip=ip,
                    port=port,
                    service=ServiceType.SMB,
                    credential_used=masked_cred,
                    success=False,
                    error_message="Authentification échouée",
                )
            return AuthTestResult(
                host_ip=ip,
                port=port,
                service=ServiceType.SMB,
                credential_used=masked_cred,
                success=False,
                error_message=f"Erreur SMB: {e}",
            )

    async def test_telnet(
        self,
        ip: str,
        port: int,
        credentials: list[dict],
        max_attempts: int = 3,
        delay: float = 1.0,
    ) -> list[AuthTestResult]:
        """Teste l'authentification Telnet avec telnetlib.
        
        Args:
            ip: Adresse IP de la cible
            port: Port Telnet (défaut: 23)
            credentials: Liste des identifiants à tester
            max_attempts: Nombre maximum de tentatives par identifiant
            delay: Délai entre chaque tentative (secondes)
            
        Returns:
            list[AuthTestResult]: Liste des résultats des tests
            
        Raises:
            UnauthorizedTargetError: Si la cible n'est pas autorisée
        """
        # Vérification d'autorisation OBLIGATOIRE
        await self.verify_authorization(ip)
        
        results = []
        
        for cred in credentials:
            username = cred["username"]
            password = cred["password"]
            masked_cred = self._mask_credential(username, password)
            
            logger.info(f"Test Telnet sur {ip}:{port} avec {masked_cred}")
            
            for attempt in range(max_attempts):
                try:
                    # Exécution du test Telnet dans un thread séparé
                    result = await asyncio.to_thread(
                        self._telnet_auth_attempt,
                        ip,
                        port,
                        username,
                        password,
                        attempt + 1,
                    )
                    results.append(result)
                    
                    if result.success:
                        logger.info(f"Telnet authentification réussie sur {ip}:{port} avec {masked_cred}")
                        break
                    
                    logger.debug(
                        f"Tentative Telnet {attempt + 1}/{max_attempts} échouée sur {ip}:{port}"
                    )
                    
                    # Rate limiting
                    if attempt < max_attempts - 1:
                        await asyncio.sleep(delay)
                        
                except Exception as e:
                    logger.error(f"Erreur lors du test Telnet sur {ip}:{port}: {e}")
                    results.append(AuthTestResult(
                        host_ip=ip,
                        port=port,
                        service=ServiceType.SSH,  # Telnet n'est pas dans ServiceType, on utilise SSH comme placeholder
                        credential_used=masked_cred,
                        success=False,
                        error_message=str(e),
                    ))
                    break
        
        return results

    def _telnet_auth_attempt(
        self,
        ip: str,
        port: int,
        username: str,
        password: str,
        attempt: int,
    ) -> AuthTestResult:
        """Tente une authentification Telnet (synchrone, exécutée dans un thread).
        
        Args:
            ip: Adresse IP de la cible
            port: Port Telnet
            username: Nom d'utilisateur
            password: Mot de passe
            attempt: Numéro de la tentative
            
        Returns:
            AuthTestResult: Résultat de la tentative
        """
        if telnetlib is None:
            masked_cred = self._mask_credential(username, password)
            return AuthTestResult(
                host_ip=ip,
                port=port,
                service=ServiceType.SSH,
                credential_used=masked_cred,
                success=False,
                error_message="telnetlib non disponible (supprimé en Python 3.13+)",
            )
        
        masked_cred = self._mask_credential(username, password)
        
        try:
            tn = telnetlib.Telnet(ip, port, timeout=10)
            
            # Attente du prompt de login
            tn.read_until(b"login: ", timeout=10)
            tn.write(username.encode('ascii') + b"\n")
            
            # Attente du prompt de mot de passe
            tn.read_until(b"Password: ", timeout=10)
            tn.write(password.encode('ascii') + b"\n")
            
            # Vérification de la connexion
            import time
            time.sleep(2)
            
            # Tentative d'exécution d'une commande
            tn.write(b"echo test\n")
            response = tn.read_until(b"test", timeout=5)
            
            tn.close()
            
            if b"test" in response:
                return AuthTestResult(
                    host_ip=ip,
                    port=port,
                    service=ServiceType.SSH,  # Telnet n'est pas dans ServiceType
                    credential_used=masked_cred,
                    success=True,
                    error_message=None,
                )
            else:
                return AuthTestResult(
                    host_ip=ip,
                    port=port,
                    service=ServiceType.SSH,
                    credential_used=masked_cred,
                    success=False,
                    error_message="Authentification échouée",
                )
            
        except Exception as e:
            return AuthTestResult(
                host_ip=ip,
                port=port,
                service=ServiceType.SSH,
                credential_used=masked_cred,
                success=False,
                error_message=f"Erreur Telnet: {e}",
            )

    async def test_rdp(
        self,
        ip: str,
        port: int,
        credentials: list[dict],
        max_attempts: int = 3,
        delay: float = 1.0,
    ) -> list[AuthTestResult]:
        """Teste l'authentification RDP (stub avec warning).
        
        Note: L'implémentation RDP n'est pas encore disponible.
        Cette méthode retourne un avertissement et ne teste pas réellement l'authentification.
        
        Args:
            ip: Adresse IP de la cible
            port: Port RDP (défaut: 3389)
            credentials: Liste des identifiants à tester
            max_attempts: Nombre maximum de tentatives par identifiant
            delay: Délai entre chaque tentative (secondes)
            
        Returns:
            list[AuthTestResult]: Liste des résultats (tous avec warning)
            
        Raises:
            UnauthorizedTargetError: Si la cible n'est pas autorisée
        """
        # Vérification d'autorisation OBLIGATOIRE
        await self.verify_authorization(ip)
        
        results = []
        
        logger.warning(f"Test RDP sur {ip}:{port} : implémentation non disponible")
        
        for cred in credentials:
            username = cred["username"]
            password = cred["password"]
            masked_cred = self._mask_credential(username, password)
            
            # Retour d'un résultat avec warning
            results.append(AuthTestResult(
                host_ip=ip,
                port=port,
                service=ServiceType.RDP,
                credential_used=masked_cred,
                success=False,
                error_message="WARNING: Implémentation RDP non disponible. "
                             "Utilisez une bibliothèque comme 'rdp' ou 'pyrdp' pour implémenter ce test.",
            ))
        
        return results

    async def test_service(
        self,
        ip: str,
        port: int,
        service_type: ServiceType,
        credentials: list[dict],
        config: Optional[AuthTestConfig] = None,
    ) -> list[AuthTestResult]:
        """Route vers le bon test selon le type de service.
        
        Args:
            ip: Adresse IP de la cible
            port: Port du service
            service_type: Type de service à tester
            credentials: Liste des identifiants à tester
            config: Configuration optionnelle des tests
            
        Returns:
            list[AuthTestResult]: Liste des résultats des tests
            
        Raises:
            UnauthorizedTargetError: Si la cible n'est pas autorisée
            AuthTestError: Si le service n'est pas supporté
        """
        # Vérification d'autorisation OBLIGATOIRE
        await self.verify_authorization(ip)
        
        # Extraction des paramètres de configuration
        max_attempts = config.max_attempts if config else 3
        delay = config.delay_between if config else 1.0
        
        logger.info(f"Test du service {service_type.value} sur {ip}:{port}")
        
        # Route vers le bon test
        if service_type == ServiceType.SSH:
            return await self.test_ssh(ip, port, credentials, max_attempts, delay)
        elif service_type == ServiceType.FTP:
            return await self.test_ftp(ip, port, credentials, max_attempts, delay)
        elif service_type == ServiceType.SMB:
            return await self.test_smb(ip, port, credentials, max_attempts, delay)
        elif service_type == ServiceType.RDP:
            return await self.test_rdp(ip, port, credentials, max_attempts, delay)
        elif service_type in [ServiceType.HTTP, ServiceType.HTTPS]:
            raise AuthTestError(
                f"Le test d'authentification HTTP(S) n'est pas encore implémenté. "
                f"Utilisez un scanner HTTP dédié."
            )
        elif service_type in [ServiceType.MYSQL, ServiceType.POSTGRESQL]:
            raise AuthTestError(
                f"Le test d'authentification {service_type.value} n'est pas encore implémenté. "
                f"Utilisez des bibliothèques dédiées (pymysql, psycopg2)."
            )
        elif service_type == ServiceType.REDIS:
            raise AuthTestError(
                "Le test d'authentification Redis n'est pas encore implémenté. "
                "Utilisez la bibliothèque redis-py."
            )
        elif service_type == ServiceType.MONGODB:
            raise AuthTestError(
                "Le test d'authentification MongoDB n'est pas encore implémenté. "
                "Utilisez la bibliothèque pymongo."
            )
        else:
            raise AuthTestError(f"Service non supporté: {service_type}")

    async def run_auth_campaign(self, campaign: AuthCampaign) -> AuthCampaign:
        """Exécute une campagne complète de tests d'authentification.
        
        Args:
            campaign: Campagne à exécuter
            
        Returns:
            AuthCampaign: Campagne mise à jour avec les résultats
            
        Raises:
            UnauthorizedTargetError: Si une cible n'est pas autorisée
            AuthTestError: En cas d'erreur lors de l'exécution
        """
        logger.info(f"Démarrage de la campagne: {campaign.name}")
        
        # Mise à jour du statut
        campaign.status = AuthCampaignStatus.RUNNING
        campaign.results = []
        
        # Calculer le total de credentials à tester
        try:
            if campaign.config.credentials_file:
                credentials = self.load_credentials(campaign.config.credentials_file)
            else:
                # Utiliser les credentials par défaut
                credentials = self.DEFAULT_CREDENTIALS
                logger.info(
                    "Aucun fichier de credentials, utilisation de %d credentials par défaut",
                    len(credentials),
                )
            
            total_targets = len(campaign.targets)
            total_credentials = len(credentials)
            total_tests = total_targets * total_credentials
            
            # Initialiser la progression dans MongoDB
            progress_doc = {
                "_id": campaign.id,
                "campaign_id": campaign.id,
                "status": "running",
                "current_target_index": 0,
                "total_targets": total_targets,
                "current_credential_index": 0,
                "total_credentials": total_credentials,
                "total_tests": total_tests,
                "tests_completed": 0,
                "current_target": campaign.targets[0] if campaign.targets else None,
                "successes": 0,
                "failures": 0,
                "updated_at": datetime.utcnow(),
            }
            await self.db.campaign_progress.update_one(
                {"_id": campaign.id},
                {"$set": progress_doc},
                upsert=True,
            )
            
            # Test de chaque cible
            for target_idx, target_ip in enumerate(campaign.targets):
                logger.info(f"Test de la cible {target_ip} dans la campagne {campaign.name}")
                
                # Mettre à jour la progression - nouveau靶点
                await self._update_progress(
                    campaign.id,
                    current_target_index=target_idx,
                    current_credential_index=0,
                    current_target=target_ip,
                )
                
                try:
                    # Vérification d'autorisation pour chaque cible
                    await self.verify_authorization(target_ip)
                    
                    # Exécution des tests pour cette cible
                    default_ports = {
                        ServiceType.SSH: 22,
                        ServiceType.FTP: 21,
                        ServiceType.SMB: 445,
                        ServiceType.RDP: 3389,
                    }
                    
                    port = default_ports.get(campaign.config.service_type, 22)
                    
                    # Tester avec un callback de progression
                    results = await self.test_service_with_progress(
                        ip=target_ip,
                        port=port,
                        service_type=campaign.config.service_type,
                        credentials=credentials,
                        config=campaign.config,
                        campaign_id=campaign.id,
                        target_index=target_idx,
                        total_targets=total_targets,
                    )
                    
                    # Ajout des résultats à la campagne
                    campaign.results.extend(results)
                    
                    # Compter succès/échecs
                    successes = sum(1 for r in results if r.success)
                    failures = len(results) - successes
                    
                    await self._update_progress(
                        campaign.id,
                        tests_completed=(target_idx + 1) * total_credentials,
                        successes=successes,
                        failures=failures,
                    )
                    
                except UnauthorizedTargetError as e:
                    logger.error(f"Cible non autorisée {target_ip}: {e}")
                    continue
                except Exception as e:
                    logger.error(f"Erreur lors du test de {target_ip}: {e}")
                    continue
            
            # Mise à jour du statut final
            campaign.status = AuthCampaignStatus.COMPLETED
            campaign.completed_at = datetime.utcnow()
            
            # Sauvegarder les résultats dans MongoDB
            await self.db.auth_test_campaigns.update_one(
                {"_id": campaign.id},
                {"$set": {
                    "status": campaign.status.value,
                    "completed_at": campaign.completed_at,
                    "results": [r.model_dump() for r in campaign.results],
                }},
            )
            
            # Marquer la progression comme terminée
            await self._update_progress(
                campaign.id,
                status="completed",
                tests_completed=total_tests,
            )
            
            logger.info(
                f"Campagne {campaign.name} terminée avec succès. "
                f"{len(campaign.results)} résultats collectés."
            )
            
        except Exception as e:
            campaign.status = AuthCampaignStatus.FAILED
            # Sauvegarder les résultats partiels dans MongoDB
            await self.db.auth_test_campaigns.update_one(
                {"_id": campaign.id},
                {"$set": {
                    "status": campaign.status.value,
                    "completed_at": datetime.utcnow(),
                    "results": [r.model_dump() for r in campaign.results],
                    "error_message": str(e),
                }},
            )
            await self._update_progress(
                campaign.id,
                status="failed",
            )
            logger.error(f"Erreur lors de l'exécution de la campagne {campaign.name}: {e}")
            raise
        
        return campaign

    async def _update_progress(
        self,
        campaign_id: str,
        status: Optional[str] = None,
        current_target_index: Optional[int] = None,
        current_credential_index: Optional[int] = None,
        current_target: Optional[str] = None,
        tests_completed: Optional[int] = None,
        successes: Optional[int] = None,
        failures: Optional[int] = None,
    ) -> None:
        """Met à jour la progression d'une campagne dans MongoDB."""
        update_fields = {"updated_at": datetime.utcnow()}
        
        if status is not None:
            update_fields["status"] = status
        if current_target_index is not None:
            update_fields["current_target_index"] = current_target_index
        if current_credential_index is not None:
            update_fields["current_credential_index"] = current_credential_index
        if current_target is not None:
            update_fields["current_target"] = current_target
        if tests_completed is not None:
            update_fields["tests_completed"] = tests_completed
        if successes is not None:
            update_fields["successes"] = successes
        if failures is not None:
            update_fields["failures"] = failures
        
        await self.db.campaign_progress.update_one(
            {"_id": campaign_id},
            {"$set": update_fields},
            upsert=True,
        )

    async def test_service_with_progress(
        self,
        ip: str,
        port: int,
        service_type: ServiceType,
        credentials: list[dict],
        config: Optional[AuthTestConfig] = None,
        campaign_id: Optional[str] = None,
        target_index: int = 0,
        total_targets: int = 1,
    ) -> list[AuthTestResult]:
        """Test un service avec suivi de progression pour chaque credential."""
        await self.verify_authorization(ip)
        
        max_attempts = config.max_attempts if config else 3
        delay = config.delay_between if config else 1.0
        
        logger.info(f"Test du service {service_type.value} sur {ip}:{port}")
        
        results: list[AuthTestResult] = []
        total_creds = len(credentials)
        
        # Compteurs cumulatifs pour le suivi de progression
        cumulative_successes = 0
        cumulative_failures = 0
        
        # Fonction callback pour mettre à jour la progression
        async def progress_callback(cred_index: int, result: AuthTestResult):
            nonlocal cumulative_successes, cumulative_failures
            if result.success:
                cumulative_successes += 1
            else:
                cumulative_failures += 1
            if campaign_id:
                await self._update_progress(
                    campaign_id,
                    tests_completed=cred_index + 1,
                    successes=cumulative_successes,
                    failures=cumulative_failures,
                )
        
        # Route vers le bon test avec callback
        if service_type == ServiceType.SSH:
            results = await self._test_ssh_with_progress(
                ip, port, credentials, max_attempts, delay, campaign_id, progress_callback
            )
        elif service_type == ServiceType.FTP:
            results = await self._test_ftp_with_progress(
                ip, port, credentials, max_attempts, delay, campaign_id, progress_callback
            )
        elif service_type == ServiceType.SMB:
            results = await self.test_smb(ip, port, credentials, max_attempts, delay)
        elif service_type == ServiceType.RDP:
            results = await self.test_rdp(ip, port, credentials, max_attempts, delay)
        else:
            raise AuthTestError(f"Service non supporté: {service_type}")
        
        return results

    async def _test_ssh_with_progress(
        self,
        ip: str,
        port: int,
        credentials: list[dict],
        max_attempts: int,
        delay: float,
        campaign_id: Optional[str],
        progress_callback,
    ) -> list[AuthTestResult]:
        """Test SSH avec progression."""
        results = []
        for idx, cred in enumerate(credentials):
            username = cred.get("username", "")
            password = cred.get("password", "")
            
            # _ssh_auth_attempt est synchrone (paramiko), il faut l'exécuter dans un thread
            result = await asyncio.to_thread(
                self._ssh_auth_attempt, ip, port, username, password, max_attempts
            )
            results.append(result)
            
            if progress_callback:
                await progress_callback(idx, result)
            
            if result.success:
                logger.info(f"Authentification SSH réussie sur {ip} avec {username}:***")
                # On continue pour tester tous les credentials
                await asyncio.sleep(delay)
                continue
            
            # Si erreur réseau fatale (host éteint, port fermé), inutile de continuer
            # On ne s'arrête PAS sur les erreurs SSH (banner, handshake) car ce sont des erreurs temporaires
            error_msg = result.error_message or ""
            is_fatal_network_error = (
                "Connection refused" in error_msg
                or "Connection timed out" in error_msg
                or "No route to host" in error_msg
                or "Host is down" in error_msg
                or "Network is unreachable" in error_msg
            )
            if is_fatal_network_error:
                logger.warning(f"Erreur réseau fatale sur {ip}:{port}, arrêt des tentatives: {error_msg}")
                break
            
            await asyncio.sleep(delay)
        
        return results

    async def _test_ftp_with_progress(
        self,
        ip: str,
        port: int,
        credentials: list[dict],
        max_attempts: int,
        delay: float,
        campaign_id: Optional[str],
        progress_callback,
    ) -> list[AuthTestResult]:
        """Test FTP avec progression."""
        results = []
        for idx, cred in enumerate(credentials):
            username = cred.get("username", "")
            password = cred.get("password", "")
            
            # _ftp_auth_attempt est synchrone (ftplib), il faut l'exécuter dans un thread
            result = await asyncio.to_thread(
                self._ftp_auth_attempt, ip, port, username, password, max_attempts
            )
            results.append(result)
            
            if progress_callback:
                await progress_callback(idx, result)
            
            if result.success:
                logger.info(f"Authentification FTP réussie sur {ip} avec {username}:***")
                # On continue pour tester tous les credentials
                await asyncio.sleep(delay)
                continue
            
            # Si erreur réseau fatale (host éteint, port fermé), inutile de continuer
            error_msg = result.error_message or ""
            is_fatal_network_error = (
                "Connection refused" in error_msg
                or "Connection timed out" in error_msg
                or "No route to host" in error_msg
                or "Host is down" in error_msg
                or "Network is unreachable" in error_msg
                or "Connection reset" in error_msg
            )
            if is_fatal_network_error:
                logger.warning(f"Erreur réseau fatale FTP sur {ip}:{port}, arrêt des tentatives: {error_msg}")
                break
            
            await asyncio.sleep(delay)
        
        return results

    async def store_results(self, campaign_id: str, results: list[AuthTestResult]) -> None:
        """Stocke les résultats de test dans la base de données.
        
        Les mots de passe dans les résultats sont déjà chiffrés.
        
        Args:
            campaign_id: Identifiant de la campagne
            results: Liste des résultats à stocker
            
        Raises:
            AuthTestError: En cas d'erreur lors du stockage
        """
        try:
            # Préparation des documents pour MongoDB
            documents = []
            for result in results:
                doc = result.model_dump()
                doc["campaign_id"] = campaign_id
                doc["timestamp"] = datetime.utcnow()
                
                # Le credential_used est déjà masqué, pas besoin de chiffrer ici
                # car il ne contient que le nom d'utilisateur et ***
                documents.append(doc)
            
            # Insertion dans MongoDB
            if documents:
                await self.db.auth_test_results.insert_many(documents)
                logger.info(
                    f"Stockage de {len(documents)} résultats pour la campagne {campaign_id}"
                )
            
        except Exception as e:
            logger.error(f"Erreur lors du stockage des résultats: {e}")
            raise AuthTestError(f"Erreur lors du stockage des résultats: {e}")

    async def get_results_by_host(self, ip: str) -> list[AuthTestResult]:
        """Récupère les résultats de test pour un hôte spécifique.
        
        Args:
            ip: Adresse IP de l'hôte
            
        Returns:
            list[AuthTestResult]: Liste des résultats pour cet hôte
            
        Raises:
            AuthTestError: En cas d'erreur lors de la récupération
        """
        try:
            cursor = self.db.auth_test_results.find({"host_ip": ip}).sort("timestamp", -1)
            
            results = []
            async for doc in cursor:
                # Conversion de l'ObjectId en string si nécessaire
                if "_id" in doc:
                    doc["_id"] = str(doc["_id"])
                
                # Suppression du campaign_id qui n'est pas dans AuthTestResult
                if "campaign_id" in doc:
                    del doc["campaign_id"]
                
                results.append(AuthTestResult(**doc))
            
            logger.info(f"Récupération de {len(results)} résultats pour l'hôte {ip}")
            return results
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des résultats pour {ip}: {e}")
            raise AuthTestError(f"Erreur lors de la récupération des résultats: {e}")
