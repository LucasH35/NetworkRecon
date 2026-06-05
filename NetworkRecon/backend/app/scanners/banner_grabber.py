"""Récupérateur de bannières réseau asynchrone."""

import asyncio
import logging
import re
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class BannerInfo(BaseModel):
    """Modèle pour les informations de bannière."""
    ip: str
    port: int
    protocol: str = "tcp"
    banner: Optional[str] = None
    service_guess: Optional[str] = None
    version: Optional[str] = None
    raw_banner: Optional[bytes] = None
    error: Optional[str] = None


class BannerGrabber:
    """Récupérateur de bannières réseau asynchrone."""
    
    # Patterns regex pour l'identification de services
    BANNER_PATTERNS = {
        'ssh': [
            r'SSH-[\d.]+-\w+',
            r'OpenSSH_[\d.]+',
        ],
        'http': [
            r'HTTP/[\d.]+',
            r'Server: [\w/\.-]+',
            r'Apache/[\d.]+',
            r'nginx/[\d.]+',
            r'Microsoft-IIS/[\d.]+',
        ],
        'ftp': [
            r'220.*FTP',
            r'220.*ProFTPD',
            r'220.*vsftpd',
        ],
        'smtp': [
            r'220.*SMTP',
            r'220.*ESMTP',
        ],
        'mysql': [
            r'mysql_native_password',
            r'MySQL[\d.]+',
        ],
        'postgresql': [
            r'PostgreSQL[\d.]+',
            r'FATAL.*password authentication',
        ],
        'redis': [
            r'\-ERR',
            r'\+PONG',
            r'\$[\d]+\r\n',
        ],
        'smb': [
            r'SMB',
            r'Samba',
        ],
    }
    
    def __init__(self, default_timeout: float = 3.0):
        """
        Initialise le récupérateur de bannières.
        
        Args:
            default_timeout: Timeout par défaut en secondes
        """
        self.default_timeout = default_timeout
    
    async def grab_banner(
        self, 
        ip: str, 
        port: int, 
        timeout: Optional[float] = None,
        protocol: str = "tcp"
    ) -> BannerInfo:
        """
        Récupère la bannière d'un port spécifique.
        
        Args:
            ip: Adresse IP de la cible
            port: Port à scanner
            timeout: Timeout en secondes (optionnel)
            protocol: Protocole ("tcp" ou "udp")
        
        Returns:
            BannerInfo avec les informations récupérées
        """
        if timeout is None:
            timeout = self.default_timeout
        
        if protocol.lower() == "udp":
            return await self._grab_udp_banner(ip, port, timeout)
        else:
            return await self._grab_tcp_banner(ip, port, timeout)
    
    async def _grab_tcp_banner(
        self, 
        ip: str, 
        port: int, 
        timeout: float
    ) -> BannerInfo:
        """
        Récupère la bannière via TCP.
        
        Args:
            ip: Adresse IP
            port: Port
            timeout: Timeout en secondes
        
        Returns:
            BannerInfo
        """
        banner_info = BannerInfo(
            ip=ip,
            port=port,
            protocol="tcp",
        )
        
        try:
            # Utilisation de asyncio.open_connection pour la connexion TCP
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            
            try:
                # Tentative de lecture de la bannière
                # Certains services envoient une bannière, d'autres attendent une commande
                data = await asyncio.wait_for(
                    reader.read(4096),
                    timeout=timeout
                )
                
                if data:
                    banner_info.raw_banner = data
                    banner_info.banner = data.decode('utf-8', errors='ignore').strip()
                    
                    # Analyse de la bannière
                    service, version = self.parse_banner(banner_info.banner)
                    banner_info.service_guess = service
                    banner_info.version = version
                    
            finally:
                writer.close()
                await writer.wait_closed()
                
        except asyncio.TimeoutError:
            banner_info.error = "Timeout"
            logger.debug(f"Timeout pour {ip}:{port}")
        except ConnectionRefusedError:
            banner_info.error = "Connection refusée"
            logger.debug(f"Connection refusée pour {ip}:{port}")
        except Exception as e:
            banner_info.error = str(e)
            logger.error(f"Erreur lors de la récupération de bannière {ip}:{port}: {e}")
        
        return banner_info
    
    async def _grab_udp_banner(
        self, 
        ip: str, 
        port: int, 
        timeout: float
    ) -> BannerInfo:
        """
        Récupère la bannière via UDP.
        
        Args:
            ip: Adresse IP
            port: Port
            timeout: Timeout en secondes
        
        Returns:
            BannerInfo
        """
        banner_info = BannerInfo(
            ip=ip,
            port=port,
            protocol="udp",
        )
        
        try:
            # Création du socket UDP
            sock = await asyncio.get_event_loop().run_in_executor(
                None, 
                lambda: __import__('socket').socket(__import__('socket').AF_INET, __import__('socket').SOCK_DGRAM)
            )
            
            try:
                # Définition du timeout
                sock.settimeout(timeout)
                
                # Envoi d'un paquet vide pour déclencher une réponse
                # Certains services répondent même à un paquet vide
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: sock.sendto(b'', (ip, port))
                )
                
                # Réception de la réponse
                data, addr = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: sock.recvfrom(4096)
                )
                
                if data:
                    banner_info.raw_banner = data
                    banner_info.banner = data.decode('utf-8', errors='ignore').strip()
                    
                    # Analyse de la bannière
                    service, version = self.parse_banner(banner_info.banner)
                    banner_info.service_guess = service
                    banner_info.version = version
                    
            finally:
                sock.close()
                
        except Exception as e:
            banner_info.error = str(e)
            logger.debug(f"Erreur UDP pour {ip}:{port}: {e}")
        
        return banner_info
    
    async def grab_service_banners(
        self, 
        ip: str, 
        ports: List[int],
        protocol: str = "tcp",
        concurrency: int = 10
    ) -> List[BannerInfo]:
        """
        Récupère les bannières de plusieurs ports de manière concurrente.
        
        Args:
            ip: Adresse IP de la cible
            ports: Liste des ports à scanner
            protocol: Protocole ("tcp" ou "udp")
            concurrency: Nombre maximum de connexions simultanées
        
        Returns:
            Liste des BannerInfo récupérés
        """
        semaphore = asyncio.Semaphore(concurrency)
        
        async def limited_grab(port: int) -> BannerInfo:
            async with semaphore:
                return await self.grab_banner(ip, port, protocol=protocol)
        
        tasks = [limited_grab(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filtrage des résultats
        banners = []
        for result in results:
            if isinstance(result, BannerInfo):
                banners.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Erreur lors de la récupération: {result}")
        
        return banners
    
    @staticmethod
    def parse_banner(banner_text: str) -> tuple[Optional[str], Optional[str]]:
        """
        Extrait le nom du service et la version à partir d'une bannière.
        
        Args:
            banner_text: Texte de la bannière
        
        Returns:
            Tuple (service, version) ou (None, None) si non identifié
        """
        if not banner_text:
            return None, None
        
        banner_lower = banner_text.lower()
        
        # Patterns pour l'extraction de version
        version_patterns = {
            'ssh': [
                (r'OpenSSH[_ ](\d+\.\d+[\.\d]*)', None),
                (r'SSH-[\d.]+-(\w+)', None),
            ],
            'http': [
                (r'Apache/(\d+\.\d+[\.\d]*)', 'Apache'),
                (r'nginx/(\d+\.\d+[\.\d]*)', 'Nginx'),
                (r'Microsoft-IIS/(\d+\.\d+)', 'IIS'),
                (r'Server: ([\w/\.-]+)', None),
            ],
            'ftp': [
                (r'ProFTPD (\d+\.\d+[\.\d]*)', 'ProFTPD'),
                (r'vsftpd (\d+\.\d+[\.\d]*)', 'vsftpd'),
                (r'220.*FTP', 'FTP'),
            ],
            'mysql': [
                (r'MySQL[\d.]*[_ ](\d+\.\d+[\.\d]*)', 'MySQL'),
            ],
            'postgresql': [
                (r'PostgreSQL[_ ](\d+\.\d+[\.\d]*)', 'PostgreSQL'),
            ],
        }
        
        # Identification du service
        service = None
        version = None
        
        # Vérification des patterns connus
        for svc, patterns in BannerGrabber.BANNER_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, banner_text, re.IGNORECASE):
                    service = svc
                    break
            if service:
                break
        
        # Extraction de la version si le service est identifié
        if service and service in version_patterns:
            for pattern, svc_name in version_patterns[service]:
                match = re.search(pattern, banner_text, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    if svc_name:
                        service = svc_name
                    break
        
        return service, version