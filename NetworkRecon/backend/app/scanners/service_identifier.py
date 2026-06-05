"""Identificateur de services réseau basé sur les ports et bannières."""

import re
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass

from pydantic import BaseModel, Field


class ServiceSignature(BaseModel):
    """Signature d'un service pour l'identification."""
    name: str
    default_ports: List[int]
    patterns: List[str] = []
    description: Optional[str] = None


class ServiceIdentifier:
    """Identificateur de services réseau."""
    
    # Base de données des signatures de services
    SERVICE_SIGNATURES: Dict[str, ServiceSignature] = {
        'http': ServiceSignature(
            name='HTTP',
            default_ports=[80, 8080, 8000, 8888, 443],
            patterns=[
                r'HTTP/[\d.]+',
                r'Server: [\w/\.-]+',
                r'Apache/[\d.]+',
                r'nginx/[\d.]+',
                r'Microsoft-IIS/[\d.]+',
                r'GET /',
                r'POST /',
            ],
            description='Serveur web HTTP/HTTPS',
        ),
        'https': ServiceSignature(
            name='HTTPS',
            default_ports=[443, 8443],
            patterns=[
                r'HTTP/[\d.]+',
                r'SSL',
                r'TLS',
            ],
            description='Serveur web sécurisé HTTPS',
        ),
        'ssh': ServiceSignature(
            name='SSH',
            default_ports=[22, 2222],
            patterns=[
                r'SSH-[\d.]+-\w+',
                r'OpenSSH_[\d.]+',
                r'ssh-',
            ],
            description='Serveur SSH (Secure Shell)',
        ),
        'ftp': ServiceSignature(
            name='FTP',
            default_ports=[21, 2121],
            patterns=[
                r'220.*FTP',
                r'220.*ProFTPD',
                r'220.*vsftpd',
                r'FTP',
            ],
            description='Serveur FTP (File Transfer Protocol)',
        ),
        'smtp': ServiceSignature(
            name='SMTP',
            default_ports=[25, 587, 465],
            patterns=[
                r'220.*SMTP',
                r'220.*ESMTP',
                r'MX',
            ],
            description='Serveur SMTP (Email)',
        ),
        'pop3': ServiceSignature(
            name='POP3',
            default_ports=[110, 995],
            patterns=[
                r'\+OK',
                r'POP3',
            ],
            description='Serveur POP3 (Email)',
        ),
        'imap': ServiceSignature(
            name='IMAP',
            default_ports=[143, 993],
            patterns=[
                r'\* OK',
                r'IMAP',
            ],
            description='Serveur IMAP (Email)',
        ),
        'dns': ServiceSignature(
            name='DNS',
            default_ports=[53],
            patterns=[
                r'domain',
                r'DNS',
            ],
            description='Serveur DNS',
        ),
        'mysql': ServiceSignature(
            name='MySQL',
            default_ports=[3306],
            patterns=[
                r'mysql_native_password',
                r'MySQL[\d.]+',
                r'Host:',
            ],
            description='Base de données MySQL',
        ),
        'postgresql': ServiceSignature(
            name='PostgreSQL',
            default_ports=[5432],
            patterns=[
                r'PostgreSQL[\d.]+',
                r'FATAL.*password authentication',
                r'pg_hba.conf',
            ],
            description='Base de données PostgreSQL',
        ),
        'redis': ServiceSignature(
            name='Redis',
            default_ports=[6379],
            patterns=[
                r'\-ERR',
                r'\+PONG',
                r'\$[\d]+\r\n',
                r'REDIS',
            ],
            description='Base de données Redis',
        ),
        'mongodb': ServiceSignature(
            name='MongoDB',
            default_ports=[27017, 27018],
            patterns=[
                r'MongoDB',
                r'ismaster',
            ],
            description='Base de données MongoDB',
        ),
        'smb': ServiceSignature(
            name='SMB',
            default_ports=[445, 139],
            patterns=[
                r'SMB',
                r'Samba',
                r'MICROSOFTNETWORK',
            ],
            description='Partage de fichiers SMB/Samba',
        ),
        'rdp': ServiceSignature(
            name='RDP',
            default_ports=[3389],
            patterns=[
                r'RDP',
                r'Remote Desktop',
            ],
            description='Bureau à distance RDP',
        ),
        'vnc': ServiceSignature(
            name='VNC',
            default_ports=[5900, 5901, 5902],
            patterns=[
                r'RFB',
                r'VNC',
            ],
            description='Bureau à distance VNC',
        ),
        'telnet': ServiceSignature(
            name='Telnet',
            default_ports=[23],
            patterns=[
                r'login:',
                r'password:',
                r'Telnet',
            ],
            description='Serveur Telnet (non sécurisé)',
        ),
        'snmp': ServiceSignature(
            name='SNMP',
            default_ports=[161, 162],
            patterns=[
                r'SNMP',
                r'public',
            ],
            description='Protocole SNMP',
        ),
        'ldap': ServiceSignature(
            name='LDAP',
            default_ports=[389, 636],
            patterns=[
                r'LDAP',
                r'Active Directory',
            ],
            description='Serveur LDAP/Active Directory',
        ),
        'ntp': ServiceSignature(
            name='NTP',
            default_ports=[123],
            patterns=[
                r'NTP',
                r'reference',
            ],
            description='Serveur NTP (heure)',
        ),
        'dhcp': ServiceSignature(
            name='DHCP',
            default_ports=[67, 68],
            patterns=[
                r'DHCP',
            ],
            description='Serveur DHCP',
        ),
    }
    
    def __init__(self):
        """Initialise l'identificateur de services."""
        self._port_to_service: Dict[int, str] = {}
        self._build_port_mapping()
    
    def _build_port_mapping(self):
        """Construit le mapping port -> service par défaut."""
        for service_name, signature in self.SERVICE_SIGNATURES.items():
            for port in signature.default_ports:
                if port not in self._port_to_service:
                    self._port_to_service[port] = service_name
    
    def get_common_ports(self) -> Dict[int, str]:
        """
        Retourne un dictionnaire des ports courants et leur service par défaut.
        
        Returns:
            Dict mapping port -> nom du service
        """
        return self._port_to_service.copy()
    
    def identify_service(
        self, 
        port: int, 
        banner: Optional[str] = None
    ) -> Tuple[str, float]:
        """
        Identifie le service à partir du port et de la bannière.
        
        Args:
            port: Numéro de port
            banner: Texte de la bannière (optionnel)
        
        Returns:
            Tuple (nom_service, confiance) avec confiance entre 0 et 1
        """
        # Si pas de bannière, utiliser le mapping port
        if not banner:
            service = self._port_to_service.get(port, 'unknown')
            return service, 0.5  # Confiance moyenne
        
        # Analyse de la bannière avec les signatures
        banner_lower = banner.lower()
        
        for service_name, signature in self.SERVICE_SIGNATURES.items():
            score = 0
            matches = 0
            
            for pattern in signature.patterns:
                if re.search(pattern, banner, re.IGNORECASE):
                    matches += 1
                    score += 1
            
            if matches > 0:
                # Confiance basée sur le nombre de patterns correspondants
                confidence = min(0.95, 0.6 + (matches * 0.1))
                
                # Bonus si le port est dans la liste des ports par défaut
                if port in signature.default_ports:
                    confidence = min(0.99, confidence + 0.1)
                
                return service_name, confidence
        
        # Fallback sur le mapping port
        service = self._port_to_service.get(port, 'unknown')
        return service, 0.3  # Confiance faible
    
    def identify_version(self, banner: str) -> Optional[str]:
        """
        Extrait la version exacte d'un service à partir de sa bannière.
        
        Args:
            banner: Texte de la bannière
        
        Returns:
            Version extraite ou None
        """
        if not banner:
            return None
        
        # Patterns d'extraction de version
        version_patterns = [
            # SSH
            (r'SSH-[\d.]+-(\w+)', None),
            (r'OpenSSH[_ ](\d+\.\d+[\.\d]*)', None),
            
            # HTTP
            (r'Apache/(\d+\.\d+[\.\d]*)', None),
            (r'nginx/(\d+\.\d+[\.\d]*)', None),
            (r'Microsoft-IIS/(\d+\.\d+)', None),
            (r'lighttpd/(\d+\.\d+[\.\d]*)', None),
            
            # FTP
            (r'ProFTPD (\d+\.\d+[\.\d]*)', None),
            (r'vsftpd (\d+\.\d+[\.\d]*)', None),
            (r'FileZilla Server (\d+\.\d+[\.\d]*)', None),
            
            # Bases de données
            (r'MySQL[\d.]*[_ ](\d+\.\d+[\.\d]*)', None),
            (r'PostgreSQL[_ ](\d+\.\d+[\.\d]*)', None),
            (r'Redis version (\d+\.\d+[\.\d]*)', None),
            (r'MongoDB (\d+\.\d+[\.\d]*)', None),
            
            # Samba
            (r'Samba (\d+\.\d+[\.\d]*)', None),
            
            # Autres
            (r'(\d+\.\d+[\.\d]*)', None),
        ]
        
        for pattern, _ in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def get_service_info(self, service_name: str) -> Optional[ServiceSignature]:
        """
        Retourne les informations détaillées d'un service.
        
        Args:
            service_name: Nom du service
        
        Returns:
            ServiceSignature ou None si non trouvé
        """
        return self.SERVICE_SIGNATURES.get(service_name.lower())
    
    def add_custom_service(
        self, 
        name: str, 
        ports: List[int], 
        patterns: List[str],
        description: Optional[str] = None
    ):
        """
        Ajoute un service personnalisé à la base de signatures.
        
        Args:
            name: Nom du service
            ports: Liste des ports par défaut
            patterns: Patterns regex pour l'identification
            description: Description du service
        """
        self.SERVICE_SIGNATURES[name.lower()] = ServiceSignature(
            name=name,
            default_ports=ports,
            patterns=patterns,
            description=description,
        )
        
        # Mise à jour du mapping port
        for port in ports:
            if port not in self._port_to_service:
                self._port_to_service[port] = name.lower()