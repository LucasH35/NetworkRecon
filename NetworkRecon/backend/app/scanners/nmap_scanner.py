"""Scanner réseau basé sur nmap avec support asynchrone."""

import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

import nmap
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class PortInfo(BaseModel):
    """Modèle pour les informations de port."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None
    extra_info: Optional[str] = None


class HostInfo(BaseModel):
    """Modèle pour les informations d'hôte."""
    ip: str
    hostname: Optional[str] = None
    state: str = "unknown"
    ports: List[PortInfo] = []
    os_guess: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None


class ScanResult(BaseModel):
    """Modèle pour les résultats de scan."""
    hosts: List[HostInfo] = []
    hosts_found: int = 0
    ports_open: int = 0
    scan_time: float = 0.0
    command: str = ""
    raw_xml: Optional[str] = None


class NmapScanner:
    """Scanner asynchrone utilisant python-nmap."""
    
    def __init__(self):
        """Initialise le scanner nmap."""
        self._nm: Optional[nmap.PortScanner] = None
    
    def _get_nmap(self) -> nmap.PortScanner:
        """Retourne une instance de PortScanner (lazy loading)."""
        if self._nm is None:
            self._nm = nmap.PortScanner()
        return self._nm
    
    async def scan_host(
        self, 
        ip: str, 
        ports: Optional[str] = None, 
        scan_type: str = "-sV"
    ) -> ScanResult:
        """
        Effectue le scan d'un hôte unique.
        
        Args:
            ip: Adresse IP de la cible
            ports: Ports à scanner (ex: "1-1000", "80,443", None pour les ports par défaut)
            scan_type: Arguments nmap (ex: "-sV", "-sT", "-O")
        
        Returns:
            ScanResult avec les informations de l'hôte
        """
        return await asyncio.to_thread(
            self._scan_sync, ip, ports, scan_type
        )
    
    async def scan_range(
        self, 
        ip_range: str, 
        ports: Optional[str] = None, 
        scan_type: str = "-sV"
    ) -> ScanResult:
        """
        Effectue le scan d'une plage d'adresses IP.
        
        Args:
            ip_range: Plage CIDR (ex: "192.168.1.0/24")
            ports: Ports à scanner
            scan_type: Arguments nmap
        
        Returns:
            ScanResult avec les informations des hôtes
        """
        return await asyncio.to_thread(
            self._scan_sync, ip_range, ports, scan_type
        )
    
    async def quick_scan(self, ip_range: str) -> ScanResult:
        """
        Effectue un scan rapide des 1000 ports les plus courants.
        
        Args:
            ip_range: Plage CIDR ou IP unique
        
        Returns:
            ScanResult avec les ports ouverts trouvés
        """
        return await asyncio.to_thread(
            self._scan_sync, ip_range, None, "-sT --top-ports 1000 -T4"
        )
    
    async def full_scan(self, ip_range: str) -> ScanResult:
        """
        Effectue un scan complet de tous les ports (1-65535).
        
        Args:
            ip_range: Plage CIDR ou IP unique
        
        Returns:
            ScanResult avec tous les ports ouverts
        """
        return await asyncio.to_thread(
            self._scan_sync, ip_range, "1-65535", "-sV -sC -O"
        )
    
    async def service_scan(
        self, 
        ip: str, 
        ports: Optional[str] = None
    ) -> ScanResult:
        """
        Effectue un scan de détection des services et versions.
        
        Args:
            ip: Adresse IP de la cible
            ports: Ports à scanner
        
        Returns:
            ScanResult avec les services détectés
        """
        return await asyncio.to_thread(
            self._scan_sync, ip, ports, "-sV -sC"
        )
    
    async def os_detect(self, ip: str) -> ScanResult:
        """
        Effectue la détection du système d'exploitation.
        
        Args:
            ip: Adresse IP de la cible
        
        Returns:
            ScanResult avec les informations OS
        """
        return await asyncio.to_thread(
            self._scan_sync, ip, None, "-O -sV"
        )
    
    def _scan_sync(
        self, 
        target: str, 
        ports: Optional[str], 
        arguments: str
    ) -> ScanResult:
        """
        Exécution synchrone du scan (appelé via asyncio.to_thread).
        
        Args:
            target: Cible du scan
            ports: Ports à scanner
            arguments: Arguments nmap
        
        Returns:
            ScanResult avec les résultats parsés
        """
        nm = self._get_nmap()
        
        try:
            logger.info(f"Début du scan de {target} avec arguments: {arguments}")
            nm.scan(hosts=target, ports=ports, arguments=arguments)
            
            # Parse les résultats XML
            return self._parse_results(nm)
            
        except nmap.PortScannerError as e:
            logger.error(f"Erreur nmap: {e}")
            raise ValueError(f"Erreur lors du scan nmap: {e}")
        except Exception as e:
            logger.error(f"Erreur inattendue: {e}")
            raise
    
    def _parse_results(self, nm: nmap.PortScanner) -> ScanResult:
        """
        Parse les résultats du scan nmap en objets Pydantic.
        
        Args:
            nm: Instance PortScanner avec les résultats
        
        Returns:
            ScanResult parsé
        """
        hosts = []
        total_ports_open = 0
        
        for host in nm.all_hosts():
            host_info = HostInfo(
                ip=host,
                hostname=nm[host].hostname() or None,
                state=nm[host].state(),
            )
            
            # Récupération des informations MAC si disponibles
            if 'addresses' in nm[host]:
                for addr_type, addr_value in nm[host]['addresses'].items():
                    if addr_type == 'mac':
                        host_info.mac_address = addr_value
                    elif addr_type == 'vendor':
                        host_info.vendor = addr_value
            
            # Parse des ports
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    port_data = nm[host][proto][port]
                    port_info = PortInfo(
                        port=port,
                        protocol=proto,
                        state=port_data.get('state', 'unknown'),
                        service=port_data.get('name'),
                        version=port_data.get('version'),
                        product=port_data.get('product'),
                        extra_info=port_data.get('extrainfo'),
                    )
                    host_info.ports.append(port_info)
                    if port_info.state == 'open':
                        total_ports_open += 1
            
            # Détection OS si disponible
            if 'osmatch' in nm[host] and nm[host]['osmatch']:
                host_info.os_guess = nm[host]['osmatch'][0].get('name')
            
            hosts.append(host_info)
        
        # Récupération du XML brut
        raw_xml = None
        try:
            raw_xml = nm.get_nmap_last_output()
        except:
            pass
        
        return ScanResult(
            hosts=hosts,
            hosts_found=len(hosts),
            ports_open=total_ports_open,
            scan_time=nm.scanstats().get('elapsed', 0.0),
            command=nm.command_line(),
            raw_xml=raw_xml,
        )
    
    @staticmethod
    def parse_xml_results(xml_output: str) -> List[HostInfo]:
        """
        Parse directement un XML nmap en liste d'HostInfo.
        
        Args:
            xml_output: Sortie XML brute de nmap
        
        Returns:
            Liste d'HostInfo parsés
        """
        hosts = []
        
        try:
            root = ET.fromstring(xml_output)
            
            for host_elem in root.findall('.//host'):
                # Adresse IP
                ip = None
                mac = None
                vendor = None
                
                for addr in host_elem.findall('address'):
                    if addr.get('addrtype') == 'ipv4':
                        ip = addr.get('addr')
                    elif addr.get('addrtype') == 'ipv6':
                        ip = ip or addr.get('addr')
                    elif addr.get('addrtype') == 'mac':
                        mac = addr.get('addr')
                        vendor = addr.get('vendor')
                
                if not ip:
                    continue
                
                # Hostname
                hostname = None
                hostname_elem = host_elem.find('.//hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name')
                
                # État
                state = 'unknown'
                status = host_elem.find('status')
                if status is not None:
                    state = status.get('state', 'unknown')
                
                # Ports
                ports = []
                for port_elem in host_elem.findall('.//port'):
                    port_num = int(port_elem.get('portid', 0))
                    protocol = port_elem.get('protocol', 'tcp')
                    
                    state_elem = port_elem.find('state')
                    port_state = state_elem.get('state', 'unknown') if state_elem is not None else 'unknown'
                    
                    service_elem = port_elem.find('service')
                    service = None
                    version = None
                    product = None
                    extra_info = None
                    
                    if service_elem is not None:
                        service = service_elem.get('name')
                        product = service_elem.get('product')
                        version = service_elem.get('version')
                        extra_info = service_elem.get('extrainfo')
                    
                    ports.append(PortInfo(
                        port=port_num,
                        protocol=protocol,
                        state=port_state,
                        service=service,
                        version=version,
                        product=product,
                        extra_info=extra_info,
                    ))
                
                # OS
                os_guess = None
                os_match = host_elem.find('.//osmatch')
                if os_match is not None:
                    os_guess = os_match.get('name')
                
                hosts.append(HostInfo(
                    ip=ip,
                    hostname=hostname,
                    state=state,
                    ports=ports,
                    os_guess=os_guess,
                    mac_address=mac,
                    vendor=vendor,
                ))
        
        except ET.ParseError as e:
            logger.error(f"Erreur de parsing XML: {e}")
        
        return hosts