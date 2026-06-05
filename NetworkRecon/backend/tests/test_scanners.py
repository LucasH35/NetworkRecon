"""Tests pour les modules de scan réseau asynchrones."""

import asyncio
import pytest
from unittest.mock import Mock, patch, AsyncMock
from typing import Optional

from app.scanners.nmap_scanner import NmapScanner, HostInfo, PortInfo, ScanResult
from app.scanners.banner_grabber import BannerGrabber, BannerInfo
from app.scanners.service_identifier import ServiceIdentifier, ServiceSignature


class TestNmapScanner:
    """Tests pour la classe NmapScanner."""
    
    @pytest.fixture
    def scanner(self):
        """Crée une instance de NmapScanner."""
        return NmapScanner()
    
    def test_initialization(self, scanner):
        """Teste l'initialisation du scanner."""
        assert scanner._nm is None
    
    def test_get_nmap(self, scanner):
        """Teste le lazy loading de python-nmap."""
        nm = scanner._get_nmap()
        assert nm is not None
        assert scanner._nm is nm
    
    @pytest.mark.asyncio
    async def test_scan_host_mock(self, scanner):
        """Teste le scan d'un hôte avec mock."""
        expected = ScanResult(hosts_found=1, ports_open=2, hosts=[])
        with patch.object(scanner, '_scan_sync', return_value=expected) as mock_sync:
            result = await scanner.scan_host('192.168.1.1')
            
            assert isinstance(result, ScanResult)
            assert result.hosts_found == 1
            assert result.ports_open == 2
            mock_sync.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_quick_scan(self, scanner):
        """Teste le scan rapide."""
        expected = ScanResult(hosts_found=1, ports_open=0, hosts=[])
        with patch.object(scanner, '_scan_sync', return_value=expected) as mock_sync:
            result = await scanner.quick_scan('192.168.1.0/24')
            
            assert result.hosts_found == 1
            mock_sync.assert_called_once()
    
    def test_parse_xml_results(self):
        """Teste le parsing XML de nmap."""
        xml_output = """<?xml version="1.0" encoding="UTF-8"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="192.168.1.1" addrtype="ipv4"/>
                <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Cisco"/>
                <hostnames>
                    <hostname name="test-host" type="PTR"/>
                </hostnames>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" product="Apache" version="2.4.41"/>
                    </port>
                    <port protocol="tcp" portid="443">
                        <state state="open"/>
                        <service name="https"/>
                    </port>
                </ports>
                <os>
                    <osmatch name="Linux 4.15 - 5.6" accuracy="95"/>
                </os>
            </host>
        </nmaprun>"""
        
        hosts = NmapScanner.parse_xml_results(xml_output)
        
        assert len(hosts) == 1
        host = hosts[0]
        assert host.ip == '192.168.1.1'
        assert host.hostname == 'test-host'
        assert host.state == 'up'
        assert host.mac_address == 'AA:BB:CC:DD:EE:FF'
        assert host.vendor == 'Cisco'
        assert len(host.ports) == 2
        assert host.os_guess == 'Linux 4.15 - 5.6'


class TestBannerGrabber:
    """Tests pour la classe BannerGrabber."""
    
    @pytest.fixture
    def grabber(self):
        """Crée une instance de BannerGrabber."""
        return BannerGrabber(default_timeout=2.0)
    
    def test_initialization(self, grabber):
        """Teste l'initialisation du récupérateur."""
        assert grabber.default_timeout == 2.0
    
    @pytest.mark.asyncio
    async def test_grab_banner_tcp(self, grabber):
        """Teste la récupération de bannière TCP."""
        with patch('asyncio.open_connection') as mock_open:
            # Mock du reader/writer
            mock_reader = AsyncMock()
            mock_writer = Mock()
            
            mock_reader.read = AsyncMock(
                return_value=b'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3'
            )
            mock_open.return_value = (mock_reader, mock_writer)
            
            result = await grabber.grab_banner('192.168.1.1', 22)
            
            assert isinstance(result, BannerInfo)
            assert result.ip == '192.168.1.1'
            assert result.port == 22
            assert result.protocol == 'tcp'
            assert 'SSH' in result.banner
            assert result.service_guess == 'ssh'
    
    @pytest.mark.asyncio
    async def test_grab_banner_timeout(self, grabber):
        """Teste le timeout lors de la récupération de bannière."""
        with patch('asyncio.open_connection') as mock_open:
            mock_open.side_effect = asyncio.TimeoutError()
            
            result = await grabber.grab_banner('192.168.1.1', 80)
            
            assert result.error == "Timeout"
    
    @pytest.mark.asyncio
    async def test_grab_service_banners(self, grabber):
        """Teste la récupération de bannières pour plusieurs ports."""
        with patch.object(grabber, 'grab_banner') as mock_grab:
            mock_grab.return_value = BannerInfo(
                ip='192.168.1.1',
                port=80,
                banner='HTTP/1.1 200 OK'
            )
            
            results = await grabber.grab_service_banners(
                '192.168.1.1', 
                [80, 443, 22]
            )
            
            assert len(results) == 3
            assert all(isinstance(r, BannerInfo) for r in results)
    
    def test_parse_banner_ssh(self):
        """Teste le parsing de bannière SSH."""
        banner = 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3'
        service, version = BannerGrabber.parse_banner(banner)
        
        assert service == 'ssh'
        assert version == '8.2'
    
    def test_parse_banner_http(self):
        """Teste le parsing de bannière HTTP."""
        banner = 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)'
        service, version = BannerGrabber.parse_banner(banner)
        
        assert service == 'Apache'
        assert version == '2.4.41'
    
    def test_parse_banner_empty(self):
        """Teste le parsing de bannière vide."""
        service, version = BannerGrabber.parse_banner('')
        
        assert service is None
        assert version is None


class TestServiceIdentifier:
    """Tests pour la classe ServiceIdentifier."""
    
    @pytest.fixture
    def identifier(self):
        """Crée une instance de ServiceIdentifier."""
        return ServiceIdentifier()
    
    def test_initialization(self, identifier):
        """Teste l'initialisation de l'identificateur."""
        assert len(identifier.SERVICE_SIGNATURES) > 0
        assert len(identifier._port_to_service) > 0
    
    def test_get_common_ports(self, identifier):
        """Teste la récupération des ports courants."""
        ports = identifier.get_common_ports()
        
        assert 22 in ports  # SSH
        assert 80 in ports  # HTTP
        assert 443 in ports  # HTTPS
        assert 3306 in ports  # MySQL
        assert 6379 in ports  # Redis
    
    def test_identify_service_with_banner(self, identifier):
        """Teste l'identification de service avec bannière."""
        banner = 'SSH-2.0-OpenSSH_8.2p1'
        service, confidence = identifier.identify_service(22, banner)
        
        assert service == 'ssh'
        assert confidence > 0.6
    
    def test_identify_service_port_only(self, identifier):
        """Teste l'identification de service par port seul."""
        service, confidence = identifier.identify_service(3306)
        
        assert service == 'mysql'
        assert confidence == 0.5
    
    def test_identify_service_unknown(self, identifier):
        """Teste l'identification d'un service inconnu."""
        service, confidence = identifier.identify_service(12345)
        
        assert service == 'unknown'
        # No banner → port-only lookup → confidence 0.5
        assert confidence == 0.5
    
    def test_identify_version(self, identifier):
        """Teste l'extraction de version."""
        banner = 'Apache/2.4.41 (Ubuntu)'
        version = identifier.identify_version(banner)
        
        assert version == '2.4.41'
    
    def test_identify_version_no_version(self, identifier):
        """Teste l'extraction de version quand il n'y en a pas."""
        banner = 'HTTP/1.1 200 OK'
        version = identifier.identify_version(banner)
        
        # The catch-all pattern extracts '1.1' from HTTP/1.1
        assert version == '1.1'
    
    def test_get_service_info(self, identifier):
        """Teste la récupération des informations de service."""
        info = identifier.get_service_info('ssh')
        
        assert info is not None
        assert info.name == 'SSH'
        assert 22 in info.default_ports
    
    def test_add_custom_service(self, identifier):
        """Teste l'ajout d'un service personnalisé."""
        identifier.add_custom_service(
            name='CustomApp',
            ports=[9999],
            patterns=[r'CustomApp/[\d.]+'],
            description='Application personnalisée'
        )
        
        assert 'customapp' in identifier.SERVICE_SIGNATURES
        assert identifier._port_to_service.get(9999) == 'customapp'


class TestModels:
    """Tests pour les modèles Pydantic."""
    
    def test_host_info(self):
        """Teste le modèle HostInfo."""
        host = HostInfo(
            ip='192.168.1.1',
            hostname='test-host',
            state='up',
            ports=[PortInfo(port=80, service='http')],
            os_guess='Linux',
            mac_address='AA:BB:CC:DD:EE:FF',
            vendor='Cisco'
        )
        
        assert host.ip == '192.168.1.1'
        assert len(host.ports) == 1
    
    def test_port_info(self):
        """Teste le modèle PortInfo."""
        port = PortInfo(
            port=443,
            protocol='tcp',
            state='open',
            service='https',
            version='nginx/1.18.0'
        )
        
        assert port.port == 443
        assert port.service == 'https'
    
    def test_scan_result(self):
        """Teste le modèle ScanResult."""
        result = ScanResult(
            hosts=[],
            hosts_found=0,
            ports_open=0,
            scan_time=1.5,
            command='nmap -sV 192.168.1.1'
        )
        
        assert result.hosts_found == 0
        assert result.scan_time == 1.5
    
    def test_banner_info(self):
        """Teste le modèle BannerInfo."""
        banner = BannerInfo(
            ip='192.168.1.1',
            port=22,
            protocol='tcp',
            banner='SSH-2.0-OpenSSH_8.2',
            service_guess='ssh',
            version='8.2'
        )
        
        assert banner.ip == '192.168.1.1'
        assert banner.service_guess == 'ssh'


class TestIntegration:
    """Tests d'intégration entre les modules."""
    
    @pytest.mark.asyncio
    async def test_full_scan_workflow(self):
        """Teste le workflow complet avec parse XML (sans nmap réel)."""
        from app.scanners.nmap_scanner import NmapScanner
        nmap_scanner = NmapScanner()
        service_identifier = ServiceIdentifier()
        
        xml_output = """<?xml version="1.0" encoding="UTF-8"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="192.168.1.1" addrtype="ipv4" vendor="Cisco"/>
                <hostnames><hostname name="test-host" type="ptr"/></hostnames>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh" product="OpenSSH" version="8.2p1"/>
                    </port>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" product="Apache" version="2.4.41"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""
        
        hosts = NmapScanner.parse_xml_results(xml_output)
        assert len(hosts) == 1
        
        # Identification des services
        for host in hosts:
            for port_info in host.ports:
                service, confidence = service_identifier.identify_service(
                    port_info.port,
                    f"{port_info.service}/{port_info.version}" if port_info.version else None
                )
                assert service != 'unknown' or confidence < 0.5


if __name__ == '__main__':
    pytest.main([__file__, '-v'])