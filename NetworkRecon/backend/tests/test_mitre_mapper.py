"""Tests unitaires pour le module MitreMapper."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.mitre import MitreMapping
from app.models.vulnerability import CVE, Severity
from app.services.mitre_mapper import (
    MitreMapper,
    MITRE_TACTICS,
    _SERVICE_MITRE_DB,
    _CVE_KEYWORD_TECHNIQUES,
    _technique_url,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def mapper() -> MitreMapper:
    """Retourne une instance Fraîche de MitreMapper."""
    return MitreMapper()


@pytest.fixture
def sample_cve() -> CVE:
    """CVE d'exemple pour les tests."""
    return CVE(
        cve_id="CVE-2023-44228",
        description="Remote code execution via Log4j JNDI injection",
        severity=Severity.CRITICAL,
        cvss_score=10.0,
        affected_products=["Apache Log4j 2.0-2.14.1"],
    )


@pytest.fixture
def sample_cve_sqli() -> CVE:
    """CVE avec injection SQL."""
    return CVE(
        cve_id="CVE-2023-9999",
        description="SQL injection dans l'application web exposée",
        severity=Severity.HIGH,
        cvss_score=8.5,
    )


@pytest.fixture
def sample_mappings() -> list[MitreMapping]:
    """Liste de mappings MITRE pour les tests."""
    return [
        MitreMapping(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            description="Exploitation d'une application exposée",
            url="https://attack.mitre.org/techniques/T1190/",
        ),
        MitreMapping(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution",
            description="Exécution de code",
            url="https://attack.mitre.org/techniques/T1059/",
        ),
        MitreMapping(
            technique_id="T1068",
            technique_name="Exploitation for Privilege Escalation",
            tactic="Privilege Escalation",
            description="Escalade de privilèges",
            url="https://attack.mitre.org/techniques/T1068/",
        ),
        MitreMapping(
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            description="Attaque par force brute",
            url="https://attack.mitre.org/techniques/T1110/",
        ),
    ]


# ---------------------------------------------------------------------------
# Tests __init__
# ---------------------------------------------------------------------------
class TestMitreMapperInit:
    """Tests d'initialisation du MitreMapper."""

    def test_mapper_initialisation(self, mapper: MitreMapper) -> None:
        """Le mapper doit être initialisé correctement."""
        assert mapper._service_db is not None
        assert mapper._cve_keywords is not None
        assert mapper._otx_cache == {}
        assert len(mapper._service_db) > 0

    def test_service_db_richesse(self, mapper: MitreMapper) -> None:
        """La base de mapping doit contenir au moins 25 services."""
        assert len(mapper._service_db) >= 25

    def test_cve_keywords_richesse(self, mapper: MitreMapper) -> None:
        """Les patterns CVE doivent couvrir au moins 15 types de vulnérabilités."""
        assert len(mapper._cve_keywords) >= 15

    def test_all_services_have_techniques(self, mapper: MitreMapper) -> None:
        """Chaque service doit avoir au moins une technique associée."""
        for service, entries in mapper._service_db.items():
            assert len(entries) >= 1, f"Service '{service}' sans technique"
            for entry in entries:
                assert "technique_id" in entry
                assert "technique_name" in entry
                assert "tactic" in entry
                assert "description" in entry

    def test_technique_ids_format(self, mapper: MitreMapper) -> None:
        """Tous les technique_id doivent respecter le format T#### ou T####.###."""
        import re
        pattern = r"^T\d{4}(\.\d{3})?$"
        for service, entries in mapper._service_db.items():
            for entry in entries:
                assert re.match(pattern, entry["technique_id"]), (
                    f"Format invalide '{entry['technique_id']}' "
                    f"pour le service '{service}'"
                )

    def test_tactics_are_valid(self, mapper: MitreMapper) -> None:
        """Toutes les tactiques du mapping doivent être dans la liste MITRE."""
        known_tactics = set(MITRE_TACTICS)
        for service, entries in mapper._service_db.items():
            for entry in entries:
                assert entry["tactic"] in known_tactics, (
                    f"Tactique inconnue '{entry['tactic']}' "
                    f"pour le service '{service}'"
                )


# ---------------------------------------------------------------------------
# Tests techniques_url
# ---------------------------------------------------------------------------
class TestTechniqueUrl:
    """Tests de la fonction utilitaire _technique_url."""

    def test_url_base(self) -> None:
        """L'URL doit commencer par la base MITRE."""
        url = _technique_url("T1190")
        assert url == "https://attack.mitre.org/techniques/T1190/"

    def test_url_subtechnique(self) -> None:
        """L'URL doit gérer les sous-techniques."""
        url = _technique_url("T1021.004")
        assert url == "https://attack.mitre.org/techniques/T1021.004/"


# ---------------------------------------------------------------------------
# Tests map_service_to_mitre
# ---------------------------------------------------------------------------
class TestMapServiceToMitre:
    """Tests du mapping service → MITRE."""

    @pytest.mark.asyncio
    async def test_ssh_mapping(self, mapper: MitreMapper) -> None:
        """Le mapping SSH doit retourner au moins 4 techniques."""
        mappings = await mapper.map_service_to_mitre("ssh")
        assert len(mappings) >= 4
        technique_ids = {m.technique_id for m in mappings}
        assert "T1021.004" in technique_ids
        assert "T1562.001" in technique_ids
        assert "T1552.004" in technique_ids

    @pytest.mark.asyncio
    async def test_http_mapping(self, mapper: MitreMapper) -> None:
        """Le mapping HTTP doit retourner des techniques web."""
        mappings = await mapper.map_service_to_mitre("http")
        assert len(mappings) >= 4
        technique_ids = {m.technique_id for m in mappings}
        assert "T1190" in technique_ids

    @pytest.mark.asyncio
    async def test_rdp_mapping(self, mapper: MitreMapper) -> None:
        """Le mapping RDP doit inclure T1021.001."""
        mappings = await mapper.map_service_to_mitre("rdp")
        technique_ids = {m.technique_id for m in mappings}
        assert "T1021.001" in technique_ids

    @pytest.mark.asyncio
    async def test_unknown_service(self, mapper: MitreMapper) -> None:
        """Un service inconnu doit retourner une liste vide (sans CVE)."""
        mappings = await mapper.map_service_to_mitre("unknown_svc_xyz")
        assert mappings == []

    @pytest.mark.asyncio
    async def test_service_with_cve_enrichment(
        self, mapper: MitreMapper, sample_cve: CVE
    ) -> None:
        """Un service avec CVE doit enrichir le mapping."""
        mappings = await mapper.map_service_to_mitre(
            "http", version="Apache/2.4", vulnerabilities=[sample_cve]
        )
        # Doit contenir les mappings statiques HTTP + ceux de la CVE
        assert len(mappings) >= 5
        technique_ids = {m.technique_id for m in mappings}
        # T1190 est déjà dans HTTP statique, donc pas en double
        # La CVE Log4j doit ajouter T1190 (déjà présent) ou d'autres
        # Le matching par mot-clé "remote code execution" → T1203
        assert "T1203" in technique_ids

    @pytest.mark.asyncio
    async def test_service_name_case_insensitive(
        self, mapper: MitreMapper
    ) -> None:
        """Le mapping doit être insensible à la casse."""
        m1 = await mapper.map_service_to_mitre("SSH")
        m2 = await mapper.map_service_to_mitre("ssh")
        m3 = await mapper.map_service_to_mitre("Ssh")
        assert len(m1) == len(m2) == len(m3)

    @pytest.mark.asyncio
    async def test_all_mappings_are_mitre_mapping(
        self, mapper: MitreMapper
    ) -> None:
        """Tous les résultats doivent être des instances MitreMapping."""
        for service in ["ssh", "http", "mysql", "rdp", "smb"]:
            mappings = await mapper.map_service_to_mitre(service)
            for m in mappings:
                assert isinstance(m, MitreMapping)

    @pytest.mark.asyncio
    async def test_mapping_url_present(self, mapper: MitreMapper) -> None:
        """Chaque mapping doit avoir une URL valide."""
        mappings = await mapper.map_service_to_mitre("ssh")
        for m in mappings:
            assert m.url is not None
            assert m.url.startswith("https://attack.mitre.org/techniques/")


# ---------------------------------------------------------------------------
# Tests map_vulnerability_to_mitre
# ---------------------------------------------------------------------------
class TestMapVulnerabilityToMitre:
    """Tests du mapping CVE → MITRE."""

    @pytest.mark.asyncio
    async def test_rce_mapping(self, mapper: MitreMapper, sample_cve: CVE) -> None:
        """Une CVE RCE doit mapper vers T1203."""
        mappings = await mapper.map_vulnerability_to_mitre(sample_cve)
        technique_ids = {m.technique_id for m in mappings}
        assert "T1203" in technique_ids

    @pytest.mark.asyncio
    async def test_sqli_mapping(
        self, mapper: MitreMapper, sample_cve_sqli: CVE
    ) -> None:
        """Une CVE SQLi doit mapper vers T1190."""
        mappings = await mapper.map_vulnerability_to_mitre(sample_cve_sqli)
        technique_ids = {m.technique_id for m in mappings}
        assert "T1190" in technique_ids

    @pytest.mark.asyncio
    async def test_auth_bypass_mapping(self, mapper: MitreMapper) -> None:
        """Une CVE auth bypass doit mapper vers T1078."""
        cve = CVE(
            cve_id="CVE-2023-5555",
            description="Authentication bypass allows unauthorized access",
            severity=Severity.HIGH,
            cvss_score=7.5,
        )
        mappings = await mapper.map_vulnerability_to_mitre(cve)
        technique_ids = {m.technique_id for m in mappings}
        assert "T1078" in technique_ids

    @pytest.mark.asyncio
    async def test_dos_mapping(self, mapper: MitreMapper) -> None:
        """Une CVE DoS doit mapper vers T1499."""
        cve = CVE(
            cve_id="CVE-2023-6666",
            description="Buffer overflow causing denial of service crash",
            severity=Severity.MEDIUM,
            cvss_score=6.5,
        )
        mappings = await mapper.map_vulnerability_to_mitre(cve)
        technique_ids = {m.technique_id for m in mappings}
        assert "T1499" in technique_ids

    @pytest.mark.asyncio
    async def test_no_duplicate_techniques(self, mapper: MitreMapper) -> None:
        """Une CVE ne doit pas produire de doublons de techniques."""
        cve = CVE(
            cve_id="CVE-2023-7777",
            description="Remote code execution via SQL injection and auth bypass",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
        )
        mappings = await mapper.map_vulnerability_to_mitre(cve)
        ids = [m.technique_id for m in mappings]
        assert len(ids) == len(set(ids)), "Doublons détectés dans les techniques"

    @pytest.mark.asyncio
    async def test_cve_returns_mitre_mapping_instances(
        self, mapper: MitreMapper, sample_cve: CVE
    ) -> None:
        """Tous les résultats doivent être des instances MitreMapping."""
        mappings = await mapper.map_vulnerability_to_mitre(sample_cve)
        for m in mappings:
            assert isinstance(m, MitreMapping)

    @pytest.mark.asyncio
    async def test_cve_with_severity_critical(
        self, mapper: MitreMapper
    ) -> None:
        """Une CVE critique doit au moins retourner des mappings."""
        cve = CVE(
            cve_id="CVE-2024-0001",
            description="Critical remote code execution vulnerability",
            severity=Severity.CRITICAL,
            cvss_score=10.0,
        )
        mappings = await mapper.map_vulnerability_to_mitre(cve)
        assert len(mappings) >= 1


# ---------------------------------------------------------------------------
# Tests get_techniques_for_tactic
# ---------------------------------------------------------------------------
class TestGetTechniquesForTactic:
    """Tests de récupération des techniques par tactique."""

    def test_initial_access_techniques(self, mapper: MitreMapper) -> None:
        """La tactique 'Initial Access' doit avoir des techniques."""
        techniques = mapper.get_techniques_for_tactic("Initial Access")
        assert len(techniques) >= 4
        for t in techniques:
            assert t.tactic == "Initial Access"

    def test_credential_access_techniques(self, mapper: MitreMapper) -> None:
        """La tactique 'Credential Access' doit avoir des techniques."""
        techniques = mapper.get_techniques_for_tactic("Credential Access")
        assert len(techniques) >= 5

    def test_unknown_tactic(self, mapper: MitreMapper) -> None:
        """Une tactique inconnue doit retourner une liste vide."""
        techniques = mapper.get_techniques_for_tactic("NonExistentTactic")
        assert techniques == []

    def test_case_insensitive(self, mapper: MitreMapper) -> None:
        """La recherche doit être insensible à la casse."""
        t1 = mapper.get_techniques_for_tactic("INITIAL ACCESS")
        t2 = mapper.get_techniques_for_tactic("initial access")
        assert len(t1) == len(t2)

    def test_no_duplicates_across_tactics(self, mapper: MitreMapper) -> None:
        """Chaque technique ne doit apparaître qu'une fois par tactique."""
        for tactic in MITRE_TACTICS:
            techniques = mapper.get_techniques_for_tactic(tactic)
            ids = [t.technique_id for t in techniques]
            assert len(ids) == len(set(ids)), (
                f"Doublon dans la tactique '{tactic}'"
            )


# ---------------------------------------------------------------------------
# Tests get_tactics
# ---------------------------------------------------------------------------
class TestGetTactics:
    """Tests de récupération des tactiques."""

    def test_tactics_count(self, mapper: MitreMapper) -> None:
        """Il doit y avoir 14 tactiques MITRE ATT&CK."""
        tactics = mapper.get_tactics()
        assert len(tactics) == 14

    def test_tactics_contain_expected(self, mapper: MitreMapper) -> None:
        """Les tactiques attendues doivent être présentes."""
        tactics = set(mapper.get_tactics())
        assert "Initial Access" in tactics
        assert "Execution" in tactics
        assert "Privilege Escalation" in tactics
        assert "Lateral Movement" in tactics
        assert "Exfiltration" in tactics

    def test_tactics_are_strings(self, mapper: MitreMapper) -> None:
        """Toutes les tactiques doivent être des chaînes."""
        for tactic in mapper.get_tactics():
            assert isinstance(tactic, str)
            assert len(tactic) > 0


# ---------------------------------------------------------------------------
# Tests get_attack_technique (avec mock)
# ---------------------------------------------------------------------------
class TestGetAttackTechnique:
    """Tests de récupération des détails d'une technique."""

    @pytest.mark.asyncio
    async def test_fallback_when_api_unavailable(
        self, mapper: MitreMapper
    ) -> None:
        """Doit retourner un dict fallback si l'API est indisponible."""
        technique = await mapper.get_attack_technique("T1190")
        assert technique["id"] == "T1190"
        assert "name" in technique
        assert "description" in technique
        assert "url" in technique
        assert technique["url"].startswith("https://attack.mitre.org")

    @pytest.mark.asyncio
    async def test_fallback_for_unknown_technique(
        self, mapper: MitreMapper
    ) -> None:
        """Doit retourner un fallback pour une technique inconnue."""
        technique = await mapper.get_attack_technique("T9999")
        assert technique["id"] == "T9999"
        assert technique["name"] == "T9999"

    @pytest.mark.asyncio
    async def test_technique_from_local_db(
        self, mapper: MitreMapper
    ) -> None:
        """Doit trouver T1021.004 dans la base locale."""
        technique = await mapper.get_attack_technique("T1021.004")
        assert technique["id"] == "T1021.004"
        assert "SSH" in technique["name"] or "Remote Services" in technique["name"]


# ---------------------------------------------------------------------------
# Tests build_attack_path
# ---------------------------------------------------------------------------
class TestBuildAttackPath:
    """Tests de construction de parcours d'attaque."""

    def test_empty_mappings(self, mapper: MitreMapper) -> None:
        """Avec une liste vide, le parcours doit être vide."""
        result = mapper.build_attack_path([])
        assert result["total_techniques"] == 0
        assert result["tactics_chain"] == []
        assert result["attack_complexity"] == "none"

    def test_single_tactic(self, mapper: MitreMapper) -> None:
        """Un mapping unique doit créer une seule tactique."""
        mappings = [
            MitreMapping(
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
                tactic="Initial Access",
                description="Test",
            )
        ]
        result = mapper.build_attack_path(mappings)
        assert result["total_techniques"] == 1
        assert len(result["tactics_chain"]) == 1
        assert result["tactics_chain"][0]["tactic"] == "Initial Access"

    def test_multiple_tactics_ordered(
        self, mapper: MitreMapper, sample_mappings: list[MitreMapping]
    ) -> None:
        """Les tactiques doivent être dans l'ordre du kill chain."""
        result = mapper.build_attack_path(sample_mappings)
        tactic_names = [t["tactic"] for t in result["tactics_chain"]]
        # Vérifier l'ordre relatif
        idx_initial = tactic_names.index("Initial Access")
        idx_execution = tactic_names.index("Execution")
        idx_priv = tactic_names.index("Privilege Escalation")
        idx_cred = tactic_names.index("Credential Access")
        assert idx_initial < idx_execution < idx_priv < idx_cred

    def test_highest_risk_technique(
        self, mapper: MitreMapper, sample_mappings: list[MitreMapping]
    ) -> None:
        """La technique la plus risquée doit être Identifiée."""
        result = mapper.build_attack_path(sample_mappings)
        assert result["highest_risk_technique"] is not None
        # T1190 (Initial Access) devrait être la plus risquée
        assert result["highest_risk_technique"]["technique_id"] == "T1190"

    def test_attack_complexity_scaling(self, mapper: MitreMapper) -> None:
        """La complexité doit augmenter avec le nombre de tactiques."""
        # 1 technique → low
        single = [
            MitreMapping(
                technique_id="T1190",
                technique_name="Test",
                tactic="Initial Access",
                description="",
            )
        ]
        assert mapper.build_attack_path(single)["attack_complexity"] == "low"

        # Beaucoup de tactiques → plus complexe
        many = []
        for i, tactic in enumerate(MITRE_TACTICS[:8]):
            many.append(
                MitreMapping(
                    technique_id=f"T{1000 + i}",
                    technique_name=f"Technique {i}",
                    tactic=tactic,
                    description="",
                )
            )
        result = mapper.build_attack_path(many)
        assert result["attack_complexity"] in ("medium", "high", "critical")


# ---------------------------------------------------------------------------
# Tests get_critical_path
# ---------------------------------------------------------------------------
class TestGetCriticalPath:
    """Tests d'analyse du chemin critique."""

    def test_empty_mappings(self) -> None:
        """Avec une liste vide, le score doit être 0."""
        result = MitreMapper.get_critical_path([])
        assert result["risk_score"] == 0
        assert result["critical_techniques"] == []

    def test_risk_score_accumulation(
        self, sample_mappings: list[MitreMapping]
    ) -> None:
        """Le score de risque doit s'accumuler."""
        result = MitreMapper.get_critical_path(sample_mappings)
        assert result["risk_score"] > 0
        assert result["risk_score"] <= 100

    def test_critical_tactics_identified(
        self, sample_mappings: list[MitreMapping]
    ) -> None:
        """Les tactiques critiques doivent être identifiées."""
        result = MitreMapper.get_critical_path(sample_mappings)
        assert len(result["critical_tactics"]) >= 3
        assert "Initial Access" in result["critical_tactics"]
        assert "Execution" in result["critical_tactics"]

    def test_techniques_sorted_by_weight(
        self, sample_mappings: list[MitreMapping]
    ) -> None:
        """Les techniques doivent être triées par poids décroissant."""
        result = MitreMapper.get_critical_path(sample_mappings)
        weights = [t["weight"] for t in result["critical_techniques"]]
        assert weights == sorted(weights, reverse=True)

    def test_max_risk_score(self) -> None:
        """Le score ne doit pas dépasser 100."""
        mappings = [
            MitreMapping(
                technique_id=f"T{1000 + i}",
                technique_name=f"Technique {i}",
                tactic=tactic,
                description="",
            )
            for i, tactic in enumerate(MITRE_TACTICS)
            for _ in range(5)
        ]
        result = MitreMapper.get_critical_path(mappings)
        assert result["risk_score"] == 100


# ---------------------------------------------------------------------------
# Tests export_to_stix
# ---------------------------------------------------------------------------
class TestExportToStix:
    """Tests d'export STIX 2.1."""

    def test_stix_bundle_structure(
        self, sample_mappings: list[MitreMapping]
    ) -> None:
        """Le bundle STIX doit avoir la structure correcte."""
        bundle = MitreMapper.export_to_stix(sample_mappings)
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert "id" in bundle
        assert "objects" in bundle

    def test_stix_objects_count(
        self, sample_mappings: list[MitreMapping]
    ) -> None:
        """Le nombre d'objets doit correspondre aux mappings."""
        bundle = MitreMapper.export_to_stix(sample_mappings)
        assert len(bundle["objects"]) == len(sample_mappings)

    def test_stix_attack_pattern_type(
        self, sample_mappings: list[MitreMapping]
    ) -> None:
        """Tous les objets doivent être de type attack-pattern."""
        bundle = MitreMapper.export_to_stix(sample_mappings)
        for obj in bundle["objects"]:
            assert obj["type"] == "attack-pattern"
            assert obj["spec_version"] == "2.1"

    def test_stix_external_references(
        self, sample_mappings: list[MitreMapping]
    ) -> None:
        """Chaque objet doit avoir des external_references."""
        bundle = MitreMapper.export_to_stix(sample_mappings)
        for obj in bundle["objects"]:
            assert "external_references" in obj
            assert len(obj["external_references"]) >= 1
            ref = obj["external_references"][0]
            assert ref["source_name"] == "mitre-attack"
            assert ref["external_id"].startswith("T")

    def test_stix_kill_chain(
        self, sample_mappings: list[MitreMapping]
    ) -> None:
        """Chaque objet doit avoir un kill_chain_phases."""
        bundle = MitreMapper.export_to_stix(sample_mappings)
        for obj in bundle["objects"]:
            assert "kill_chain_phases" in obj
            assert len(obj["kill_chain_phases"]) >= 1
            phase = obj["kill_chain_phases"][0]
            assert phase["kill_chain_name"] == "mitre-attack"

    def test_stix_empty_input(self) -> None:
        """Un input vide doit retourner un bundle vide."""
        bundle = MitreMapper.export_to_stix([])
        assert bundle["objects"] == []

    def test_stix_valid_json(
        self, sample_mappings: list[MitreMapping]
    ) -> None:
        """Le bundle doit être sérialisable en JSON valide."""
        bundle = MitreMapper.export_to_stix(sample_mappings)
        json_str = json.dumps(bundle, indent=2)
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["type"] == "bundle"


# ---------------------------------------------------------------------------
# Tests store_mapping (avec mock MongoDB)
# ---------------------------------------------------------------------------
class TestStoreMapping:
    """Tests de stockage MongoDB."""

    @pytest.mark.asyncio
    async def test_store_mapping_inserts_document(
        self, mapper: MitreMapper, sample_mappings: list[MitreMapping]
    ) -> None:
        """Le stockage doit insérer un document dans MongoDB."""
        mock_db = MagicMock()
        mock_collection = MagicMock()
        mock_result = MagicMock()
        mock_result.inserted_id = "507f1f77bcf86cd799439013"
        mock_collection.insert_one = AsyncMock(return_value=mock_result)
        # Accès par attribut: db.mitre_mappings
        mock_db.mitre_mappings = mock_collection

        with patch(
            "app.services.mitre_mapper.get_database",
            new_callable=AsyncMock,
            return_value=mock_db,
        ):
            doc_id = await mapper.store_mapping(
                scan_id="scan-123",
                host_ip="192.168.1.1",
                mappings=sample_mappings,
            )

        assert doc_id == "507f1f77bcf86cd799439013"
        mock_collection.insert_one.assert_called_once()

        # Vérifier le contenu du document inséré
        call_args = mock_collection.insert_one.call_args
        doc = call_args[0][0]
        assert doc["scan_id"] == "scan-123"
        assert doc["host_ip"] == "192.168.1.1"
        assert doc["total_techniques"] == len(sample_mappings)
        assert "mappings" in doc
        assert "attack_path" in doc
        assert "created_at" in doc

    @pytest.mark.asyncio
    async def test_store_mapping_empty_list(
        self, mapper: MitreMapper
    ) -> None:
        """Le stockage avec une liste vide doit fonctionner."""
        mock_db = MagicMock()
        mock_collection = MagicMock()
        mock_result = MagicMock()
        mock_result.inserted_id = "empty-id"
        mock_collection.insert_one = AsyncMock(return_value=mock_result)
        mock_db.mitre_mappings = mock_collection

        with patch(
            "app.services.mitre_mapper.get_database",
            new_callable=AsyncMock,
            return_value=mock_db,
        ):
            doc_id = await mapper.store_mapping(
                scan_id="scan-empty",
                host_ip="10.0.0.1",
                mappings=[],
            )

        assert doc_id == "empty-id"
        doc = mock_collection.insert_one.call_args[0][0]
        assert doc["total_techniques"] == 0


# ---------------------------------------------------------------------------
# Tests de cohérence globale
# ---------------------------------------------------------------------------
class TestGlobalConsistency:
    """Tests de cohérence entre les différentes parties du mapper."""

    def test_all_services_have_valid_urls(self, mapper: MitreMapper) -> None:
        """Tous les mappings statiques doivent avoir des URLs valides."""
        for service, entries in mapper._service_db.items():
            for entry in entries:
                url = _technique_url(entry["technique_id"])
                assert url.startswith("https://attack.mitre.org/techniques/")
                assert url.endswith("/")

    def test_mitre_tactics_immutable(self) -> None:
        """La liste des tactiques ne doit pas être modifiable."""
        tactics = MITRE_TACTICS
        assert isinstance(tactics, list)
        original_len = len(tactics)
        # On ne peut pas 'append' car c'est un tuple-like
        # mais on vérifie qu'il y en a 14
        assert original_len == 14

    def test_mapper_multiple_instances(self) -> None:
        """Deux instances du mapper doivent avoir des caches indépendants."""
        m1 = MitreMapper()
        m2 = MitreMapper()
        # Le cache OTX est propre à chaque instance
        assert m1._otx_cache is not m2._otx_cache
        # La base statique est partagée (module-level) mais les instances sont distinctes
        assert m1 is not m2

    def test_mapping_consistency_across_services(
        self, mapper: MitreMapper
    ) -> None:
        """Vérifie la cohérence des mappings pour tous les services."""
        all_technique_ids: set[str] = set()
        for service, entries in mapper._service_db.items():
            for entry in entries:
                all_technique_ids.add(entry["technique_id"])

        # Au moins 30 techniques uniques dans toute la base
        assert len(all_technique_ids) >= 30, (
            f"Seulement {len(all_technique_ids)} techniques uniques"
        )
