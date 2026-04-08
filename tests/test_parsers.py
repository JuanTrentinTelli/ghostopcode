# GhostOpcode — parser unit tests
# Run: pytest tests/test_parsers.py -v

from __future__ import annotations

import pytest

from modules.dns_recon import parse_spf
from utils.base_module import pack_session_result
from utils.target_parser import TargetType, parse_target


class TestParseTarget:
    """parse_target — classifies operator input (utils/target_parser.py)."""

    def test_dominio_simples(self) -> None:
        result = parse_target("viasoft.com.br")
        assert result.type is TargetType.DOMAIN
        assert result.value == "viasoft.com.br"

    def test_subdominio(self) -> None:
        result = parse_target("jira.viasoft.com.br")
        assert result.type is TargetType.DOMAIN

    def test_ip_publico(self) -> None:
        result = parse_target("45.33.32.156")
        assert result.type is TargetType.IP

    def test_ip_privado(self) -> None:
        result = parse_target("192.168.1.1")
        assert result.type is TargetType.IP

    def test_cidr(self) -> None:
        result = parse_target("192.168.0.0/24")
        assert result.type is TargetType.CIDR
        assert "/24" in result.value

    def test_input_vazio_falha(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            parse_target("")

    def test_input_none_falha(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            parse_target(None)  # type: ignore[arg-type]


class TestParseSPF:
    """
    parse_spf — SPF from TXT list (modules/dns_recon.py).
    Returns dict with 'risk' key.
    """

    def test_hard_fail_e_low(self) -> None:
        out = parse_spf(["v=spf1 include:spf.google.com -all"])
        assert out["risk"] == "LOW"
        assert out["all_policy"] == "-all"

    def test_soft_fail_e_medium(self) -> None:
        out = parse_spf(["v=spf1 ip4:200.195.135.0/24 ~all"])
        assert out["risk"] == "MEDIUM"

    def test_neutro_e_high(self) -> None:
        out = parse_spf(["v=spf1 ?all"])
        assert out["risk"] == "HIGH"

    def test_pass_e_critical(self) -> None:
        out = parse_spf(["v=spf1 +all"])
        assert out["risk"] == "CRITICAL"

    def test_sem_spf_records_vazia_e_critical(self) -> None:
        out = parse_spf([])
        assert out["found"] is False
        assert out["risk"] == "CRITICAL"

    def test_txt_records_none_nao_aceite(self) -> None:
        """Assinatura real: list[str]; None não é iterável."""
        with pytest.raises(TypeError):
            parse_spf(None)  # type: ignore[arg-type]

    def test_string_vazia_txt_sem_spf_e_critical(self) -> None:
        out = parse_spf([""])
        assert out["risk"] == "CRITICAL"
        assert out["found"] is False


class TestPackSessionResult:
    """pack_session_result — contract dict for JSON/HTML (utils/base_module.py)."""

    def test_estrutura_minima(self) -> None:
        result = pack_session_result(
            {
                "module": "dns_recon",
                "target": "scanme.nmap.org",
                "status": "success",
                "findings": [],
            },
            wall_duration_s=1.5,
        )
        assert isinstance(result, dict)
        assert result["target"] == "scanme.nmap.org"
        assert result["module"] == "dns_recon"
        assert "duration_s" in result
        assert result["_ghostopcode_module_contract_v1"] is True
        assert "errors" in result
        assert "warnings" in result

    def test_target_preservado(self) -> None:
        result = pack_session_result(
            {
                "module": "x",
                "target": "viasoft.com.br",
                "status": "success",
            },
            wall_duration_s=0.0,
        )
        assert result["target"] == "viasoft.com.br"

    def test_lista_vazia_findings_nao_quebra(self) -> None:
        result = pack_session_result(
            {
                "module": "dir_enum",
                "target": "example.com",
                "status": "success",
                "findings": [],
            },
            wall_duration_s=0.0,
        )
        assert result is not None
        assert result["total_findings"] == 0
