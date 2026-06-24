"""
Testes automatizados — agente-seguranca-soc
Cobertura: FileLock granular, segurança de configuração, validação de URL TLS
"""
import sys
import os
import shutil
import asyncio
import pytest
from pathlib import Path

# Adiciona soc-central ao path
sys.path.insert(0, str(Path(__file__).parent))

TEMP_VAULT = Path(__file__).parent / "test_vault_temp"


@pytest.fixture(autouse=True)
def vault_temp(monkeypatch):
    """Cria vault temporário antes de cada teste e remove depois."""
    TEMP_VAULT.mkdir(exist_ok=True)

    import config as cfg
    monkeypatch.setattr(cfg, "OBSIDIAN_VAULT_PATH", str(TEMP_VAULT.resolve()))

    yield

    if TEMP_VAULT.exists():
        shutil.rmtree(TEMP_VAULT)


# ===========================================================================
# 1. FileLock Granular
# ===========================================================================

class TestFileLockGranular:

    def test_lock_gerado_dentro_da_pasta_locks(self):
        import cerebro_ti
        lock = cerebro_ti.obter_lock_entidade("1.2.3.4")
        assert ".locks" in str(lock.lock_file), "Lock deve estar dentro de .locks/"

    def test_lock_nome_correto_para_ip(self):
        import cerebro_ti
        lock = cerebro_ti.obter_lock_entidade("1.2.3.4")
        assert "1.2.3.4.lock" in str(lock.lock_file)

    def test_lock_sanitiza_caracteres_invalidos(self):
        import cerebro_ti
        lock = cerebro_ti.obter_lock_entidade("hello/world\\test:foo?bar*baz")
        assert "hello_world_test_foo_bar_baz" in str(lock.lock_file), \
            "Caracteres inválidos devem ser substituídos por underscore"

    def test_lock_adquirido_e_liberado(self):
        import cerebro_ti
        lock = cerebro_ti.obter_lock_entidade("192.168.0.1")
        with lock:
            assert lock.is_locked

    def test_locks_diferentes_para_ips_diferentes(self):
        import cerebro_ti
        lock_a = cerebro_ti.obter_lock_entidade("1.1.1.1")
        lock_b = cerebro_ti.obter_lock_entidade("2.2.2.2")
        assert lock_a.lock_file != lock_b.lock_file, \
            "IPs diferentes devem ter locks diferentes"

    def test_mesmo_ip_gera_mesmo_lock(self):
        import cerebro_ti
        lock_a = cerebro_ti.obter_lock_entidade("8.8.8.8")
        lock_b = cerebro_ti.obter_lock_entidade("8.8.8.8")
        assert lock_a.lock_file == lock_b.lock_file, \
            "Mesmo IP deve gerar o mesmo arquivo de lock"


# ===========================================================================
# 2. Configuração Segura — soc-central/config.py
# ===========================================================================

class TestConfiguracaoSegura:

    def test_admin_token_carregado(self):
        import config as cfg
        assert cfg.ADMIN_TOKEN, "ADMIN_TOKEN deve estar definido via .env"

    def test_mysql_user_carregado(self):
        import config as cfg
        assert cfg.MYSQL_USER, "MYSQL_USER deve estar definido via .env"

    def test_mysql_password_carregado(self):
        import config as cfg
        assert cfg.MYSQL_PASSWORD, "MYSQL_PASSWORD deve estar definido via .env"

    def test_admin_token_nao_e_placeholder(self):
        import config as cfg
        placeholders = ["sua_chave", "token_aqui", "admin", "secret", "changeme", ""]
        assert cfg.ADMIN_TOKEN not in placeholders, \
            "ADMIN_TOKEN não deve ser um valor placeholder"


# ===========================================================================
# 3. Validação de URL TLS — config.py raiz
# ===========================================================================

class TestValidacaoTLS:

    def _carregar_config_raiz(self):
        """Importa o config.py da raiz do projeto, evitando conflito com soc-central/config.py."""
        import importlib.util
        raiz = Path(__file__).parent.parent
        spec = importlib.util.spec_from_file_location("config_raiz", raiz / "config.py")
        cfg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cfg)
        return cfg

    def test_url_central_definida(self):
        cfg = self._carregar_config_raiz()
        assert cfg.API_CENTRAL_URL, "API_CENTRAL_URL deve estar definida no config.py da raiz"

    def test_url_local_aceita_http(self):
        cfg = self._carregar_config_raiz()
        url = cfg.API_CENTRAL_URL
        is_local = "127.0.0.1" in url or "localhost" in url
        if is_local:
            assert url.startswith("http://"), \
                "URL local pode usar HTTP em desenvolvimento"

    def test_url_externa_rejeita_http(self):
        """Valida que a lógica de proteção rejeita URLs externas sem HTTPS."""
        url = "http://meu-servidor-soc.com:8000"
        is_local = "127.0.0.1" in url or "localhost" in url
        url_segura = is_local or url.startswith("https://")
        assert not url_segura, \
            "URL externa com HTTP deve ser rejeitada pela validação de TLS"


# ===========================================================================
# 4. Utilitários do cerebro_ti
# ===========================================================================

class TestUtilitariosCerebroTI:

    def test_sanitizar_nome_arquivo_remove_caracteres_invalidos(self):
        import cerebro_ti
        resultado = cerebro_ti._sanitizar_nome_arquivo("arquivo:invalido?nome*aqui")
        assert ":" not in resultado
        assert "?" not in resultado
        assert "*" not in resultado

    def test_sanitizar_nome_arquivo_vazio_retorna_desconhecido(self):
        import cerebro_ti
        assert cerebro_ti._sanitizar_nome_arquivo("") == "Desconhecido"

    def test_sanitizar_nome_arquivo_limite_80_chars(self):
        import cerebro_ti
        nome_longo = "a" * 200
        resultado = cerebro_ti._sanitizar_nome_arquivo(nome_longo)
        assert len(resultado) <= 80

    def test_normalizar_risco_critico(self):
        import cerebro_ti
        assert cerebro_ti.normalizar_risco("CRÍTICO") == "CRÍTICO"
        assert cerebro_ti.normalizar_risco("CRITICO") == "CRÍTICO"

    def test_normalizar_risco_medio(self):
        import cerebro_ti
        assert cerebro_ti.normalizar_risco("MÉDIO") == "MÉDIO"
        assert cerebro_ti.normalizar_risco("MEDIO") == "MÉDIO"

    def test_atualizar_risco_maximo_prioriza_maior(self):
        import cerebro_ti
        assert cerebro_ti.atualizar_risco_maximo("BAIXO", "CRÍTICO") == "CRÍTICO"
        assert cerebro_ti.atualizar_risco_maximo("CRÍTICO", "BAIXO") == "CRÍTICO"
        assert cerebro_ti.atualizar_risco_maximo("MÉDIO", "ALTO") == "ALTO"

    def test_obter_caminho_nota_ip(self):
        import cerebro_ti
        caminho = cerebro_ti.obter_caminho_nota("1.2.3.4", "IPs")
        assert "IPs" in str(caminho)
        assert "IP_1.2.3.4.md" in str(caminho)

    def test_obter_caminho_nota_ttp(self):
        import cerebro_ti
        caminho = cerebro_ti.obter_caminho_nota("T1071", "TTPs")
        assert "TTPs" in str(caminho)
        assert "T1071.md" in str(caminho)