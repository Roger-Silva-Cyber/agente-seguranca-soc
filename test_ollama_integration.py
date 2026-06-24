import sys
from pathlib import Path
import os

project_root = Path("c:/agente-seguranca-soc")
sys.path.insert(0, str(project_root.resolve()))
sys.path.insert(0, str((project_root / "soc-central").resolve()))

import dotenv
dotenv.load_dotenv(project_root / ".env")

import agente
import config
import cerebro_ti

def testar_agente_ia():
    print("=== TESTANDO AGENTE IA (OLLAMA LOCAL) ===")
    os.environ["OLLAMA_URL"] = "http://localhost:11434"
    agente.OLLAMA_URL = "http://localhost:11434/v1/chat/completions"
    mensagens = [{"role": "user", "content": "Diga 'Olá Mundo' em apenas uma palavra."}]
    res = agente.chamar_ia(mensagens, timeout=60)
    print(f"Resposta Ollama: {res.strip()}")
    assert len(res) > 0, "Ollama falhou!"
    print("✅ Sucesso no teste do Ollama local no agente!\n")

def testar_agente_fallback():
    print("=== TESTANDO AGENTE IA (FALLBACK GROQ) ===")
    os.environ["OLLAMA_URL"] = "http://localhost:9999"
    agente.OLLAMA_URL = "http://localhost:9999/v1/chat/completions"
    mensagens = [{"role": "user", "content": "Diga 'Fallback' em apenas uma palavra."}]
    res = agente.chamar_ia(mensagens, timeout=60)
    print(f"Resposta Fallback Groq: {res.strip()}")
    assert len(res) > 0, "Groq fallback falhou!"
    print("✅ Sucesso no fallback para Groq no agente!\n")

def testar_cerebro_ti_yara():
    print("=== TESTANDO GERAR REGRA YARA (OLLAMA LOCAL) ===")
    os.environ["OLLAMA_URL"] = "http://localhost:11434"
    dados = {"malware": "Redline Trojan", "termo": "198.51.100.2", "iocs": ["198.51.100.2"]}
    regra = cerebro_ti.gerar_regra_yara(dados)
    print(f"Regra YARA gerada:\n{regra}")
    assert "rule" in regra, "Regra YARA inválida!"
    print("✅ Sucesso na geração de regra YARA com Ollama!\n")

def testar_cerebro_ti_yara_fallback():
    print("=== TESTANDO GERAR REGRA YARA (FALLBACK GROQ) ===")
    os.environ["OLLAMA_URL"] = "http://localhost:9999"
    dados = {"malware": "Redline Trojan", "termo": "198.51.100.2", "iocs": ["198.51.100.2"]}
    regra = cerebro_ti.gerar_regra_yara(dados)
    print(f"Regra YARA via fallback:\n{regra}")
    assert "rule" in regra, "Regra YARA inválida no fallback!"
    print("✅ Sucesso no fallback de geração de regra YARA!\n")

if __name__ == "__main__":
    try:
        testar_agente_ia()
        testar_agente_fallback()
        testar_cerebro_ti_yara()
        testar_cerebro_ti_yara_fallback()
        print("🎉 TODOS OS TESTES DE INTEGRAÇÃO PASSARAM!")
    except Exception as e:
        print(f"❌ Erro nos testes de integração: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)