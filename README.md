# 🛡️ Agente de Segurança SOC

Agente autônomo de monitoramento e resposta a incidentes com análise por IA, threat intelligence em tempo real e mitigação automática. Desenvolvido como projeto prático de Blue Team / SOC Tier 1.

---

## Capacidades

| Categoria | Descrição |
|---|---|
| **Monitoramento** | CPU, RAM, conexões de rede e baseline de arquivos em tempo real |
| **Detecção de Processos** | Processos em locais suspeitos, process masquerading e binários adulterados |
| **Validação 3 Fatores** | Nome + caminho esperado + assinatura digital (Authenticode/codesign/dpkg) |
| **Infostealer Detection** | Acesso não autorizado a tokens de sessão e correlação com exfiltração |
| **Threat Intelligence** | Consulta automática de IPs via OTX AlienVault com enriquecimento de contexto |
| **MITRE ATT&CK** | Mapeamento automático de alertas para técnicas e táticas |
| **Mitigação Automática** | Bloqueio de IPs, quarentena de executáveis e encerramento de processos |
| **Knowledge Graph** | Notas bidirecionais no Obsidian: IPs ↔ Malwares ↔ TTPs ↔ Campanhas |
| **Relatório Diário** | Geração automática de relatório com todas as ocorrências do ciclo |

---

## Mitigação Automática

| Ameaça | Risco | Ação |
|---|---|---|
| IP malicioso externo | ALTO / CRÍTICO | Bloqueio no firewall via `netsh` (Windows) / `iptables` (Linux) |
| Executável em diretório temporário | CRÍTICO | Move para quarentena isolada |
| Process masquerading | CRÍTICO | Encerra o processo e registra evidência |
| Binário com assinatura inválida | CRÍTICO | Alerta + encerramento do processo |

---

## Stack

- **Python 3** — núcleo do agente
- **Groq API** — Llama 3.3 70B (análise e classificação por IA)
- **OTX AlienVault API** — threat intelligence de IPs e IOCs
- **MITRE ATT&CK** — contexto de técnicas de ataque
- **Flask** — dashboard web local
- **psutil** — monitoramento do sistema
- **filelock** — locks granulares por entidade para escrita concorrente segura
- **python-dotenv** — gerenciamento seguro de credenciais

---

## Arquitetura

```
agente-seguranca-soc/
├── agente.py                  # Núcleo do agente — orquestração do ciclo
├── config.py                  # Configuração via variáveis de ambiente (.env)
├── monitor.py                 # Coleta de métricas do sistema
├── detector_processos.py      # Detecção de processos suspeitos (validação 3 fatores)
├── detector_tokens.py         # Detecção de acesso a tokens de sessão
├── detector_ameacas.py        # Consulta de IPs maliciosos via OTX
├── mitigacao.py               # Mapeamento MITRE ATT&CK e ações automáticas
├── soc-central/
│   ├── cerebro_ti.py          # Knowledge Graph bidirecional (Obsidian)
│   ├── config.py              # Configuração da central SOC
│   └── banco.py               # Persistência de eventos
└── dashboard.py               # Dashboard Flask com autenticação
```

---

## Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/Roger-Silva-Cyber/agente-seguranca-soc.git
cd agente-seguranca-soc
```

### 2. Instale as dependências

```bash
pip install -r requirements.txt
```

### 3. Configure as variáveis de ambiente

```bash
cp .env.example .env
```

Edite o `.env` com suas chaves:

```env
GROQ_API_KEY=sua_chave_groq
OTX_API_KEY=sua_chave_otx
API_CENTRAL_URL=http://127.0.0.1:8000
```

> ⚠️ **Nunca commite o arquivo `.env`.** Ele já está protegido no `.gitignore`.
> Gere um token seguro com: `python -c "import secrets; print(secrets.token_hex(32))"`

### 4. Execute o agente

```bash
python agente.py
```

---

## Security Findings & Mitigations

Este projeto passou por uma revisão de segurança completa. As vulnerabilidades identificadas foram corrigidas antes da publicação.

| Severidade | Vulnerabilidade | Arquivo | Status |
|---|---|---|---|
| 🔴 Crítica | Command Injection via interpolação de `exe_path` no PowerShell | `detector_processos.py` | ✅ Corrigido |
| 🟠 Alta | Credenciais hardcoded — hash bcrypt e token admin no código | `dashboard.py`, `config.py` | ✅ Corrigido |
| 🟠 Alta | Comunicação sem TLS — telemetria em HTTP puro | `config.py` | ✅ Corrigido |
| 🟡 Média | Global FileLock bloqueando requisições concorrentes | `cerebro_ti.py` | ✅ Corrigido |

### Detalhes das Correções

**Command Injection**
O `exe_path` era interpolado diretamente na string do comando PowerShell, permitindo execução de código arbitrário via nomes de arquivo maliciosos. Corrigido passando o caminho via variável de ambiente (`$env:TARGET_EXE`) com `-LiteralPath`, eliminando completamente o vetor.

**Hardcoded Credentials**
Tokens e senhas com valores padrão hardcoded como fallback no `os.getenv()`. Corrigido removendo todos os defaults inseguros e adicionando validação explícita com `raise EnvironmentError` caso a variável não esteja definida.

**TLS**
URL da Central SOC com default `http://`. Corrigido forçando configuração explícita via `.env` e adicionando validação que rejeita URLs HTTP em produção (exceto `localhost` para desenvolvimento).

**Global FileLock**
Lock único global bloqueava todo o processamento de threat intelligence sequencialmente. Corrigido com locks granulares por entidade (`obter_lock_entidade(termo)`), `ExitStack` com aquisição ordenada alfabeticamente para evitar deadlocks, e chamadas de rede movidas para fora da zona crítica.

---

## Compatibilidade

| Sistema | Suporte |
|---|---|
| Windows 10/11 | ✅ Completo |
| macOS | ✅ Completo |
| Linux (Debian/Ubuntu/RHEL) | ✅ Completo |

---

## Autor

**Roger Silva** — Blue Team / SOC Tier 1  