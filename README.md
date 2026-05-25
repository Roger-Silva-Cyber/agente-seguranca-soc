# 🛡️ Agente de Segurança SOC

Agente autônomo de monitoramento de segurança com análise por IA, threat intelligence e mitigação automática.

## O que faz

- Monitora CPU, RAM e conexões de rede em tempo real
- Constrói baseline de arquivos e detecta modificações inesperadas
- Detecta processos rodando de locais suspeitos
- Detecta acesso não autorizado a tokens de sessão
- Correlaciona acesso a tokens com conexões externas (exfiltração)
- Consulta IPs maliciosos via OTX AlienVault em tempo real
- Mapeia alertas para técnicas MITRE ATT&CK com contexto completo
- Executa mitigação automática para riscos ALTO e CRÍTICO
- Gera relatório diário automático com todas as ocorrências

## Mitigação automática

| Ameaça | Ação automática |
|---|---|
| IP malicioso | Bloqueia no firewall via iptables |
| Executável em /tmp | Move para quarentena |
| Processo suspeito | Encerra o processo |

## Stack

- Python 3
- Groq API — Llama 3 (análise por IA)
- OTX AlienVault API (threat intelligence)
- MITRE ATT&CK (contexto de técnicas de ataque)
- psutil (monitoramento do sistema)
- schedule (agendamento de tarefas)

## Módulos

| Arquivo | Função |
|---|---|
| agente.py | Núcleo do agente |
| detector_tokens.py | Detecção de acesso a tokens de sessão |
| detector_processos.py | Detecção de processos suspeitos |
| detector_ameacas.py | Consulta de IPs maliciosos via OTX |
| mitigacao.py | MITRE ATT&CK e ações automáticas |
| monitor.py | Coleta de dados do sistema |

## Como usar

1. Clone o repositório
2. Crie o arquivo config.py com suas chaves
3. Instale as dependências: pip install -r requirements.txt
4. Execute: python3 agente.py

## config.py necessário

```python
GROQ_API_KEY = "sua_chave_groq"
OTX_API_KEY = "sua_chave_otx"
MODELO = "llama-3.3-70b-versatile"
CPU_LIMITE = 80
RAM_LIMITE = 85
CONEXOES_LIMITE = 50
DIRETORIOS_MONITORADOS = ["/home/user", "/etc", "/tmp", "/var/log"]
EXTENSOES_SUSPEITAS = [".sh", ".py", ".exe", ".bin", ".elf"]
LOCAIS_SUSPEITOS = ["/tmp", "/var/tmp", "/dev/shm"]
RELATORIO_PATH = "relatorio_diario.txt"
```

## Autor

Roger — SOC Tier 1 | Segurança de Redes
