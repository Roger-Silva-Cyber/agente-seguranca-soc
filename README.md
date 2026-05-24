# 🛡️ Agente de Segurança SOC

Agente autônomo de monitoramento de segurança com análise por IA.

## O que faz
- Monitora CPU, RAM e conexões de rede em tempo real
- Detecta arquivos novos ou modificados em diretórios críticos
- Detecta processos rodando de locais suspeitos
- Detecta acesso não autorizado a tokens de sessão
- Correlaciona acesso a tokens com conexões externas
- Analisa eventos com IA e classifica por risco
- Gera relatório diário automático

## Stack
- Python 3
- Groq API (Llama 3)
- psutil
- schedule

## Como usar
1. Clone o repositório
2. Crie o arquivo config.py com sua chave Groq
3. Instale as dependências: pip install -r requirements.txt
4. Execute: python3 agente.py

## Autor
Roger — SOC Tier 1 | Segurança de Redes
