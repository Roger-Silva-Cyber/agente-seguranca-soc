import os
import re
import datetime
import json
import httpx
import asyncio
from pathlib import Path
from filelock import FileLock
import config

# Mapeamento local para mitre de fallback se API estiver fora ou falhar
LOCAL_MITRE_DB = {
    'T1059': {
        'id': 'T1059',
        'nome': 'Command and Scripting Interpreter',
        'tatica': 'Execution',
        'descricao': 'Atacantes executam scripts maliciosos em diretórios temporários para evitar detecção.',
        'grupos': 'APT41, FIN7, Lazarus Group',
        'mitigacao': 'Restringir execução em diretórios temporários. Monitorar processos filhos de shells.'
    },
    'T1068': {
        'id': 'T1068',
        'nome': 'Exploitation for Privilege Escalation',
        'tatica': 'Privilege Escalation',
        'descricao': 'Processo não autorizado rodando com altos privilégios pode indicar escalação de privilégios.',
        'grupos': 'APT28, Cobalt Group',
        'mitigacao': 'Revisar permissões de processos. Aplicar patches de segurança do kernel/OS.'
    },
    'T1539': {
        'id': 'T1539',
        'nome': 'Steal Web Session Cookie',
        'tatica': 'Credential Access',
        'descricao': 'Malware acessa arquivos de sessão para roubar tokens de autenticação sem precisar de senha.',
        'grupos': 'Lumma Stealer, Redline Stealer, Raccoon',
        'mitigacao': 'Revogar sessões ativas. Ativar autenticação por hardware (FIDO2).'
    },
    'T1041': {
        'id': 'T1041',
        'nome': 'Exfiltration Over C2 Channel',
        'tatica': 'Exfiltration',
        'descricao': 'Dados sensíveis sendo enviados para servidor externo do atacante.',
        'grupos': 'APT29, FIN6',
        'mitigacao': 'Bloquear IP externo imediatamente. Revogar todos os tokens de sessão.'
    },
    'T1071': {
        'id': 'T1071',
        'nome': 'Application Layer Protocol',
        'tatica': 'Command and Control',
        'descricao': 'Comunicação com IP conhecido como malicioso — possível C2 ou botnet.',
        'grupos': 'APT19, Cozy Bear',
        'mitigacao': 'Bloquear IP no firewall. Verificar processo responsável pela conexão.'
    },
    'T1565': {
        'id': 'T1565',
        'nome': 'Data Manipulation',
        'tatica': 'Impact',
        'descricao': 'Arquivo crítico do sistema foi modificado inesperadamente.',
        'grupos': 'APT38, Sandworm Team',
        'mitigacao': 'Comparar com backup limpo. Reinstalar pacote/sistema afetado.'
    },
    'T1547.001': {
        'id': 'T1547.001',
        'nome': 'Registry Run Keys / Startup Folder',
        'tatica': 'Persistence',
        'descricao': 'Atacantes adicionam programas maliciosos às chaves de inicialização do registro para manter persistência após reinicialização.',
        'grupos': 'APT1, FIN8, Redline Stealer',
        'mitigacao': 'Restringir escrita nas chaves Run/RunOnce. Usar assinaturas digitais nos arquivos referenciados.'
    }
}

# Níveis de risco ordenados
RISCO_NIVEIS = {
    'BAIXO': 1,
    'MÉDIO': 2,
    'MEDIO': 2,
    'ALTO': 3,
    'CRÍTICO': 4,
    'CRITICO': 4
}

# Acumulador de estatísticas global para o ciclo de análise
STATS = {
    "notas_criadas": 0,
    "notas_atualizadas": 0,
    "links_adicionados": 0
}

def reset_stats():
    global STATS
    STATS["notas_criadas"] = 0
    STATS["notas_atualizadas"] = 0
    STATS["links_adicionados"] = 0

def obter_sumario() -> dict:
    return STATS.copy()

def normalizar_risco(r: str) -> str:
    if not r:
        return 'BAIXO'
    r_upper = r.upper().strip()
    if r_upper in ['CRÍTICO', 'CRITICO']:
        return 'CRÍTICO'
    if r_upper in ['MÉDIO', 'MEDIO']:
        return 'MÉDIO'
    if r_upper == 'ALTO':
        return 'ALTO'
    if r_upper == 'BAIXO':
        return 'BAIXO'
    return r_upper

def atualizar_risco_maximo(risco_atual: str, risco_novo: str) -> str:
    r_atual_norm = normalizar_risco(risco_atual)
    r_novo_norm = normalizar_risco(risco_novo)
    
    n_atual = RISCO_NIVEIS.get(r_atual_norm, 0)
    n_novo = RISCO_NIVEIS.get(r_novo_norm, 0)
    
    return r_atual_norm if n_atual >= n_novo else r_novo_norm

def obter_lock_entidade(termo: str) -> FileLock:
    vault_path = config.OBSIDIAN_VAULT_PATH or "."
    # Sanitiza o termo para uso como nome de arquivo
    termo_safe = re.sub(r'[\\/:*?"<>|\s]', '_', termo)
    lock_path = os.path.join(vault_path, f".locks/{termo_safe}.lock")
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    return FileLock(lock_path)

def ler_arquivo(caminho: Path) -> str:
    try:
        with open(caminho, 'r', encoding='utf-8-sig') as f:
            return f.read()
    except Exception as e:
        print(f"❌ Erro ao ler arquivo {caminho}: {e}")
        raise

def escrever_arquivo(caminho: Path, conteudo: str):
    try:
        caminho.parent.mkdir(parents=True, exist_ok=True)
        with open(caminho, 'w', encoding='utf-8-sig') as f:
            f.write(conteudo)
    except Exception as e:
        print(f"❌ Erro ao escrever arquivo {caminho}: {e}")
        raise

def _sanitizar_nome_arquivo(nome: str) -> str:
    if not nome:
        return "Desconhecido"
    # Remove caracteres inválidos no Windows
    nome = re.sub(r'[\\/:*?"<>|\n\r\t]', '', nome)
    # Substitui espaços múltiplos por underscore simples
    nome = re.sub(r'\s+', '_', nome).strip('_ ')
    # Limita tamanho
    nome = nome[:80]
    if not nome:
        return "Desconhecido"
    return nome

def obter_caminho_nota(nome: str, categoria: str = "") -> Path:
    vault_path = Path(config.OBSIDIAN_VAULT_PATH or ".")
    
    if categoria:
        subpasta = categoria
    elif nome.startswith("IP_"):
        subpasta = "IPs"
    elif nome.startswith("Resumo_") or "resumo" in nome.lower():
        subpasta = "Resumos"
    elif nome.startswith("Campanha_") or "campanha" in nome.lower():
        subpasta = "Campanhas"
    else:
        subpasta = ""
        
    nome_clean = nome
    if nome_clean.endswith(".md"):
        nome_clean = nome_clean[:-3]
        
    # Sanitização do nome do arquivo
    nome_clean = _sanitizar_nome_arquivo(nome_clean)
        
    if subpasta == "IPs" and not nome_clean.startswith("IP_"):
        nome_clean = f"IP_{nome_clean}"
        
    return vault_path / subpasta / f"{nome_clean}.md"

def obter_obsidian_link(caminho: Path) -> str:
    pasta = caminho.parent.name
    nome = caminho.stem
    if pasta:
        return f"{pasta}/{nome}"
    return nome

def extrair_chave_deteccao(linha: str) -> str:
    partes = [p.strip() for p in linha.split('|')]
    if len(partes) >= 5:
        data_hora = partes[1]
        processo = partes[2]
        pid = partes[3]
        if data_hora and data_hora[0].isdigit():
            data_minuto = data_hora[:16] if len(data_hora) >= 16 else data_hora
            return f"{data_minuto}:{processo}:{pid}"
    return None

def _obter_linhas_secao_texto(conteudo: str, nome_secao: str) -> list:
    linhas = conteudo.splitlines()
    secao_titulo_clean = nome_secao.lstrip('#').strip()
    
    idx_secao = -1
    for i, linha in enumerate(linhas):
        if linha.strip().startswith('#'):
            header_text = linha.lstrip('#').strip()
            if header_text.lower() == secao_titulo_clean.lower():
                idx_secao = i
                break
                
    if idx_secao == -1:
        return []
        
    idx_fim = len(linhas)
    for i in range(idx_secao + 1, len(linhas)):
        if linhas[i].strip().startswith('#'):
            idx_fim = i
            break
            
    return [l for l in list(linhas[idx_secao + 1 : idx_fim])]

def _atualizar_secao_markdown(conteudo: str, nome_secao: str, nova_linha: str) -> str:
    """
    Insere nova_linha no final da seção nome_secao sem duplicar.
    Usa parsing linha a linha para não corromper outras seções.
    Retorna o conteúdo atualizado.
    """
    linhas = conteudo.splitlines()
    secao_titulo_clean = nome_secao.lstrip('#').strip()
    
    idx_secao = -1
    for i, linha in enumerate(linhas):
        if linha.strip().startswith('#'):
            header_text = linha.lstrip('#').strip()
            if header_text.lower() == secao_titulo_clean.lower():
                idx_secao = i
                break
                
    if idx_secao == -1:
        linhas.append("")
        linhas.append(f"## {secao_titulo_clean}")
        linhas.append(nova_linha)
        return "\n".join(linhas)
        
    idx_fim = len(linhas)
    for i in range(idx_secao + 1, len(linhas)):
        if linhas[i].strip().startswith('#'):
            idx_fim = i
            break
            
    linhas_secao = linhas[idx_secao + 1 : idx_fim]
    
    idx_fim_conteudo = len(linhas_secao)
    while idx_fim_conteudo > 0 and not linhas_secao[idx_fim_conteudo - 1].strip():
        idx_fim_conteudo -= 1
        
    linhas_efetivas = linhas_secao[:idx_fim_conteudo]
    linhas_vazias_finais = linhas_secao[idx_fim_conteudo:]
    
    detectou_duplicado = False
    nova_chave_det = None
    if "|" in nova_linha:
        nova_chave_det = extrair_chave_deteccao(nova_linha)
        
    if nova_chave_det:
        for l in linhas_efetivas:
            if "|" in l:
                chave_l = extrair_chave_deteccao(l)
                if chave_l == nova_chave_det:
                    detectou_duplicado = True
                    break
    else:
        links_na_nova_linha = re.findall(r'(\[\[[^\]]+\]\])', nova_linha)
        if links_na_nova_linha:
            for link in links_na_nova_linha:
                if any(link in l for l in linhas_efetivas):
                    detectou_duplicado = True
                    break
        else:
            if any(l.strip() == nova_linha.strip() for l in linhas_efetivas):
                detectou_duplicado = True
                
    if detectou_duplicado:
        return conteudo
        
    linhas_efetivas.append(nova_linha)
    linhas_secao_atualizadas = linhas_efetivas + linhas_vazias_finais
    linhas[idx_secao + 1 : idx_fim] = linhas_secao_atualizadas
    
    return "\n".join(linhas)

def _substituir_corpo_secao(conteudo: str, nome_secao: str, novo_corpo: str) -> str:
    """
    Substitui o corpo completo da seção nome_secao pelo novo_corpo.
    """
    linhas = conteudo.splitlines()
    secao_titulo_clean = nome_secao.lstrip('#').strip()
    
    idx_secao = -1
    for i, linha in enumerate(linhas):
        if linha.strip().startswith('#'):
            header_text = linha.lstrip('#').strip()
            if header_text.lower() == secao_titulo_clean.lower():
                idx_secao = i
                break
                
    if idx_secao == -1:
        linhas.append("")
        linhas.append(f"## {secao_titulo_clean}")
        linhas.append(novo_corpo)
        return "\n".join(linhas)
        
    idx_fim = len(linhas)
    for i in range(idx_secao + 1, len(linhas)):
        if linhas[i].strip().startswith('#'):
            idx_fim = i
            break
            
    linhas[idx_secao + 1 : idx_fim] = [novo_corpo]
    return "\n".join(linhas)

def _atualizar_frontmatter(conteudo: str, updates: dict) -> str:
    """
    Atualiza campos específicos do frontmatter YAML da nota.
    Nunca sobrescreve campos não mencionados em updates.
    Usa regex para localizar e substituir valores individuais.
    """
    match = re.match(r'^---\r?\n(.*?)\r?\n---\r?\n', conteudo, re.DOTALL)
    if not match:
        linhas_fm = []
        for k, v in updates.items():
            if isinstance(v, list):
                if k == 'tags':
                    v_str = f"[{', '.join(str(x) for x in v)}]"
                else:
                    v_str = json.dumps(v, ensure_ascii=False)
            else:
                v_str = str(v)
            linhas_fm.append(f"{k}: {v_str}")
        return "---\n" + "\n".join(linhas_fm) + "\n---\n" + conteudo.lstrip()

    frontmatter_original = match.group(1)
    conteudo_resto = conteudo[match.end():]
    linhas_fm = frontmatter_original.splitlines()
    
    for k, v in updates.items():
        if isinstance(v, list):
            if k == 'tags':
                v_str = f"[{', '.join(str(x) for x in v)}]"
            else:
                v_str = json.dumps(v, ensure_ascii=False)
        else:
            v_str = str(v)
            
        key_pattern = re.compile(r'^' + re.escape(k) + r':\s*(.*)$')
        found = False
        for idx, linha in enumerate(linhas_fm):
            if key_pattern.match(linha):
                linhas_fm[idx] = f"{k}: {v_str}"
                found = True
                break
        if not found:
            linhas_fm.append(f"{k}: {v_str}")
            
    return "---\n" + "\n".join(linhas_fm) + "\n---\n" + conteudo_resto

def _ler_frontmatter(conteudo: str) -> dict:
    match = re.match(r'^---\r?\n(.*?)\r?\n---\r?\n', conteudo, re.DOTALL)
    if not match:
        return {}
    
    fm_text = match.group(1)
    result = {}
    for line in fm_text.splitlines():
        if ":" in line:
            parts = line.split(":", 1)
            k = parts[0].strip()
            v_str = parts[1].strip()
            if v_str.startswith("[") and v_str.endswith("]"):
                try:
                    items_str = v_str[1:-1]
                    result[k] = [x.strip().strip('"').strip("'") for x in items_str.split(",") if x.strip()]
                except Exception:
                    result[k] = []
            else:
                try:
                    if v_str.isdigit():
                        result[k] = int(v_str)
                    else:
                        result[k] = v_str.strip('"').strip("'")
                except Exception:
                    result[k] = v_str
    return result

def _criar_nota_minima(caminho: Path, nome: str):
    pasta_pai = caminho.parent.name
    data_hoje = datetime.date.today().strftime("%Y-%m-%d")
    data_hora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    
    if pasta_pai == "IPs":
        ip = nome.replace("IP_", "")
        conteudo = f"""---
tags: [ip, threat-intelligence, IOC, malicioso]
ip: {ip}
primeira_deteccao: {data_hora}
ultima_deteccao: {data_hora}
total_deteccoes: 0
risco_maximo: BAIXO
paises: []
---

# IP: {ip}

## Resumo
- **País:** Desconhecido
- **Total de Detecções:** 0
- **Primeira Detecção:** N/A
- **Última Detecção:** N/A
- **Risco Máximo Observado:** BAIXO

## Histórico de Detecções
| Data/Hora | Processo | PID | Risco | Porta |
|-----------|----------|-----|-------|-------|

## Malwares Associados

## TTPs (MITRE ATT&CK)

## IOCs Relacionados
- **Hash:** `Nenhum`
- **Domínios:** `Nenhum`

## Pulsos OTX

## Contramedidas Aplicadas
"""
    elif pasta_pai == "Malwares":
        conteudo = f"""---
tags: [malware, threat-intelligence]
familia: {nome}
tipo: Desconhecido
primeira_deteccao: {data_hora}
ultima_deteccao: {data_hora}
total_ips_associados: 0
---

# {nome}

## Classificação
- **Tipo:** Desconhecido
- **Família:** {nome}
- **Nível de Ameaça:** BAIXO

## IPs Conhecidos

## TTPs Utilizadas

## Campanhas Conhecidas

## Contramedidas

## Regra YARA (gerada por IA)

## Referências
"""
    elif pasta_pai == "TTPs":
        tech_id = nome
        tech_info = LOCAL_MITRE_DB.get(tech_id, {
            'nome': f"Técnica {tech_id}",
            'tatica': "Desconhecido",
            'descricao': "Descrição não disponível localmente.",
            'mitigacao': "Monitorar comportamentos no host."
        })
        conteudo = f"""---
tags: [TTP, MITRE, {tech_id}]
tecnica_id: {tech_id}
nome: {tech_info['nome']}
tatica: {tech_info['tatica']}
primeira_deteccao: {data_hoje}
total_ips_usando: 0
---

# {tech_id} — {tech_info['nome']}

## Descrição
{tech_info['descricao']}

## Tática
- **Fase:** {tech_info['tatica']}

## IPs Detectados Usando Esta Técnica

## Malwares que Usam Esta Técnica

## Mitigações
- {tech_info['mitigacao']}

## Referências
- [MITRE ATT&CK {tech_id}](https://attack.mitre.org/techniques/{tech_id}/)
"""
    elif pasta_pai == "Campanhas":
        conteudo = f"""---
tags: [campanha, threat-intelligence]
nome: {nome}
primeira_deteccao: {data_hoje}
---

# {nome}

## Descrição

## IPs Relacionados

## Malwares Utilizados

## TTPs Identificadas

## Referências
"""
    else:
        conteudo = f"""---
tags: [threat-intelligence]
nome: {nome}
---

# {nome}
"""
    
    escrever_arquivo(caminho, conteudo)
    global STATS
    STATS["notas_criadas"] += 1

def _atualizar_meta_entidade(caminho: Path):
    conteudo = ler_arquivo(caminho)
    pasta_pai = caminho.parent.name
    updates = {}
    
    if pasta_pai == "IPs":
        linhas_det = _obter_linhas_secao_texto(conteudo, "Histórico de Detecções")
        count = 0
        for l in linhas_det:
            if "|" in l and not any(x in l for x in ["Data/Hora", "---"]):
                count += 1
        updates["total_deteccoes"] = count
        
    elif pasta_pai == "Malwares":
        linhas_ips = _obter_linhas_secao_texto(conteudo, "IPs Conhecidos")
        count = sum(1 for l in linhas_ips if "[[IPs/" in l)
        updates["total_ips_associados"] = count
        
    elif pasta_pai == "TTPs":
        linhas_ips = _obter_linhas_secao_texto(conteudo, "IPs Detectados Usando Esta Técnica")
        count = sum(1 for l in linhas_ips if "[[IPs/" in l)
        updates["total_ips_usando"] = count
        
    if updates:
        conteudo_novo = _atualizar_frontmatter(conteudo, updates)
        if conteudo_novo != conteudo:
            escrever_arquivo(caminho, conteudo_novo)

def _adicionar_link_bidirecional(nota_origem: Path, nota_destino: Path, secao_origem: str, secao_destino: str, contexto):
    try:
        if not nota_origem.exists():
            _criar_nota_minima(nota_origem, nota_origem.stem)
            
        if not nota_destino.exists():
            _criar_nota_minima(nota_destino, nota_destino.stem)
            
        conteudo_origem = ler_arquivo(nota_origem)
        conteudo_destino = ler_arquivo(nota_destino)
        
        link_destino = obter_obsidian_link(nota_destino)
        link_origem = obter_obsidian_link(nota_origem)
        
        ctx_origem = ""
        ctx_destino = ""
        if isinstance(contexto, (tuple, list)):
            if len(contexto) >= 2:
                ctx_origem, ctx_destino = contexto[0], contexto[1]
            elif len(contexto) == 1:
                ctx_origem = contexto[0]
        elif isinstance(contexto, str) and contexto:
            ctx_clean = contexto.strip()
            if ctx_clean.startswith("—") or ctx_clean.startswith("-"):
                ctx_clean = ctx_clean.lstrip("—- ").strip()
                
            if "ocorrência" in ctx_clean.lower() or "otx" in ctx_clean.lower() or "pulse" in ctx_clean.lower():
                ctx_origem = f"— {ctx_clean}"
            elif "detectado" in ctx_clean.lower() or "via" in ctx_clean.lower():
                ctx_destino = f"— {ctx_clean}"
            elif re.match(r'^\d{4}-\d{2}-\d{2}', ctx_clean):
                ctx_destino = f"— {ctx_clean}"
            else:
                ctx_destino = f"— {ctx_clean}"
                
        link_busca_destino = f"[[{link_destino}]]"
        secao_linhas_origem = _obter_linhas_secao_texto(conteudo_origem, secao_origem)
        duplicado_origem = any(link_busca_destino in l for l in secao_linhas_origem)
        
        link_busca_origem = f"[[{link_origem}]]"
        secao_linhas_destino = _obter_linhas_secao_texto(conteudo_destino, secao_destino)
        duplicado_destino = any(link_busca_origem in l for l in secao_linhas_destino)
        
        modificou = False
        
        if not duplicado_origem:
            nova_linha_origem = f"- {link_busca_destino}"
            if ctx_origem:
                nova_linha_origem += f" {ctx_origem}"
            conteudo_origem = _atualizar_secao_markdown(conteudo_origem, secao_origem, nova_linha_origem)
            modificou = True
            
        if not duplicado_destino:
            nova_linha_destino = f"- {link_busca_origem}"
            if ctx_destino:
                nova_linha_destino += f" {ctx_destino}"
            conteudo_destino = _atualizar_secao_markdown(conteudo_destino, secao_destino, nova_linha_destino)
            modificou = True
            
        if modificou:
            escrever_arquivo(nota_origem, conteudo_origem)
            escrever_arquivo(nota_destino, conteudo_destino)
            
            _atualizar_meta_entidade(nota_origem)
            _atualizar_meta_entidade(nota_destino)
            
            global STATS
            STATS["links_adicionados"] += 1
            
    except Exception as e:
        print(f"❌ Erro ao adicionar link bidirecional entre {nota_origem} e {nota_destino}: {e}")
        raise

def _obter_detalhes_do_ip_do_banco(ip: str) -> dict:
    detalhes_padrao = {
        "processo": "Desconhecido",
        "pid": "N/A",
        "risco": "ALTO",
        "porta": "443",
        "data_hora": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    
    try:
        from banco import SessionLocal, Evento
        db = SessionLocal()
        eventos = db.query(Evento).order_by(Evento.id.desc()).limit(10).all()
        db.close()
        
        for ev in eventos:
            alertas = ev.alertas
            if not alertas:
                continue
            if isinstance(alertas, str):
                try:
                    alertas = json.loads(alertas)
                except Exception:
                    pass
            
            if not isinstance(alertas, list):
                continue
                
            for alerta in alertas:
                if not isinstance(alerta, dict):
                    continue
                detalhes = alerta.get('detalhes', {})
                if not isinstance(detalhes, dict):
                    continue
                
                if detalhes.get('ip') == ip:
                    processo = detalhes.get('processo') or "Desconhecido"
                    pid = detalhes.get('pid') or "N/A"
                    risco = detalhes.get('risco') or ev.risco or "ALTO"
                    porta = detalhes.get('porta') or detalhes.get('port') or "443"
                    
                    risco_norm = normalizar_risco(str(risco))
                    
                    data_hora = ev.hora if ev.hora else datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
                    if len(data_hora) <= 8:
                        hoje = datetime.date.today().strftime("%Y-%m-%d")
                        data_hora = f"{hoje} {data_hora[:5]}"
                        
                    return {
                        "processo": processo,
                        "pid": str(pid),
                        "risco": risco_norm,
                        "porta": str(porta),
                        "data_hora": data_hora
                    }
    except Exception as e:
        print(f"⚠️ Erro ao obter detalhes do IP do banco de dados: {e}")
        
    return detalhes_padrao

async def _obter_detalhes_do_ip_do_banco_async(ip: str) -> dict:
    detalhes_padrao = {
        "processo": "desconhecido",
        "pid": "desconhecido",
        "risco": "desconhecido",
        "porta": "desconhecido",
        "data_hora": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return _obter_detalhes_do_ip_do_banco(ip)
        
    try:
        res = await asyncio.wait_for(
            loop.run_in_executor(None, _obter_detalhes_do_ip_do_banco, ip),
            timeout=2.0
        )
        return res
    except asyncio.TimeoutError:
        print(f"⚠️ [TI] Timeout de 2s excedido ao consultar banco para o IP {ip}. Usando valores 'desconhecido'.")
        return detalhes_padrao
    except Exception as e:
        print(f"⚠️ [TI] Falha na consulta assíncrona ao banco para o IP {ip}: {e}. Usando valores 'desconhecido'.")
        return detalhes_padrao

def extrair_iocs_da_nota(conteudo_nota: str) -> set:
    iocs = set()
    matches = re.findall(r'`([^`\s]+)`', conteudo_nota)
    for m in matches:
        m_clean = m.strip()
        if m_clean and m_clean != "Nenhum":
            iocs.add(m_clean)
    return iocs

def pesquisar_ip(ip: str) -> dict:
    headers = {"X-OTX-API-KEY": config.OTX_API_KEY} if config.OTX_API_KEY else {}
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        response = httpx.get(url, headers=headers, timeout=10.0)
        if response.status_code == 200:
            dados = response.json()
            pulse_info = dados.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            total_pulsos = pulse_info.get("count", 0)
            
            malwares = []
            comportamentos = []
            tags_todas = []
            pulsos_lista = []
            
            for p in pulses:
                name = p.get("name", "")
                if name:
                    malwares.append(name)
                    pulsos_lista.append(name)
                desc = p.get("description", "")
                if desc:
                    comportamentos.append(desc)
                for tag in p.get("tags", []):
                    tags_todas.append(tag.lower())
                for fam in p.get("malware_families", []):
                    if isinstance(fam, str):
                        malwares.append(fam)
                    elif isinstance(fam, dict):
                        malwares.append(fam.get("name", ""))
            
            tipo = "Desconhecido"
            for t in tags_todas:
                if "ransomware" in t:
                    tipo = "ransomware"
                    break
                elif "trojan" in t:
                    tipo = "trojan"
                    break
                elif "botnet" in t:
                    tipo = "botnet"
                    break
                elif "worm" in t:
                    tipo = "worm"
                    break
                elif "spyware" in t:
                    tipo = "spyware"
                    break
            
            if tipo == "Desconhecido" and pulses:
                tipo = "trojan"
                
            malware_associado = malwares[0] if malwares else "IP Suspeito"
            comportamento_desc = comportamentos[0] if comportamentos else f"Conexão detectada com IP classificado como malicioso no OTX AlienVault com {total_pulsos} pulses."
            pais = dados.get("country_name", "Desconhecido")
            
            return {
                "termo": ip,
                "malware": malware_associado,
                "malwares": list(set(malwares)),
                "origem": pais,
                "pulsos": total_pulsos,
                "pulsos_lista": list(set(pulsos_lista)),
                "iocs": [ip],
                "tipo": tipo,
                "comportamento": comportamento_desc,
                "referencias": ["OTX AlienVault"]
            }
        else:
            print(f"⚠️ OTX retornou status {response.status_code} para o IP {ip}")
    except Exception as e:
        print(f"⚠️ Erro ao consultar OTX para {ip}: {e}")
        
    return {
        "termo": ip,
        "malware": "IP Suspeito",
        "origem": "Desconhecido",
        "pulsos": 0,
        "pulsos_lista": [],
        "iocs": [ip],
        "tipo": "Desconhecido",
        "comportamento": "IP consultado sem informações detalhadas disponíveis.",
        "referencias": ["OTX AlienVault"]
    }

def pesquisar_mitre(tecnica_id: str) -> dict:
    try:
        url = f"https://attack.mitre.org/api/technique/{tecnica_id}"
        response = httpx.get(url, timeout=10.0)
        if response.status_code == 200:
            pass
    except Exception as e:
        print(f"⚠️ Erro ao consultar MITRE para {tecnica_id}: {e}")
        
    tech = LOCAL_MITRE_DB.get(tecnica_id)
    if tech:
        return tech
        
    return {
        'id': tecnica_id,
        'nome': f"Técnica {tecnica_id}",
        'tatica': "Desconhecido",
        'descricao': "Descrição não disponível localmente.",
        'grupos': "Desconhecido",
        'mitigacao': "Monitorar comportamentos no host."
    }

def gerar_nota_obsidian(dados: dict) -> str:
    # Mantida para compatibilidade genérica se necessário, mas consultar_base_local usa templates cirúrgicos
    data_hoje = datetime.date.today().strftime("%Y-%m-%d")
    
    ips_str = ", ".join([f"`{ip}`" for ip in dados.get("iocs", []) if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip)])
    if not ips_str:
        ips_str = "Nenhum"
        
    dominios_str = ", ".join([f"`{d}`" for d in dados.get("iocs", []) if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', d)])
    if not dominios_str:
        dominios_str = "Nenhum"
        
    ttps_list = dados.get("ttps", [])
    if ttps_list:
        ttps_formatted = "\n".join([f"- [[{tid}]] — {tnome}" for tid, tnome in ttps_list])
    else:
        ttps_formatted = "- Nenhuma técnica mapeada"
        
    contramedidas = "\n".join([f"- {c}" for c in dados.get("contramedidas", [])])
    if not contramedidas:
        contramedidas = "- Nenhuma contramedida especificada"
        
    regra_yara = dados.get("yara_rule", "")
    
    nota = f"""---
tags: [malware, threat-intelligence, IOC]
data: {data_hoje}
fonte: OTX AlienVault
---

# {dados.get('malware', dados['termo'])}

## Classificação
- Tipo: {dados.get('tipo', 'Desconhecido')}

## Comportamento Típico
- {dados.get('comportamento', 'Comportamento não especificado.')}

## IOCs Conhecidos
- IPs: {ips_str}
- Domínios: {dominios_str}

## TTPs (MITRE ATT&CK)
{ttps_formatted}

## Contramedidas
{contramedidas}

## Regra YARA
```yara
{regra_yara}
```

## Referências
- OTX: https://otx.alienvault.com
- MITRE: https://attack.mitre.org
"""
    return nota

def gerar_regra_yara(dados: dict) -> str:
    prompt = f"Gere uma regra YARA válida para detectar o malware {dados.get('malware', 'Malware')}. Use os IOCs: {dados['iocs']}. A regra deve começar com 'rule Detect_...' e incluir as seções 'strings' e 'condition'. Retorne apenas o código YARA formatado, sem introduções ou explicações."
    
    conteudo = None
    
    # 1. Tenta Ollama local primeiro com timeout de 60s
    try:
        ollama_url_env = os.getenv("OLLAMA_URL", "http://localhost:11434")
        if "v1/chat/completions" not in ollama_url_env:
            ollama_url = f"{ollama_url_env.rstrip('/')}/v1/chat/completions"
        else:
            ollama_url = ollama_url_env
            
        response = httpx.post(
            ollama_url,
            json={
                "model": os.getenv("OLLAMA_MODEL", "llama3.1"),
                "messages": [{"role": "user", "content": prompt}],
                "stream": False
            },
            timeout=60.0
        )
        if response.status_code == 200:
            conteudo = response.json()['choices'][0]['message']['content']
    except Exception as e:
        print(f"⚠️ Ollama local indisponível para gerar regra YARA: {e}. Tentando Groq como fallback.")

    # 2. Fallback para Groq se o Ollama falhar/não estiver disponível
    if conteudo is None:
        if config.GROQ_API_KEY and config.GROQ_API_KEY != "sua_chave_groq":
            try:
                response = httpx.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {config.GROQ_API_KEY}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "llama-3.3-70b-versatile",
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 400
                    },
                    timeout=10.0
                )
                if response.status_code == 200:
                    conteudo = response.json()['choices'][0]['message']['content']
            except Exception as e:
                print(f"⚠️ Erro ao gerar regra YARA com Groq: {e}")
        else:
            print("⚠️ Groq não configurado como fallback para gerar regra YARA.")

    # 3. Processa e limpa a resposta obtida ou usa a regra YARA estática básica de fallback se ambos falharem
    if conteudo:
        # Tenta extrair apenas o bloco que contém a regra YARA
        idx_rule = conteudo.find("rule ")
        if idx_rule == -1:
            idx_rule = conteudo.find("rule")
            
        if idx_rule != -1:
            idx_close = conteudo.rfind("}")
            if idx_close != -1 and idx_close > idx_rule:
                conteudo = conteudo[idx_rule:idx_close+1]
        elif "```" in conteudo:
            # Fallback para o limpador de markdown legado caso não consiga fatiar
            linhas = conteudo.split("\n")
            linhas_limpas = []
            inside = False
            for l in linhas:
                if l.strip().startswith("```"):
                    inside = not inside
                    continue
                linhas_limpas.append(l)
            conteudo = "\n".join(linhas_limpas)
            
        return conteudo.strip()

    return f"""rule Detect_{dados.get('malware', 'Malware').replace(' ', '_')} {{
    strings:
        $ip = "{dados['termo']}"
    condition:
        $ip
}}"""

def salvar_nota(nome: str, conteudo: str):
    # Mantida apenas para compatibilidade legada se for importada ou testada dinamicamente
    # Delega para a nova estrutura de gravação baseada no nome
    caminho = obter_caminho_nota(nome)
    escrever_arquivo(caminho, conteudo)
    global STATS
    STATS["notas_criadas"] += 1

def criar_ou_atualizar_nota_malware(malware_name: str, ip: str, tipo_malware: str, ttps: list, contramedidas: list):
    # Mantida para compatibilidade legada, delegando para adicionar_link_bidirecional
    ip_path = obter_caminho_nota(ip, "IPs")
    malware_path = obter_caminho_nota(malware_name, "Malwares")
    
    dt_curta = datetime.date.today().strftime("%Y-%m-%d")
    contexto = (
        "— 1 ocorrência OTX",
        f"— detectado em {dt_curta}"
    )
    _adicionar_link_bidirecional(ip_path, malware_path, "Malwares Associados", "IPs Conhecidos", contexto)

async def consultar_base_local(
    termo: str, 
    processo: str = None, 
    pid: str = None, 
    risco: str = None, 
    porta: str = None
) -> str:
    """
    Verifica se já existe nota sobre o IP ou outro termo na vault.
    Se não encontrar, pesquisa remotamente e salva no Obsidian.
    Implementado com Timeline Imutável e Knowledge Graph Bidirecional.
    """
    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', termo)
    
    # 1. Executa chamadas de rede fora do lock
    dados_otx = None
    yara_rule = None
    malware_nome = None
    malware_name_clean = None
    
    if is_ip:
        dados_otx = pesquisar_ip(termo)
        malware_nome = dados_otx.get("malware")
        if malware_nome and malware_nome not in ["IP Suspeito", "Desconhecido"]:
            malware_name_clean = _sanitizar_nome_arquivo(malware_nome)
            malware_path = obter_caminho_nota(malware_name_clean, "Malwares")
            if not malware_path.exists():
                dados_yara = {
                    "termo": termo,
                    "malware": malware_name_clean,
                    "iocs": [termo]
                }
                yara_rule = gerar_regra_yara(dados_yara)
                
    # 2. Define o escopo dos locks granulares
    from contextlib import ExitStack
    lock_names = {termo}
    if is_ip and dados_otx:
        if malware_name_clean:
            lock_names.add(malware_name_clean)
        pulsos_lista = dados_otx.get("pulsos_lista", [])
        for pulso in pulsos_lista:
            campanha_nome = _sanitizar_nome_arquivo(pulso)
            if campanha_nome and campanha_nome != "Desconhecido":
                lock_names.add(campanha_nome)
        lock_names.add("T1071") # Técnica padrão sempre vinculada
        
    sorted_locks = sorted(list(lock_names))
    locks = [obter_lock_entidade(name) for name in sorted_locks]
    
    with ExitStack() as stack:
        for lock in locks:
            stack.enter_context(lock)
            
        try:
            if is_ip:
                ip_path = obter_caminho_nota(termo, "IPs")
                is_new_note = not ip_path.exists()
                
                if is_new_note:
                    _criar_nota_minima(ip_path, termo)
                    
                conteudo = ler_arquivo(ip_path)
                fm = _ler_frontmatter(conteudo)
                
                if not processo or not pid or not risco or not porta:
                    db_det = await _obter_detalhes_do_ip_do_banco_async(termo)
                    proc_val = processo or db_det["processo"]
                    pid_val = pid or db_det["pid"]
                    risco_val = risco or db_det["risco"]
                    porta_val = porta or db_det["porta"]
                    dt_val = db_det["data_hora"]
                else:
                    proc_val = processo
                    pid_val = pid
                    risco_val = risco
                    porta_val = porta
                    dt_val = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
                
                risco_val = normalizar_risco(risco_val)
                
                # 3. Verifica duplicados na seção de Histórico de Detecções antes de atualizar
                nova_linha_historico = f"| {dt_val} | {proc_val} | {pid_val} | {risco_val} | {porta_val} |"
                conteudo_atualizado = _atualizar_secao_markdown(conteudo, "Histórico de Detecções", nova_linha_historico)
                
                if conteudo_atualizado == conteudo:
                    return conteudo
                
                conteudo = conteudo_atualizado
                
                # 4. Atualizar Frontmatter
                if is_new_note:
                    total_deteccoes = 1
                else:
                    linhas_hist = _obter_linhas_secao_texto(conteudo, "Histórico de Detecções")
                    count = 0
                    for l in linhas_hist:
                        if "|" in l and not any(x in l for x in ["Data/Hora", "---"]):
                            count += 1
                    total_deteccoes = count
                    
                risco_maximo = fm.get("risco_maximo", "BAIXO")
                risco_maximo = atualizar_risco_maximo(risco_maximo, risco_val)
                
                primeira_deteccao = fm.get("primeira_deteccao", "")
                if not primeira_deteccao or primeira_deteccao == "N/A":
                    primeira_deteccao = dt_val
                    
                paises = fm.get("paises", [])
                if not isinstance(paises, list):
                    paises = []
                
                updates_fm = {
                    "ultima_deteccao": dt_val,
                    "total_deteccoes": total_deteccoes,
                    "risco_maximo": risco_maximo,
                    "primeira_deteccao": primeira_deteccao
                }
                
                if is_new_note:
                    # dados_otx já foi consultado fora do lock
                    pais_otx = dados_otx.get("origem", "Desconhecido")
                    if pais_otx and pais_otx != "Desconhecido" and pais_otx not in paises:
                        paises.append(pais_otx)
                    updates_fm["paises"] = paises
                else:
                    if not paises or paises == ["Desconhecido"]:
                        # dados_otx já foi consultado fora do lock
                        pais_otx = dados_otx.get("origem", "Desconhecido")
                        if pais_otx and pais_otx != "Desconhecido":
                            paises = [pais_otx]
                        updates_fm["paises"] = paises
                
                conteudo = _atualizar_frontmatter(conteudo, updates_fm)
                
                # 6. Atualizar Seção Resumo
                pais_nome = paises[0] if paises else "Desconhecido"
                novo_corpo_resumo = f"""- **País:** {pais_nome}
- **Total de Detecções:** {total_deteccoes}
- **Primeira Detecção:** {primeira_deteccao}
- **Última Detecção:** {dt_val}
- **Risco Máximo Observado:** {risco_maximo}"""
                conteudo = _substituir_corpo_secao(conteudo, "Resumo", novo_corpo_resumo)
                
                # 7. Atualizar Contramedidas Aplicadas
                if risco_val in ["ALTO", "CRÍTICO"]:
                    nova_contramedida = f"- ✅ {dt_val} — IP bloqueado no Windows Firewall via netsh"
                    conteudo = _atualizar_secao_markdown(conteudo, "Contramedidas Aplicadas", nova_contramedida)
                    
                escrever_arquivo(ip_path, conteudo)
                global STATS
                if not is_new_note:
                    STATS["notas_atualizadas"] += 1
                
                # Grafo de Conhecimento Bidirecional
                if malware_nome and malware_nome not in ["IP Suspeito", "Desconhecido"]:
                    malware_path = obter_caminho_nota(malware_name_clean, "Malwares")
                    
                    if not malware_path.exists():
                        _criar_nota_minima(malware_path, malware_name_clean)
                        # Usa a regra gerada fora do lock
                        rule_to_write = yara_rule
                        if not rule_to_write:
                            dados_yara = {
                                "termo": termo,
                                "malware": malware_name_clean,
                                "iocs": [termo]
                            }
                            rule_to_write = gerar_regra_yara(dados_yara)
                            
                        conteudo_malware = ler_arquivo(malware_path)
                        conteudo_malware = _substituir_corpo_secao(conteudo_malware, "Regra YARA (gerada por IA)", f"```yara\n{rule_to_write}\n```")
                        
                        tipo_malware = dados_otx.get("tipo", "Trojan")
                        classif_corpo = f"""- **Tipo:** {tipo_malware}
- **Família:** {malware_name_clean}
- **Nível de Ameaça:** {risco_maximo}"""
                        conteudo_malware = _substituir_corpo_secao(conteudo_malware, "Classificação", classif_corpo)
                        
                        ref_corpo = f"""- MITRE ATT&CK — {malware_name_clean} ( https://attack.mitre.org/ )
- OTX AlienVault ( https://otx.alienvault.com/ )"""
                        conteudo_malware = _substituir_corpo_secao(conteudo_malware, "Referências", ref_corpo)
                        
                        escrever_arquivo(malware_path, conteudo_malware)
                        
                    contexto_link_mw = (
                        f"— {dados_otx.get('pulsos', 0)} ocorrências OTX",
                        f"— detectado em {dt_val[:10]}, via {proc_val}"
                    )
                    _adicionar_link_bidirecional(
                        ip_path, 
                        malware_path, 
                        "Malwares Associados", 
                        "IPs Conhecidos", 
                        contexto_link_mw
                    )
                    
                ttp_path = obter_caminho_nota("T1071", "TTPs")
                contexto_link_ttp = (
                    "— Application Layer Protocol",
                    f"— {dt_val[:10]}"
                )
                _adicionar_link_bidirecional(
                    ip_path,
                    ttp_path,
                    "TTPs (MITRE ATT&CK)",
                    "IPs Detectados Usando Esta Técnica",
                    contexto_link_ttp
                )
                
                if malware_nome and malware_nome not in ["IP Suspeito", "Desconhecido"]:
                    malware_name_clean = _sanitizar_nome_arquivo(malware_nome)
                    malware_path = obter_caminho_nota(malware_name_clean, "Malwares")
                    _adicionar_link_bidirecional(
                        malware_path,
                        ttp_path,
                        "TTPs Utilizadas",
                        "Malwares que Usam Esta Técnica",
                        ("— Application Layer Protocol", "")
                    )
                    
                pulsos_lista = dados_otx.get("pulsos_lista", [])
                for pulso in pulsos_lista:
                    campanha_nome = _sanitizar_nome_arquivo(pulso)
                    
                    if campanha_nome and campanha_nome != "Desconhecido":
                        campanha_path = obter_caminho_nota(campanha_nome, "Campanhas")
                        
                        contexto_camp = (
                            f"— [Ver no OTX](https://otx.alienvault.com/indicator/ip/{termo})",
                            ""
                        )
                        _adicionar_link_bidirecional(
                            campanha_path,
                            ip_path,
                            "IPs Relacionados",
                            "Pulsos OTX",
                            contexto_camp
                        )
                        
                        if malware_nome and malware_nome not in ["IP Suspeito", "Desconhecido"]:
                            malware_name_clean = _sanitizar_nome_arquivo(malware_nome)
                            malware_path = obter_caminho_nota(malware_name_clean, "Malwares")
                            _adicionar_link_bidirecional(
                                malware_path,
                                campanha_path,
                                "Campanhas Conhecidas",
                                "Malwares Utilizados",
                                ""
                            )
                
                conteudo_final = ler_arquivo(ip_path)
                sumario = obter_sumario()
                print(f"[TI] Ciclo de análise de IP concluído: {sumario['notas_criadas']} notas criadas, {sumario['notas_atualizadas']} notas updates, {sumario['links_adicionados']} links adicionados.")
                
                return conteudo_final
                
            else:
                is_tech = re.match(r'^T\d{4}(?:\.\d{3})?$', termo)
                if is_tech:
                    caminho = obter_caminho_nota(termo, "TTPs")
                    if not caminho.exists():
                        _criar_nota_minima(caminho, termo)
                    return ler_arquivo(caminho)
                else:
                    caminho = obter_caminho_nota(termo, "Malwares")
                    if not caminho.exists():
                        _criar_nota_minima(caminho, termo)
                    return ler_arquivo(caminho)
                    
        except Exception as e:
            print(f"❌ Erro em consultar_base_local para {termo}: {e}")
            raise
