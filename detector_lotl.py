import psutil
import re
import base64
import sys
from pathlib import Path

# Processos Office, leitores PDF, e servidores web comuns
PROCESSO_GATILHO_PAI = [
    'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 
    'acrord32.exe', 'acrobat.exe', 'w3wp.exe', 'tomcat.exe',
    'winword', 'excel', 'powerpnt', 'outlook', 'acrord32', 'acrobat'
]

# Interpretadores e proxies de sistema usados como filhos anômalos
PROCESSO_FILHO_SUSPEITO = [
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 
    'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe', 'bash', 'sh', 'zsh'
]

# LOLBins que não devem fazer conexões de rede ativas externas
LOLBINS_REDE_SUSPEITA = [
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wmic.exe', 'mshta.exe', 
    'regsvr32.exe', 'rundll32.exe', 'notepad.exe', 'calc.exe', 'certutil.exe'
]

def _contem_base64_suspeito(cmdline_str):
    """
    Identifica strings em Base64 na linha de comando e tenta decodificá-las 
    para procurar por termos comuns de execução de scripts de ataque.
    """
    padroes = re.findall(r'\b[A-Za-z0-9+/]{20,}\b={0,2}', cmdline_str)
    for p in padroes:
        try:
            # Tenta decodificar como UTF-16-LE (padrão do PowerShell -EncodedCommand)
            decodificado_u16 = base64.b64decode(p).decode('utf-16-le', errors='ignore')
            termos = ['invoke-', 'download', 'bypass', 'hidden', 'iex', 'exec', 'http', 'new-object']
            if any(t in decodificado_u16.lower() for t in termos):
                return True, decodificado_u16[:100]
            
            # Tenta decodificar como UTF-8
            decodificado_utf8 = base64.b64decode(p).decode('utf-8', errors='ignore')
            if any(t in decodificado_utf8.lower() for t in termos):
                return True, decodificado_utf8[:100]
        except Exception:
            pass
    return False, None

def verificar_lotl():
    """
    Varre os processos ativos e detecta abuso de LOLBins, 
    linhas de comando suspeitas, parent-child anômalos e conexões suspeitas.
    """
    alertas = []
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid']):
        try:
            pid = proc.info.get('pid')
            nome = proc.info.get('name') or ''
            exe = proc.info.get('exe') or ''
            ppid = proc.info.get('ppid')
            cmdline_list = proc.info.get('cmdline') or []
            cmdline_str = ' '.join(cmdline_list)
            
            nome_lower = nome.lower()
            cmdline_lower = cmdline_str.lower()
            
            # --- Regra 1: PowerShell com argumentos encodados ou ofuscados ---
            if 'powershell' in nome_lower or 'pwsh' in nome_lower:
                # Verifica se há flags de ofuscação/Base64
                flags_enc = ['-encodedcommand', '-enc', '-e ']
                if any(f in cmdline_lower for f in flags_enc):
                    suspeito, decodificado = _contem_base64_suspeito(cmdline_str)
                    if suspeito:
                        alertas.append({
                            'tipo': 'lotl_powershell_encodado',
                            'mensagem': f"🚨 LOTL DETECTADO — PowerShell com comando encodado em Base64 suspeito (PID: {pid}). Decodificado: {decodificado}",
                            'detalhes': {'pid': pid, 'nome': nome, 'caminho': exe, 'cmdline': cmdline_str}
                        })
            
            # --- Regra 2: Certutil baixando ou decodificando arquivos ---
            elif 'certutil' in nome_lower:
                flags_cert = ['-urlcache', '-split', '-decode', '-ping']
                tem_url = 'http://' in cmdline_lower or 'https://' in cmdline_lower
                if any(f in cmdline_lower for f in flags_cert) or tem_url:
                    alertas.append({
                        'tipo': 'lotl_certutil_suspeito',
                        'mensagem': f"🚨 LOTL DETECTADO — Certutil executando download ou decodificação (PID: {pid}). Comando: {cmdline_str}",
                        'detalhes': {'pid': pid, 'nome': nome, 'caminho': exe, 'cmdline': cmdline_str}
                    })
                    
            # --- Regra 3: WMIC criando processos ou acessando nós remotos ---
            elif 'wmic' in nome_lower:
                if 'process' in cmdline_lower and 'create' in cmdline_lower:
                    alertas.append({
                        'tipo': 'lotl_wmic_criacao_processo',
                        'mensagem': f"🚨 LOTL DETECTADO — WMIC criando processo remotamente/anômalo (PID: {pid}). Comando: {cmdline_str}",
                        'detalhes': {'pid': pid, 'nome': nome, 'caminho': exe, 'cmdline': cmdline_str}
                    })
                elif '/node:' in cmdline_lower:
                    alertas.append({
                        'tipo': 'lotl_wmic_remoto',
                        'mensagem': f"🚨 LOTL DETECTADO — WMIC conectando a nó remoto (PID: {pid}). Comando: {cmdline_str}",
                        'detalhes': {'pid': pid, 'nome': nome, 'caminho': exe, 'cmdline': cmdline_str}
                    })
            
            # --- Regra 4: Proxies de Execução (mshta, regsvr32, rundll32) rodando da web ---
            elif any(proxy in nome_lower for proxy in ['mshta', 'regsvr32', 'rundll32']):
                tem_web = 'http://' in cmdline_lower or 'https://' in cmdline_lower
                tem_sct = '.sct' in cmdline_lower or '.xml' in cmdline_lower
                if tem_web or tem_sct:
                    alertas.append({
                        'tipo': 'lotl_proxy_execucao_web',
                        'mensagem': f"🚨 LOTL DETECTADO — Proxy de Execução '{nome}' carregando script remoto/SCT (PID: {pid}). Comando: {cmdline_str}",
                        'detalhes': {'pid': pid, 'nome': nome, 'caminho': exe, 'cmdline': cmdline_str}
                    })
            
            # --- Regra 5: Relação Parent-Child Anômala ---
            if ppid:
                try:
                    proc_pai = psutil.Process(ppid)
                    nome_pai = proc_pai.name().lower()
                    
                    eh_pai_anomalo = any(p in nome_pai for p in PROCESSO_GATILHO_PAI)
                    eh_filho_suspeito = any(f in nome_lower for f in PROCESSO_FILHO_SUSPEITO)
                    
                    if eh_pai_anomalo and eh_filho_suspeito:
                        # Exceção específica: whitelistar IDEs ou shells do próprio sistema se disparados do explorer
                        alertas.append({
                            'tipo': 'comportamento_anomalo_parent_child',
                            'mensagem': f"🚨 COMPORTAMENTO ANÔMALO — Processo pai '{proc_pai.name()}' gerou interpretador filho '{nome}' (PID: {pid}). Comando: {cmdline_str}",
                            'detalhes': {'pid': pid, 'nome': nome, 'caminho': exe, 'cmdline': cmdline_str, 'ppid': ppid, 'nome_pai': proc_pai.name()}
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # --- Regra 6: LOLBins gerando conexões de rede externas ---
            if any(bin_rede in nome_lower for bin_rede in LOLBINS_REDE_SUSPEITA):
                try:
                    conexoes = proc.connections()
                    for c in conexoes:
                        if c.status == 'ESTABLISHED' and c.raddr:
                            ip = c.raddr.ip
                            # Ignora conexões locais (loopback e ranges privados de rede)
                            eh_local = (
                                ip.startswith('127.') or 
                                ip.startswith('192.168.') or 
                                ip.startswith('10.') or 
                                ip.startswith('172.16.') or # Simplificado para classe B
                                ip.startswith('172.17.') or 
                                ip.startswith('172.18.') or 
                                ip.startswith('172.19.') or 
                                ip.startswith('172.20.') or 
                                ip.startswith('172.31.') or 
                                ip == '::1'
                            )
                            if not eh_local:
                                alertas.append({
                                    'tipo': 'comportamento_anomalo_conexao_lolbin',
                                    'mensagem': f"🚨 COMPORTAMENTO ANÔMALO — LOLBin '{nome}' estabeleceu conexão de rede externa com {ip} (PID: {pid})",
                                    'detalhes': {'pid': pid, 'nome': nome, 'caminho': exe, 'ip': ip, 'porta': c.raddr.port}
                                })
                                break # Apenas um alerta por processo já é suficiente
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            # Captura de falhas gerais para manter estabilidade
            print(f"⚠️ Erro ao examinar processo no detector_lotl: {e}")
            
    return alertas
