import os
import subprocess
import shutil
import datetime
import sys
import psutil

import config

# Mapeamento de comportamentos para técnicas MITRE
MITRE_MAP = {
    'executavel_tmp': {
        'id': 'T1059',
        'nome': 'Command and Scripting Interpreter',
        'descricao': 'Atacantes executam scripts maliciosos em diretórios temporários para evitar detecção.',
        'malwares': 'Emotet, TrickBot, Cobalt Strike',
        'mitigacao': 'Restringir execução em diretórios temporários. Monitorar processos filhos de shells.'
    },
    'processo_root_suspeito': {
        'id': 'T1068',
        'nome': 'Exploitation for Privilege Escalation',
        'descricao': 'Processo não autorizado rodando com altos privilégios pode indicar escalação de privilégios.',
        'malwares': 'Dirty COW, PwnKit, UAC Bypass',
        'mitigacao': 'Revisar permissões de processos. Aplicar patches de segurança do kernel/OS.'
    },
    'acesso_token': {
        'id': 'T1539',
        'nome': 'Steal Web Session Cookie',
        'descricao': 'Malware acessa arquivos de sessão para roubar tokens de autenticação sem precisar de senha.',
        'malwares': 'Redline Stealer, Raccoon, Lumma Stealer',
        'mitigacao': 'Revogar sessões ativas. Ativar autenticação por hardware (FIDO2).'
    },
    'exfiltracao': {
        'id': 'T1041',
        'nome': 'Exfiltration Over C2 Channel',
        'descricao': 'Dados sensíveis sendo enviados para servidor externo do atacante.',
        'malwares': 'Agent Tesla, NjRAT, AsyncRAT',
        'mitigacao': 'Bloquear IP externo imediatamente. Revogar todos os tokens de sessão.'
    },
    'ip_malicioso': {
        'id': 'T1071',
        'nome': 'Application Layer Protocol',
        'descricao': 'Comunicação com IP conhecido como malicioso — possível C2 ou botnet.',
        'malwares': 'Mirai, ZLoader, QakBot',
        'mitigacao': 'Bloquear IP no firewall. Verificar processo responsável pela conexão.'
    },
    'arquivo_sistema': {
        'id': 'T1565',
        'nome': 'Data Manipulation',
        'descricao': 'Arquivo crítico do sistema foi modificado inesperadamente.',
        'malwares': 'Rootkits, backdoors persistentes, manipuladores de Hosts',
        'mitigacao': 'Comparar com backup limpo. Reinstalar pacote/sistema afetado.'
    },
    'registro_persistencia': {
        'id': 'T1547.001',
        'nome': 'Registry Run Keys / Startup Folder',
        'descricao': 'Atacantes adicionam programas maliciosos às chaves de inicialização do registro para manter persistência após reinicialização.',
        'malwares': 'Redline, Agent Tesla, WannaCry',
        'mitigacao': 'Restringir escrita nas chaves Run/RunOnce. Usar assinaturas digitais nos arquivos referenciados.'
    }
}

def identificar_tecnica(alerta):
    alerta_str = alerta.get('mensagem', '') if isinstance(alerta, dict) else str(alerta)
    alerta_lower = alerta_str.lower()
    
    tipo = alerta.get('tipo', '') if isinstance(alerta, dict) else ''
    
    if 'tmp' in alerta_lower or 'executável em local' in alerta_lower or tipo == 'executavel_suspeito_tmp' or tipo.startswith('lotl_') or tipo == 'comportamento_anomalo_parent_child':
        return MITRE_MAP['executavel_tmp']
    elif ('root' in alerta_lower and 'suspeito' in alerta_lower) or tipo in ['processo_privilegiado_suspeito', 'processo_root_suspeito']:
        return MITRE_MAP['processo_root_suspeito']
    elif 'token' in alerta_lower or 'sensível' in alerta_lower or tipo in ['acesso_token_suspeito', 'acesso_token_nao_identificado', 'infostealer_copia_massa']:
        return MITRE_MAP['acesso_token']
    elif 'exfiltração' in alerta_lower or 'exfiltracao' in alerta_lower or tipo == 'exfiltracao':
        return MITRE_MAP['exfiltracao']
    elif 'ip malicioso' in alerta_lower or tipo == 'ip_malicioso' or tipo == 'comportamento_anomalo_conexao_lolbin':
        return MITRE_MAP['ip_malicioso']
    elif 'sistema alterado' in alerta_lower or tipo == 'arquivo_sistema_alterado':
        return MITRE_MAP['arquivo_sistema']
    elif 'persistência' in alerta_lower or 'persistencia' in alerta_lower or tipo.startswith('registro_persistência'):
        return MITRE_MAP['registro_persistencia']
    return None

def formatar_contexto_mitre(alertas):
    contexto = []
    tecnicas_vistas = set()
    for alerta in alertas:
        tecnica = identificar_tecnica(alerta)
        if tecnica and tecnica['id'] not in tecnicas_vistas:
            tecnicas_vistas.add(tecnica['id'])
            contexto.append(
                f"\n🎯 MITRE {tecnica['id']} — {tecnica['nome']}\n"
                f"📖 {tecnica['descricao']}\n"
                f"🦠 Usado por: {tecnica['malwares']}\n"
                f"🛡️  Mitigação: {tecnica['mitigacao']}"
            )
    return '\n'.join(contexto) if contexto else None

def criar_quarentena():
    path = config.QUARENTENA_PATH
    if not os.path.exists(path):
        try:
            os.makedirs(path, exist_ok=True)
        except Exception as e:
            print(f"❌ Erro ao criar diretório de quarentena: {e}")

def mover_para_quarentena(caminho_arquivo):
    try:
        criar_quarentena()
        nome = os.path.basename(caminho_arquivo)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        destino = os.path.join(config.QUARENTENA_PATH, f"{timestamp}_{nome}")
        shutil.move(caminho_arquivo, destino)
        return f"✅ Arquivo movido para quarentena: {destino}"
    except Exception as e:
        return f"❌ Erro ao mover para quarentena {caminho_arquivo}: {e}"

def bloquear_ip(ip):
    try:
        if sys.platform.startswith("win32"):
            # 🪟 Windows: netsh advfirewall
            # Adiciona regras de entrada e saída
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule', 
                 f'name=BlockIP_OUT_{ip}', 'dir=out', 'action=block', f'remoteip={ip}'],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule', 
                 f'name=BlockIP_IN_{ip}', 'dir=in', 'action=block', f'remoteip={ip}'],
                capture_output=True, timeout=5
            )
            return f"✅ IP bloqueado no firewall (Windows Firewall/netsh): {ip}"
            
        elif sys.platform.startswith("darwin"):
            # 🍎 macOS: pfctl
            subprocess.run(['sudo', 'pfctl', '-e'], capture_output=True, timeout=5)
            regra = f"block drop out quick to {ip}\nblock drop in quick from {ip}\n"
            p = subprocess.Popen(
                ['sudo', 'pfctl', '-a', 'com.agente.soc', '-f', '-'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            p.communicate(input=regra.encode(), timeout=5)
            return f"✅ IP bloqueado no firewall (macOS pfctl): {ip}"
            
        else:
            # 🐧 Linux: iptables
            subprocess.run(
                ['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True, timeout=5
            )
            return f"✅ IP bloqueado no firewall (Linux iptables): {ip}"
            
    except Exception as e:
        return f"❌ Erro ao bloquear IP {ip}: {e}"

import detector_processos

def validar_processo_3_fatores(proc):
    """
    Valida um processo com base em três fatores simultâneos delegando para o modulo detector_processos.
    """
    return detector_processos.validar_processo_3_fatores(proc)

PIDS_PROTEGIDOS = [0, 1, 2, 3, 4] # PIDs reservados do kernel e init

def matar_processo(pid):
    # Proteção de segurança: impede matar o agente ou processos vitais do init/kernel
    if pid in PIDS_PROTEGIDOS or pid == os.getpid():
        return f"⚠️ Bloqueado: Tentativa de encerrar processo protegido ou do próprio agente (PID {pid})"
        
    try:
        proc = psutil.Process(pid)
        nome = proc.name()
        
        # Proteção adicional contra derrubar processos vitais da interface gráfica ou sistema
        PROCESSOS_SISTEMA_CRITICOS = [
            'csrss.exe', 'smss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 
            'explorer.exe', 'searchhost.exe', 'sihost.exe', 'systemd', 'launchd', 'windowserver'
        ]
        if any(c in nome.lower() for c in PROCESSOS_SISTEMA_CRITICOS):
            # Validação do caminho/legitimidade para processos críticos
            eh_caminho_legitimo = True
            if sys.platform.startswith("win32"):
                exe_lower_path = ""
                try:
                    exe_lower_path = proc.exe().lower()
                except Exception:
                    pass
                
                if nome.lower() == "explorer.exe":
                    eh_caminho_legitimo = (exe_lower_path == "c:\\windows\\explorer.exe" or
                                           exe_lower_path.startswith("c:\\windows\\system32") or 
                                           exe_lower_path.startswith("c:\\windows\\syswow64"))
                elif nome.lower() == "searchhost.exe":
                    eh_caminho_legitimo = "c:\\windows\\systemapps\\microsoft.windows.search_" in exe_lower_path or "systemapps" in exe_lower_path or "windowsapps" in exe_lower_path
                elif nome.lower() == "sihost.exe":
                    eh_caminho_legitimo = (exe_lower_path == "c:\\windows\\system32\\sihost.exe" or
                                           exe_lower_path.startswith("c:\\windows\\system32") or
                                           exe_lower_path.startswith("c:\\windows\\syswow64"))
                else:
                    eh_caminho_legitimo = (exe_lower_path.startswith("c:\\windows\\system32") or 
                                           exe_lower_path.startswith("c:\\windows\\syswow64"))
            else:
                # Unix
                exe_path = ""
                try:
                    exe_path = proc.exe()
                except Exception:
                    pass
                eh_caminho_legitimo = exe_path.startswith('/usr') or exe_path.startswith('/lib') or exe_path.startswith('/sbin') or exe_path.startswith('/bin')
            
            if eh_caminho_legitimo:
                return f"⚠️ Bloqueado: Tentativa de encerrar processo crítico de sistema: {nome} (PID {pid})"
            
        # Checagem de 3 fatores para os processos da whitelist (como discord.exe, chrome.exe)
        status_val, _, _ = validar_processo_3_fatores(proc)
        if status_val == 'valido':
            return f"⚠️ Bloqueado: Tentativa de encerrar processo confiável verificado (3 fatores): {nome} (PID {pid})"
            
        # Coleta os processos filhos recursivamente antes de matar o alvo
        filhos = []
        try:
            filhos = proc.children(recursive=True)
        except Exception:
            pass
            
        # Encerra os filhos primeiro
        for filho in filhos:
            try:
                # Proteção extra para não matar PIDs protegidos nos filhos
                if filho.pid not in PIDS_PROTEGIDOS and filho.pid != os.getpid():
                    filho_nome = filho.name()
                    if not any(c in filho_nome.lower() for c in PROCESSOS_SISTEMA_CRITICOS):
                        filho.kill()
            except Exception:
                pass
                
        proc.kill()
        return f"✅ Processo e descendentes encerrados: {nome} (PID {pid})"
    except Exception as e:
        return f"❌ Erro ao encerrar processo (PID {pid}): {e}"

def agir_automaticamente(alertas, risco):
    acoes = []

    # A mitigação automática só deve ocorrer em riscos altos
    if risco not in ['ALTO', 'CRÍTICO']:
        return acoes

    for alerta in alertas:
        if not isinstance(alerta, dict):
            continue
            
        tipo = alerta.get('tipo', '')
        detalhes = alerta.get('detalhes', {})
        
        # 1. Mitigação de IP Malicioso
        if tipo in ['ip_malicioso', 'ip_suspeito']:
            ip = detalhes.get('ip')
            if ip:
                resultado = bloquear_ip(ip)
                acoes.append(resultado)
                
        # 2. Mitigação de Executável em Local Suspeito (Quarentena)
        elif tipo in ['executavel_suspeito_tmp', 'executavel_tmp']:
            caminho = detalhes.get('caminho')
            if caminho and os.path.exists(caminho):
                resultado = mover_para_quarentena(caminho)
                acoes.append(resultado)
                
        # 3. Mitigação de Processo Suspeito / Acesso de Credenciais
        elif tipo in ['processo_local_suspeito', 'processo_pasta_oculta', 'processo_disfarcado', 'acesso_token_suspeito',
                      'processo_masquerading', 'binario_adulterado', 'validacao_incompleta']:
            pid = detalhes.get('pid')
            if pid:
                resultado = matar_processo(int(pid))
                acoes.append(resultado)

    return acoes
