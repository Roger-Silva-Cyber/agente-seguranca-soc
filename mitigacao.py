import os
import subprocess
import shutil
import datetime
import psutil

QUARENTENA_PATH = "/home/vboxuser/agente-seguranca/quarentena"

# Mapeamento de comportamentos para técnicas MITRE
MITRE_MAP = {
    'executavel_tmp': {
        'id': 'T1059',
        'nome': 'Command and Scripting Interpreter',
        'descricao': 'Atacantes executam scripts maliciosos em diretórios temporários para evitar detecção.',
        'malwares': 'Emotet, TrickBot, Cobalt Strike',
        'mitigacao': 'Restringir execução em /tmp e /dev/shm. Monitorar processos filhos de shells.'
    },
    'processo_root_suspeito': {
        'id': 'T1068',
        'nome': 'Exploitation for Privilege Escalation',
        'descricao': 'Processo não autorizado rodando como root pode indicar escalação de privilégios.',
        'malwares': 'Dirty COW, PwnKit, diversos rootkits',
        'mitigacao': 'Revisar permissões de processos. Aplicar patches de segurança do kernel.'
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
        'malwares': 'Rootkits, backdoors persistentes',
        'mitigacao': 'Comparar com backup limpo. Reinstalar pacote afetado via apt.'
    }
}

def identificar_tecnica(alerta):
    alerta_lower = alerta.lower()
    if 'tmp' in alerta_lower or 'executável em local' in alerta_lower:
        return MITRE_MAP['executavel_tmp']
    elif 'root' in alerta_lower and 'suspeito' in alerta_lower:
        return MITRE_MAP['processo_root_suspeito']
    elif 'token' in alerta_lower or 'sensível' in alerta_lower:
        return MITRE_MAP['acesso_token']
    elif 'exfiltração' in alerta_lower or 'exfiltracao' in alerta_lower:
        return MITRE_MAP['exfiltracao']
    elif 'ip malicioso' in alerta_lower:
        return MITRE_MAP['ip_malicioso']
    elif 'sistema alterado' in alerta_lower:
        return MITRE_MAP['arquivo_sistema']
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
    if not os.path.exists(QUARENTENA_PATH):
        os.makedirs(QUARENTENA_PATH)

def mover_para_quarentena(caminho_arquivo):
    try:
        criar_quarentena()
        nome = os.path.basename(caminho_arquivo)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        destino = os.path.join(QUARENTENA_PATH, f"{timestamp}_{nome}")
        shutil.move(caminho_arquivo, destino)
        return f"✅ Arquivo movido para quarentena: {destino}"
    except Exception as e:
        return f"❌ Erro ao mover para quarentena: {e}"

def bloquear_ip(ip):
    try:
        subprocess.run(
            ['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'],
            capture_output=True, timeout=5
        )
        subprocess.run(
            ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
            capture_output=True, timeout=5
        )
        return f"✅ IP bloqueado no firewall: {ip}"
    except Exception as e:
        return f"❌ Erro ao bloquear IP: {e}"

def matar_processo(pid):
    try:
        proc = psutil.Process(pid)
        nome = proc.name()
        proc.kill()
        return f"✅ Processo encerrado: {nome} (PID {pid})"
    except Exception as e:
        return f"❌ Erro ao encerrar processo: {e}"

def agir_automaticamente(alertas, risco):
    acoes = []

    if risco not in ['ALTO', 'CRÍTICO']:
        return acoes

    for alerta in alertas:
        alerta_lower = alerta.lower()

        # Bloquear IP malicioso automaticamente
        if 'ip malicioso' in alerta_lower:
            import re
            ips = re.findall(r'\d+\.\d+\.\d+\.\d+', alerta)
            for ip in ips:
                resultado = bloquear_ip(ip)
                acoes.append(resultado)

        # Mover executável suspeito em /tmp para quarentena
        if 'executável em local suspeito' in alerta_lower:
            import re
            caminhos = re.findall(r'/[^\s]+', alerta)
            for caminho in caminhos:
                if os.path.exists(caminho):
                    resultado = mover_para_quarentena(caminho)
                    acoes.append(resultado)

        # Matar processo rodando de local suspeito
        if 'processo' in alerta_lower and 'suspeito' in alerta_lower and 'pid' in alerta_lower:
            import re
            pids = re.findall(r'pid\s+(\d+)', alerta_lower)
            for pid in pids:
                resultado = matar_processo(int(pid))
                acoes.append(resultado)

    return acoes
