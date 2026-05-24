import os
import time
import psutil

ARQUIVOS_SENSIVEIS = [
    os.path.expanduser("~/.config/discord/Local Storage/leveldb"),
    os.path.expanduser("~/.config/google-chrome/Default/Cookies"),
    os.path.expanduser("~/.config/google-chrome/Default/Login Data"),
    os.path.expanduser("~/.mozilla/firefox"),
    os.path.expanduser("~/.config/BraveSoftware/Brave-Browser/Default/Cookies"),
    os.path.expanduser("~/.ssh"),
    os.path.expanduser("~/.gitconfig"),
    os.path.expanduser("~/.git-credentials"),
]

PROCESSOS_LEGITIMOS = [
    'chrome', 'chromium', 'firefox', 'brave',
    'discord', 'code', 'ssh', 'git'
]

acesso_recente = {}

def verificar_acesso_tokens():
    alertas = []
    processos_ativos = {}
    for proc in psutil.process_iter(['pid', 'name', 'open_files']):
        try:
            for arquivo in proc.open_files():
                processos_ativos[arquivo.path] = {
                    'pid': proc.pid,
                    'nome': proc.name()
                }
        except:
            pass
    for caminho_sensivel in ARQUIVOS_SENSIVEIS:
        if not os.path.exists(caminho_sensivel):
            continue
        if os.path.isdir(caminho_sensivel):
            for root, dirs, files in os.walk(caminho_sensivel):
                for f in files:
                    _checar_acesso(os.path.join(root, f), processos_ativos, alertas)
        else:
            _checar_acesso(caminho_sensivel, processos_ativos, alertas)
    return alertas

def _checar_acesso(caminho, processos_ativos, alertas):
    try:
        stat = os.stat(caminho)
        ultimo_acesso = stat.st_atime
        agora = time.time()
        if agora - ultimo_acesso < 30:
            if caminho not in acesso_recente or acesso_recente[caminho] != ultimo_acesso:
                acesso_recente[caminho] = ultimo_acesso
                processo = processos_ativos.get(caminho, None)
                if processo:
                    nome = processo['nome'].lower()
                    eh_legitimo = any(leg in nome for leg in PROCESSOS_LEGITIMOS)
                    if not eh_legitimo:
                        alertas.append(
                            f"⛔ CRÍTICO — Processo '{processo['nome']}' "
                            f"(PID {processo['pid']}) acessando arquivo sensível: {caminho}"
                        )
                else:
                    alertas.append(
                        f"⚠️  ACESSO NÃO IDENTIFICADO em arquivo sensível: {caminho}"
                    )
    except:
        pass

def verificar_exfiltracao(alertas_tokens, conexoes_externas):
    alertas_exfil = []
    if alertas_tokens and conexoes_externas:
        ips_suspeitos = [
            c['ip'] for c in conexoes_externas
            if not c['ip'].startswith('192.168.')
            and not c['ip'].startswith('10.')
            and not c['ip'].startswith('127.')
            and not c['ip'].startswith('172.')
        ]
        if ips_suspeitos:
            alertas_exfil.append(
                f"🚨 POSSÍVEL EXFILTRAÇÃO — "
                f"Acesso a tokens + conexão externa para: {ips_suspeitos[:3]}"
            )
    return alertas_exfil
