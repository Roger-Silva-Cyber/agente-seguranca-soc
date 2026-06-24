import psutil
import os
import sys
from pathlib import Path

HOME = Path.home()

# Configurações dinâmicas de diretórios e processos padrão baseadas no OS
if sys.platform.startswith("win32"):
    LOCALAPPDATA = Path(os.getenv("LOCALAPPDATA", str(HOME / "AppData" / "Local")))
    APPDATA = Path(os.getenv("APPDATA", str(HOME / "AppData" / "Roaming")))
    SYSTEMROOT = Path(os.getenv("SystemRoot", "C:\\Windows"))
    
    LOCAIS_SUSPEITOS = [
        str(LOCALAPPDATA / "Temp"),
        str(SYSTEMROOT / "Temp"),
        str(SYSTEMROOT / "System32" / "spool" / "drivers" / "color"),
    ]
    LOCAIS_SUSPEITOS_HOME = [
        str(APPDATA),
        str(LOCALAPPDATA),
    ]
    PROCESSOS_SISTEMA = [
        'system', 'idle', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
        'lsass.exe', 'svchost.exe', 'explorer.exe', 'cmd.exe', 'powershell.exe',
        'taskhostw.exe', 'runtimebroker.exe', 'conhost.exe'
    ]
elif sys.platform.startswith("darwin"):
    LOCAIS_SUSPEITOS = [
        "/tmp",
        "/var/tmp",
        "/private/tmp",
        "/private/var/tmp",
    ]
    LOCAIS_SUSPEITOS_HOME = [
        str(HOME / "Library" / "Caches"),
        str(HOME / "Library" / "Application Support"),
    ]
    PROCESSOS_SISTEMA = [
        'launchd', 'kernel_task', 'syslogd', 'usereventagent', 'windowserver',
        'cfprefsd', 'distnoted', 'finder', 'dock', 'bash', 'sh', 'zsh', 'python3',
        'taskgated', 'loginwindow'
    ]
else:
    # Linux / Outros Unix
    LOCAIS_SUSPEITOS = [
        "/tmp",
        "/dev/shm",
        "/var/tmp",
        "/run/user",
    ]
    LOCAIS_SUSPEITOS_HOME = [
        str(HOME / ".cache"),
        str(HOME / ".local" / "share"),
    ]
    PROCESSOS_SISTEMA = [
        'systemd', 'kworker', 'ksoftirqd', 'migration',
        'rcu_', 'watchdog', 'sshd', 'bash', 'sh',
        'python3', 'gnome', 'xorg', 'dbus', 'networkmanager', 'chronyd'
    ]

import json

def carregar_whitelist():
    caminho_whitelist = Path(__file__).parent / "whitelist.json"
    if caminho_whitelist.exists():
        try:
            with open(caminho_whitelist, "r", encoding="utf-8") as f:
                dados = json.load(f)
                return {
                    "processos": dados.get("processos", []),
                    "caminhos": dados.get("caminhos", [])
                }
        except Exception as e:
            print(f"⚠️ Erro ao ler whitelist.json: {e}")
    return {"processos": [], "caminhos": []}

import hashlib

# Cache em memória: hash_sha256_do_binario -> (assinatura_valida, status_assinatura)
cache_assinaturas = {}

def calcular_hash_arquivo(caminho):
    """
    Calcula de forma rápida e eficiente o hash SHA-256 de um arquivo em disco.
    """
    try:
        h = hashlib.sha256()
        with open(caminho, 'rb') as f:
            while True:
                bloco = f.read(65536)
                if not bloco:
                    break
                h.update(bloco)
        return h.hexdigest()
    except Exception:
        return None

def validar_processo_3_fatores(proc):
    """
    Valida um processo com base em três fatores simultâneos: Nome, Caminho esperado e Assinatura/Integridade nativa.
    Retorna (status_validacao, mensagem_erro, tipo_erro)
    """
    import subprocess
    import shutil
    
    CAMINHOS_ESPERADOS = {
        "discord.exe": ["appdata\\local\\discord"],
        "telegram.exe": [
            "appdata\\roaming\\telegram desktop",
            "windowsapps\\telegramme",          # Windows Store
            "program files\\windowsapps\\telegram"
        ],
        "onedrive.exe": [
            "appdata\\local\\microsoft\\onedrive",
            "program files\\microsoft onedrive"  # Instalação corporativa
        ],
        "apsdaemon.exe": [
            "windowsapps\\appleinc",
            "program files\\common files\\apple"
        ],
        "chrome.exe": ["program files\\google\\chrome"],
        "discord": ["discord", "share/discord"],
        "telegram": ["telegram", "telegram desktop", "bin/telegram-desktop"],
        "telegram-desktop": ["telegram", "telegram desktop", "bin/telegram-desktop"],
        "chrome": ["google/chrome", "google-chrome", "bin/chrome"],
        "onedrive": ["onedrive"],
    }
    
    nome = None
    pid = None
    try:
        pid = proc.pid
        nome = proc.info.get('name') if hasattr(proc, 'info') and proc.info else None
        if not nome:
            nome = proc.name()
    except Exception:
        pass
        
    if not nome:
        return 'nao_alvo', None, None
        
    nome_lower = nome.lower()
    if nome_lower not in CAMINHOS_ESPERADOS:
        return 'nao_alvo', None, None
        
    # Fator 1: Nome ok. Agora verificamos Fator 2: Caminho esperado
    exe_path = None
    try:
        exe_path = proc.info.get('exe') if hasattr(proc, 'info') and proc.info else None
        if not exe_path:
            exe_path = proc.exe()
    except Exception as e:
        return 'incompleto', f"⛔ CRÍTICO — Processo '{nome}' (PID {pid}) com combinação incompleta: falha ao obter o caminho do executável ({e}).", 'validacao_incompleta'
        
    if not exe_path:
        return 'incompleto', f"⛔ CRÍTICO — Processo '{nome}' (PID {pid}) com combinação incompleta: caminho do executável está vazio.", 'validacao_incompleta'
        
    exe_lower = exe_path.lower().replace("/", "\\")
    caminho_valido = any(expected in exe_lower for expected in CAMINHOS_ESPERADOS[nome_lower])
    
    # Fator 3: Assinatura digital / Integridade nativa (com caching baseado no hash do binário)
    assinatura_valida = False
    status_assinatura = "DESCONHECIDO"
    
    # Calcula o hash para ver se está em cache
    hash_binario = calcular_hash_arquivo(exe_path)
    
    if hash_binario and hash_binario in cache_assinaturas:
        # Recupera do cache
        assinatura_valida, status_assinatura = cache_assinaturas[hash_binario]
    else:
        try:
            if sys.platform.startswith("win32"):
                # Windows: Get-AuthenticodeSignature
                # Removida a interpolação direta de 'exe_path' para evitar injeção de comandos (Command Injection)
                # caso o nome do arquivo contenha caracteres especiais como aspas ou ponto e vírgula.
                # O caminho é passado com segurança por meio de variável de ambiente.
                script = "(Get-AuthenticodeSignature -LiteralPath $env:TARGET_EXE).Status"
                env = os.environ.copy()
                env["TARGET_EXE"] = exe_path
                res = subprocess.run([
                    "powershell", "-NoProfile", "-NonInteractive", "-Command", script
                ], capture_output=True, text=True, timeout=10, env=env)
                status_assinatura = res.stdout.strip()
                if status_assinatura == "Valid":
                    assinatura_valida = True
            elif sys.platform.startswith("darwin"):
                # macOS: codesign --verify --strict
                res = subprocess.run([
                    "codesign", "--verify", "--strict", exe_path
                ], capture_output=True, text=True, timeout=10)
                if res.returncode == 0:
                    assinatura_valida = True
                    status_assinatura = "Valid"
                else:
                    status_assinatura = f"Invalid (codesign exit code {res.returncode})"
            else:
                # Linux: dpkg -S ou rpm -qf
                dpkg_exists = shutil.which("dpkg")
                rpm_exists = shutil.which("rpm")
                
                if dpkg_exists:
                    res = subprocess.run([
                        "dpkg", "-S", exe_path
                    ], capture_output=True, text=True, timeout=10)
                    if res.returncode == 0:
                        assinatura_valida = True
                        status_assinatura = "Valid"
                    else:
                        status_assinatura = f"Invalid (dpkg exit code {res.returncode})"
                elif rpm_exists:
                    res = subprocess.run([
                        "rpm", "-qf", exe_path
                    ], capture_output=True, text=True, timeout=10)
                    if res.returncode == 0:
                        assinatura_valida = True
                        status_assinatura = "Valid"
                    else:
                        status_assinatura = f"Invalid (rpm exit code {res.returncode})"
                else:
                    status_assinatura = "DESCONHECIDO"
            
            # Salva o resultado no cache se conseguirmos calcular o hash
            if hash_binario:
                cache_assinaturas[hash_binario] = (assinatura_valida, status_assinatura)
                    
        except Exception as e:
            return 'incompleto', f"⛔ CRÍTICO — Processo '{nome}' (PID {pid}) com combinação incompleta: falha na execução da validação nativa de assinatura ({e}).", 'validacao_incompleta'
        
    # Regras de decisão:
    # 1. Nome + Caminho + Assinatura válidos → processo confiável
    if caminho_valido and assinatura_valida:
        return 'valido', None, None
        
    # 2. Nome ok, mas caminho errado → Process Masquerading detectado
    if not caminho_valido:
        return 'masquerading', f"⛔ CRÍTICO — Processo '{nome}' (PID {pid}) suspeito: Process Masquerading detectado. Caminho esperado: {CAMINHOS_ESPERADOS[nome_lower]}, Caminho atual: {exe_path}", 'processo_masquerading'
        
    # 3. Nome ok, caminho ok, mas assinatura inválida → Binário adulterado detectado
    if caminho_valido and not assinatura_valida:
        if status_assinatura == "DESCONHECIDO":
            return 'adulterado', f"⛔ CRÍTICO — Processo '{nome}' (PID {pid}) suspeito: Integridade não pôde ser verificada (status DESCONHECIDO). Tratado como suspeito.", 'binario_adulterado'
        else:
            return 'adulterado', f"⛔ CRÍTICO — Processo '{nome}' (PID {pid}) suspeito: Binário adulterado detectado. Assinatura inválida (Status: {status_assinatura}).", 'binario_adulterado'

    return 'incompleto', f"⛔ CRÍTICO — Processo '{nome}' (PID {pid}) com combinação incompleta.", 'validacao_incompleta'

def verificar_processos_suspeitos():
    alertas = []
    whitelist = carregar_whitelist()
    wl_processos = [p.lower() for p in whitelist.get("processos", [])]
    wl_caminhos = [c.lower().replace("/", "\\") for c in whitelist.get("caminhos", [])]

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
        try:
            nome = proc.info.get('name', '') or proc.name()
            pid = proc.info.get('pid') or proc.pid

            # Validação baseada em 3 fatores simultâneos
            status_val, msg_val, tipo_val = validar_processo_3_fatores(proc)
            if status_val != 'nao_alvo':
                if status_val == 'valido':
                    # Processo confiável - ignora todas as outras detecções suspeitas para ele
                    continue
                else:
                    # Qualquer outra regra de decisão (masquerading, adulterado, incompleto) gera alerta crítico
                    alertas.append({
                        'tipo': tipo_val,
                        'mensagem': msg_val,
                        'detalhes': {
                            'pid': pid,
                            'nome': nome,
                            'caminho': proc.info.get('exe') or ''
                        }
                    })
                    continue

            exe = proc.info.get('exe')
            usuario = proc.info.get('username', '')

            if not exe:
                continue

            exe_lower = exe.lower()
            exe_normalized = exe_lower.replace("/", "\\")

            # 1. Whitelist inteligente baseada em caminhos legítimos de instalação
            caminhos_confiaveis = ["\\programs\\", "\\program files\\", "\\program files (x86)\\"]
            if any(conf in exe_normalized for conf in caminhos_confiaveis):
                continue

            # 2. Whitelist do usuário via whitelist.json
            if nome.lower() in wl_processos:
                continue
            if any(wl_c in exe_normalized for wl_c in wl_caminhos):
                continue

            # Processo rodando de local suspeito
            for local in LOCAIS_SUSPEITOS:
                if exe.lower().startswith(local.lower()):
                    alertas.append({
                        'tipo': 'processo_local_suspeito',
                        'mensagem': f"⛔ CRÍTICO — Processo '{nome}' (PID {pid}) rodando de local suspeito: {exe}",
                        'detalhes': {'pid': pid, 'nome': nome, 'caminho': exe}
                    })

            # Processo rodando de local suspeito no home (oculto)
            for local in LOCAIS_SUSPEITOS_HOME:
                # Evita falsos positivos para processos legítimos gerais
                eh_legitimo = any(leg.lower() in nome.lower() for leg in ['chrome', 'brave', 'discord', 'firefox', 'teams', 'slack', 'code', 'python'])
                if exe.lower().startswith(local.lower()) and not eh_legitimo:
                    alertas.append({
                        'tipo': 'processo_pasta_oculta',
                        'mensagem': f"⚠️  SUSPEITO — Processo '{nome}' (PID {pid}) rodando de pasta oculta: {exe}",
                        'detalhes': {'pid': pid, 'nome': nome, 'caminho': exe}
                    })

            # Processo rodando com altos privilégios (root/Administrator) fora do padrão do sistema
            is_root = False
            if sys.platform.startswith("win32"):
                is_root = (usuario == 'SYSTEM' or (usuario and 'Administrators' in usuario) or (usuario and 'Administrador' in usuario))
            else:
                is_root = (usuario == 'root')
                
            if is_root:
                eh_sistema = any(s.lower() in nome.lower() for s in PROCESSOS_SISTEMA)
                eh_caminho_legitimo = False
                
                if sys.platform.startswith("win32"):
                    # Caminhos padrão do Windows para executáveis legítimos
                    eh_caminho_legitimo = exe.lower().startswith("c:\\windows") or exe.lower().startswith("c:\\program files")
                else:
                    # Caminhos padrão Unix para executáveis legítimos
                    eh_caminho_legitimo = exe.startswith('/usr') or exe.startswith('/lib') or exe.startswith('/sbin') or exe.startswith('/bin')
                    
                if not eh_sistema and not eh_caminho_legitimo:
                    alertas.append({
                        'tipo': 'processo_privilegiado_suspeito',
                        'mensagem': f"⚠️  SUSPEITO — Processo '{nome}' (PID {pid}) rodando com privilégios altos fora do padrão: {exe}",
                        'detalhes': {'pid': pid, 'nome': nome, 'caminho': exe}
                    })

            # Nome de processo disfarçado de sistema mas em local incorreto
            nomes_sistema = ['systemd', 'sshd', 'cron', 'init', 'svchost', 'explorer', 'lsass', 'searchhost', 'sihost']
            for nome_sys in nomes_sistema:
                if nome_sys.lower() in nome.lower():
                    eh_caminho_legitimo = False
                    
                    # Correção 2 — SearchHost.exe como falso positivo
                    EXCECOES_CAMINHO_SISTEMA = {
                        "searchhost.exe": ["systemapps", "windowsapps"],
                        "sihost.exe": ["windows\\system32"],
                    }
                    nome_key = nome.lower()
                    if nome_key in EXCECOES_CAMINHO_SISTEMA:
                        if any(val in exe.lower() for val in EXCECOES_CAMINHO_SISTEMA[nome_key]):
                            eh_caminho_legitimo = True
                            
                    if not eh_caminho_legitimo:
                        if sys.platform.startswith("win32"):
                            exe_lower_path = exe.lower()
                            # explorer.exe legítimo roda em c:\windows\explorer.exe ou em system32/syswow64
                            if nome.lower() == "explorer.exe":
                                eh_caminho_legitimo = (exe_lower_path == "c:\\windows\\explorer.exe" or
                                                       exe_lower_path.startswith("c:\\windows\\system32") or 
                                                       exe_lower_path.startswith("c:\\windows\\syswow64"))
                            # SearchHost.exe legítimo roda em Windows\SystemApps\Microsoft.Windows.Search...
                            elif nome.lower() == "searchhost.exe":
                                eh_caminho_legitimo = "c:\\windows\\systemapps\\microsoft.windows.search_" in exe_lower_path
                            # sihost.exe legítimo roda em system32
                            elif nome.lower() == "sihost.exe":
                                eh_caminho_legitimo = (exe_lower_path == "c:\\windows\\system32\\sihost.exe" or
                                                       exe_lower_path.startswith("c:\\windows\\system32") or
                                                       exe_lower_path.startswith("c:\\windows\\syswow64"))
                            else:
                                eh_caminho_legitimo = (exe_lower_path.startswith("c:\\windows\\system32") or 
                                                       exe_lower_path.startswith("c:\\windows\\syswow64"))
                        else:
                            eh_caminho_legitimo = exe.startswith('/usr') or exe.startswith('/lib') or exe.startswith('/sbin') or exe.startswith('/bin')
                            
                    if not eh_caminho_legitimo:
                        alertas.append({
                            'tipo': 'processo_disfarcado',
                            'mensagem': f"⛔ CRÍTICO — Processo '{nome}' se disfarça de processo do sistema mas roda de: {exe}",
                            'detalhes': {'pid': pid, 'nome': nome, 'caminho': exe}
                        })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return alertas
