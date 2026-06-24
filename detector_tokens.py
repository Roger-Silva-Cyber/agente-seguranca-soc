import os
import sys
import time
import psutil
import threading
import subprocess
import fnmatch
from pathlib import Path
from detector_ameacas import eh_conexao_externa

WHITELIST_ACESSOS = {
    # Discord
    "*/users/*/appdata/local/discord/app-*/discord.exe": [
        "*/discord/local storage/leveldb*",
        "*/cookies*",
        "*/login data*"
    ],
    "*/users/*/appdata/local/discord/discord.exe": [
        "*/discord/local storage/leveldb*",
        "*/cookies*",
        "*/login data*"
    ],
    # Git
    "*/program files/git/cmd/git.exe": [
        "*/.gitconfig",
        "*/.git-credentials"
    ],
    "*/program files/git/bin/git.exe": [
        "*/.gitconfig",
        "*/.git-credentials"
    ],
    # Chrome
    "*/program files/google/chrome/application/chrome.exe": [
        "*/google/chrome/user data/default/cookies*",
        "*/google/chrome/user data/default/login data*"
    ],
    # Edge
    "*/program files (x86)/microsoft/edge/application/msedge.exe": [
        "*/cookies*",
        "*/login data*"
    ],
    # SSH legítimo no Windows/Linux
    "*/ssh.exe": [
        "*/.ssh*"
    ],
    "/usr/bin/ssh": [
        "*/.ssh*"
    ],
    "/usr/bin/git": [
        "*/.gitconfig",
        "*/.git-credentials"
    ],
    # Discord no Linux
    "/usr/share/discord/discord": [
        "*/discord/local storage/leveldb*"
    ],
}

def eh_acesso_legitimo(caminho_processo: str, caminho_arquivo: str) -> bool:
    if not caminho_processo or not caminho_arquivo:
        return False
        
    proc_norm = str(caminho_processo).lower().replace("\\", "/")
    arq_norm = str(caminho_arquivo).lower().replace("\\", "/")
    
    for padrão_proc, padrões_arq in WHITELIST_ACESSOS.items():
        if fnmatch.fnmatch(proc_norm, padrão_proc):
            for padrão_arq in padrões_arq:
                if fnmatch.fnmatch(arq_norm, padrão_arq):
                    return True
    return False


_supressoes_logadas_no_ciclo = set()

def _logar_supressao(processo: str, caminho: str):
    chave = f"{processo.lower()}:{caminho.lower()}"
    if chave not in _supressoes_logadas_no_ciclo:
        print(f"[ACESSO LEGÍTIMO SUPRIMIDO] {processo} → {caminho}")
        _supressoes_logadas_no_ciclo.add(chave)

def reset_supressoes_ciclo():
    _supressoes_logadas_no_ciclo.clear()


PROCESSOS_COM_LEVELDB_PROPRIO = [
    "msedgewebview2.exe",
    "overwolfbrowser.exe",
    "nvidia overlay.exe",
    "msedge.exe",
    "whatsapp.exe",
]

def eh_acesso_ao_proprio_leveldb(nome_processo: str, caminho_arquivo: str) -> bool:
    """
    Retorna True se o processo está acessando seu próprio LevelDB interno,
    não o LevelDB de tokens do Discord ou outro alvo sensível real.
    """
    if not nome_processo:
        return False
    nome_lower = nome_processo.lower()
    if nome_lower not in PROCESSOS_COM_LEVELDB_PROPRIO:
        return False
    # Verifica se o caminho do LevelDB é do Discord especificamente
    caminho_lower = caminho_arquivo.lower().replace("\\", "/")
    # Se não é o LevelDB do Discord, é o LevelDB próprio do processo
    return "appdata/roaming/discord" not in caminho_lower


ARQUIVOS_IGNORADOS_SEM_PROCESSO = [
    ".gitconfig",
    ".git-credentials",
    "discord/local storage/leveldb",
]

def eh_arquivo_ignorado_sem_processo(caminho: str) -> bool:
    """
    Retorna True se o arquivo deve ser ignorado quando o processo
    acessante não puder ser identificado pelo sistema operacional.
    """
    caminho_lower = caminho.lower().replace("\\", "/")
    for padrao in ARQUIVOS_IGNORADOS_SEM_PROCESSO:
        if padrao in caminho_lower:
            return True
    return False


# Configuração dinâmica de caminhos de arquivos sensíveis por OS
HOME = Path.home()
ARQUIVOS_SENSIVEIS = []

if sys.platform.startswith("win32"):
    APPDATA = Path(os.getenv("APPDATA", str(HOME / "AppData" / "Roaming")))
    LOCALAPPDATA = Path(os.getenv("LOCALAPPDATA", str(HOME / "AppData" / "Local")))
    ARQUIVOS_SENSIVEIS = [
        # Tokens de sessão — alvos reais de infostealer
        str(LOCALAPPDATA / "Google" / "Chrome" / "User Data" / "Default" / "Cookies"),
        str(LOCALAPPDATA / "Google" / "Chrome" / "User Data" / "Default" / "Login Data"),
        str(APPDATA / "Mozilla" / "Firefox" / "Profiles"),
        str(LOCALAPPDATA / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Cookies"),
        # SSH e credenciais Git — alvos reais
        str(HOME / ".ssh"),
        str(HOME / ".gitconfig"),
        str(HOME / ".git-credentials"),
        # Discord — apenas o LevelDB específico do Discord, não qualquer LevelDB
        str(APPDATA / "discord" / "Local Storage" / "leveldb"),
    ]
elif sys.platform.startswith("darwin"):
    SUPPORT = HOME / "Library" / "Application Support"
    ARQUIVOS_SENSIVEIS = [
        str(SUPPORT / "discord" / "Local Storage" / "leveldb"),
        str(SUPPORT / "Google" / "Chrome" / "Default" / "Cookies"),
        str(SUPPORT / "Google" / "Chrome" / "Default" / "Login Data"),
        str(HOME / "Library" / "Application Support" / "Firefox" / "Profiles"),
        str(SUPPORT / "BraveSoftware" / "Brave-Browser" / "Default" / "Cookies"),
        str(HOME / ".ssh"),
        str(HOME / ".gitconfig"),
        str(HOME / ".git-credentials"),
    ]
else:
    # Linux / Outros Unix
    CONFIG = HOME / ".config"
    ARQUIVOS_SENSIVEIS = [
        str(CONFIG / "discord" / "Local Storage" / "leveldb"),
        str(CONFIG / "google-chrome" / "Default" / "Cookies"),
        str(CONFIG / "google-chrome" / "Default" / "Login Data"),
        str(HOME / ".mozilla" / "firefox"),
        str(CONFIG / "BraveSoftware" / "Brave-Browser" / "Default" / "Cookies"),
        str(HOME / ".ssh"),
        str(HOME / ".gitconfig"),
        str(HOME / ".git-credentials"),
    ]

# Armazena os acessos detectados assincronamente pelas threads
acessos_detectados = []
acessos_lock = threading.Lock()

def registrar_acesso(caminho, pid, nome_processo, exe_path=None):
    with acessos_lock:
        # Evita duplicados em janelas curtas de tempo
        ja_registrado = any(
            ac['caminho'] == caminho and ac['pid'] == pid and (time.time() - ac['timestamp'] < 5)
            for ac in acessos_detectados
        )
        if not ja_registrado:
            acessos_detectados.append({
                'caminho': caminho,
                'pid': pid,
                'nome': nome_processo,
                'exe_path': exe_path,
                'timestamp': time.time()
            })

def detectar_processo_acessando(caminho_alvo):
    caminho_alvo_normalizado = str(Path(caminho_alvo).resolve()).lower()
    
    # Escaneia os processos ativos para ver se algum deles tem o arquivo aberto
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'open_files']):
        try:
            files = proc.info.get('open_files')
            if files:
                for f in files:
                    if f.path and str(Path(f.path).resolve()).lower() == caminho_alvo_normalizado:
                        registrar_acesso(caminho_alvo, proc.pid, proc.info['name'], proc.info.get('exe'))
                        return
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    # Se não foi possível mapear o processo exato, registra acesso não identificado
    registrar_acesso(caminho_alvo, None, None, None)

# --- IMPLEMENTAÇÃO NATIVA: WINDOWS (ReadDirectoryChangesW) ---
def _run_windows_monitor():
    import ctypes
    from ctypes import wintypes
    
    FILE_LIST_DIRECTORY = 0x0001
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
    FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
    FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
    
    kernel32 = ctypes.windll.kernel32
    
    # Identifica diretórios únicos para monitorar
    dirs_to_watch = {}
    for caminho in ARQUIVOS_SENSIVEIS:
        p = Path(caminho)
        if p.exists():
            if p.is_dir():
                dirs_to_watch[str(p.resolve())] = str(p.resolve())
            else:
                dirs_to_watch[str(p.parent.resolve())] = str(p.resolve())
                
    def watch_dir(directory, target):
        handle = kernel32.CreateFileW(
            directory,
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None
        )
        if handle == -1:
            return
            
        buffer = ctypes.create_string_buffer(2048)
        bytes_returned = wintypes.DWORD(0)
        
        try:
            while True:
                success = kernel32.ReadDirectoryChangesW(
                    handle,
                    buffer,
                    len(buffer),
                    True,
                    FILE_NOTIFY_CHANGE_LAST_ACCESS | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME,
                    ctypes.byref(bytes_returned),
                    None,
                    None
                )
                if not success:
                    break
                detectar_processo_acessando(target)
                time.sleep(1)
        except:
            pass
        finally:
            kernel32.CloseHandle(handle)

    for watch_d, target_f in dirs_to_watch.items():
        t = threading.Thread(target=watch_dir, args=(watch_d, target_f), daemon=True)
        t.start()

# --- IMPLEMENTAÇÃO NATIVA: MACOS (FSEvents via Watchdog) ---
def _run_macos_monitor():
    try:
        from watchdog.observers.fsevents import FSEventsObserver
        from watchdog.events import FileSystemEventHandler
        print("🍏 Iniciando monitoramento via FSEventsObserver no macOS...")
    except ImportError as e:
        print(f"⚠️ Erro ao importar watchdog FSEventsObserver: {e}")
        # TODO: não suportado em macOS (sem watchdog ou pyobjc)
        return

    class TokenHandler(FileSystemEventHandler):
        def on_any_event(self, event):
            if event.is_directory:
                return
            caminho = event.src_path
            caminho_normalizado = str(Path(caminho).resolve()).lower()
            for sensivel in ARQUIVOS_SENSIVEIS:
                sensivel_normalizado = str(Path(sensivel).resolve()).lower()
                if caminho_normalizado.startswith(sensivel_normalizado):
                    detectar_processo_acessando(caminho)
                    break

    try:
        observer = FSEventsObserver()
        dirs_to_watch = set()
        for caminho in ARQUIVOS_SENSIVEIS:
            p = Path(caminho)
            if p.exists():
                dirs_to_watch.add(str(p.resolve()) if p.is_dir() else str(p.parent.resolve()))
                
        if not dirs_to_watch:
            return
            
        handler = TokenHandler()
        for d in dirs_to_watch:
            observer.schedule(handler, path=d, recursive=True)
            print(f"✅ Watchdog FSEvents agendado para diretório: {d}")
            
        observer.start()
    except Exception as e:
        print(f"⚠️ Erro no FSEvents macOS via Watchdog: {e}")

# --- IMPLEMENTAÇÃO NATIVA: LINUX (auditd / syscall level) ---
def _run_linux_monitor():
    # Garante que auditd rules sejam aplicadas para chaves de tokens
    for caminho in ARQUIVOS_SENSIVEIS:
        if os.path.exists(caminho):
            try:
                # Adiciona regra de auditoria de leitura (p=r) com tag 'token_access'
                subprocess.run(['sudo', 'auditctl', '-w', caminho, '-p', 'r', '-k', 'token_access'], capture_output=True)
            except Exception as e:
                print(f"⚠️ Erro ao registrar regra auditctl para {caminho}: {e}")
                
    # Thread que acompanha o log do auditd em tempo real
    def watch_audit_log():
        log_path = '/var/log/audit/audit.log'
        if not os.path.exists(log_path):
            # TODO: não suportado em Linux (sem auditd rodando ou log inacessível)
            return
            
        try:
            with open(log_path, 'r', errors='ignore') as f:
                # Vai para o fim do arquivo
                f.seek(0, 2)
                while True:
                    linha = f.readline()
                    if not linha:
                        time.sleep(0.5)
                        continue
                        
                    if 'key="token_access"' in linha or 'k=token_access' in linha:
                        import re
                        pid_match = re.search(r'\bpid=(\d+)', linha)
                        comm_match = re.search(r'\bcomm="([^"]+)"', linha)
                        
                        if pid_match and comm_match:
                            pid = int(pid_match.group(1))
                            comm = comm_match.group(1)
                            
                            caminho_detectado = None
                            for path in ARQUIVOS_SENSIVEIS:
                                if path in linha:
                                    caminho_detectado = path
                                    break
                                    
                            if not caminho_detectado:
                                try:
                                    proc = psutil.Process(pid)
                                    for f_open in proc.open_files():
                                        if f_open.path in ARQUIVOS_SENSIVEIS:
                                            caminho_detectado = f_open.path
                                            break
                                except:
                                    pass
                                    
                            if caminho_detectado:
                                exe_path = None
                                try:
                                    exe_path = psutil.Process(pid).exe()
                                except:
                                    pass
                                registrar_acesso(caminho_detectado, pid, comm, exe_path)
        except Exception as e:
            pass

    t = threading.Thread(target=watch_audit_log, daemon=True)
    t.start()

def iniciar_monitoramento_assincrono():
    if sys.platform.startswith("win32"):
        _run_windows_monitor()
    elif sys.platform.startswith("darwin"):
        _run_macos_monitor()
    else:
        _run_linux_monitor()

def verificar_acesso_tokens():
    import config
    alertas = []
    global acessos_detectados
    with acessos_lock:
        temp_acessos = list(acessos_detectados)
        acessos_detectados.clear()
        
    # 1. Agrupa os acessos por PID para detectar cópia em massa (Infostealer)
    limiar_qtd = getattr(config, 'INFOSTEALER_LIMITE_QUANTIDADE', 3)
    janela_tempo = getattr(config, 'INFOSTEALER_JANELA_TEMPO', 2.0)
    
    acessos_por_pid = {}
    for ac in temp_acessos:
        pid = ac['pid']
        if pid is None:
            continue
            
        # Pula se for um acesso legítimo pela whitelist de caminhos absolutos
        exe_path = ac.get('exe_path')
        if exe_path and eh_acesso_legitimo(exe_path, ac['caminho']):
            continue
            
        if pid not in acessos_por_pid:
            acessos_por_pid[pid] = []
        acessos_por_pid[pid].append(ac)
        
    pids_infostealer = set()
    for pid, lista_ac in acessos_por_pid.items():
        if len(lista_ac) >= limiar_qtd:
            # Ordena por timestamp para verificar a janela de tempo
            lista_ac.sort(key=lambda x: x['timestamp'])
            
            arquivos_acessados = set()
            t_inicio = lista_ac[0]['timestamp']
            
            for ac in lista_ac:
                if ac['timestamp'] - t_inicio <= janela_tempo:
                    arquivos_acessados.add(ac['caminho'])
                else:
                    if len(arquivos_acessados) >= limiar_qtd:
                        break
                    arquivos_acessados = {ac['caminho']}
                    t_inicio = ac['timestamp']
                    
            if len(arquivos_acessados) >= limiar_qtd:
                pids_infostealer.add(pid)
                nome = lista_ac[0]['nome']
                alertas.append({
                    'tipo': 'infostealer_copia_massa',
                    'mensagem': f"⛔ CRÍTICO — INFOSTEALER DETECTADO: Processo '{nome}' (PID {pid}) realizando leitura/cópia em massa de {len(arquivos_acessados)} arquivos sensíveis.",
                    'detalhes': {'pid': pid, 'nome': nome, 'caminho': lista_ac[0]['caminho'], 'quantidade': len(arquivos_acessados)}
                })
                
    # 2. Gera alertas individuais para acessos que não foram classificados como cópia em massa
    for ac in temp_acessos:
        caminho = ac['caminho']
        pid = ac['pid']
        nome = ac['nome']
        exe_path = ac.get('exe_path')
        
        # Pula se já foi alertado como infostealer
        if pid in pids_infostealer:
            continue
            
        if eh_acesso_ao_proprio_leveldb(nome, caminho):
            continue  # Processo acessando seu próprio LevelDB — não é suspeito
            
        # Validação baseada no caminho absoluto do executável
        if exe_path and eh_acesso_legitimo(exe_path, caminho):
            _logar_supressao(nome, caminho)
            continue

        # Fallback: tenta validar pelo nome do processo quando exe_path é None
        if not exe_path and nome:
            NOMES_CONFIAVEIS_POR_ARQUIVO = {
                ".gitconfig": ["git.exe", "git-remote-https.exe", "git-credential"],
                "leveldb": ["discord.exe"],
                ".git-credentials": ["git.exe"],
            }
            arquivo_lower = caminho.lower().replace("\\", "/")
            nome_lower = nome.lower()
            suprimido = False
            for padrao_arq, nomes_proc in NOMES_CONFIAVEIS_POR_ARQUIVO.items():
                if padrao_arq in arquivo_lower:
                    if any(n in nome_lower for n in nomes_proc):
                        _logar_supressao(nome, caminho)
                        suprimido = True
                        break
            if suprimido:
                continue  # Suprime — acesso legítimo identificado por nome
            
        if nome:
            alertas.append({
                'tipo': 'acesso_token_suspeito',
                'mensagem': f"⛔ CRÍTICO — Processo '{nome}' (PID {pid}) acessando arquivo sensível: {caminho}",
                'detalhes': {'pid': pid, 'nome': nome, 'caminho': caminho, 'exe_path': exe_path}
            })
        else:
            # Processo não identificado
            if eh_arquivo_ignorado_sem_processo(caminho):
                print(f"[ACESSO SUPRIMIDO] Acesso não identificado a {caminho} — processo não identificável no Windows sem admin")
                continue
            alertas.append({
                'tipo': 'acesso_token_nao_identificado',
                'mensagem': f"⚠️  ACESSO NÃO IDENTIFICADO em arquivo sensível: {caminho}",
                'detalhes': {'caminho': caminho}
            })
            
    return alertas

def verificar_exfiltracao(alertas_tokens, conexoes_externas):
    alertas_exfil = []
    if alertas_tokens and conexoes_externas:
        ips_suspeitos = [
            c['ip'] for c in conexoes_externas
            if eh_conexao_externa(c['ip'])
        ]
        if ips_suspeitos:
            alertas_exfil.append({
                'tipo': 'exfiltracao',
                'mensagem': f"🚨 POSSÍVEL EXFILTRAÇÃO — Acesso a tokens + conexão externa para: {ips_suspeitos[:3]}",
                'detalhes': {'ips': ips_suspeitos[:3]}
            })
    return alertas_exfil
