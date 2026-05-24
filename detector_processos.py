import psutil
import os

# Locais suspeitos para executáveis
LOCAIS_SUSPEITOS = [
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/run/user",
]

# Locais suspeitos no home
HOME = os.path.expanduser("~")
LOCAIS_SUSPEITOS_HOME = [
    os.path.join(HOME, ".cache"),
    os.path.join(HOME, ".local/share"),
]

# Processos do sistema que são sempre legítimos
PROCESSOS_SISTEMA = [
    'systemd', 'kworker', 'ksoftirqd', 'migration',
    'rcu_', 'watchdog', 'sshd', 'bash', 'sh',
    'python3', 'gnome', 'Xorg', 'dbus', 'NetworkManager', 'chronyd'

]

def verificar_processos_suspeitos():
    alertas = []

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
        try:
            exe = proc.info.get('exe')
            nome = proc.info.get('name', '')
            pid = proc.info.get('pid')
            usuario = proc.info.get('username', '')

            if not exe:
                continue

            # Processo rodando de local suspeito
            for local in LOCAIS_SUSPEITOS:
                if exe.startswith(local):
                    alertas.append(
                        f"⛔ CRÍTICO — Processo '{nome}' (PID {pid}) "
                        f"rodando de local suspeito: {exe}"
                    )

            # Processo rodando de local suspeito no home
            for local in LOCAIS_SUSPEITOS_HOME:
                if exe.startswith(local):
                    alertas.append(
                        f"⚠️  SUSPEITO — Processo '{nome}' (PID {pid}) "
                        f"rodando de pasta oculta: {exe}"
                    )

            # Processo rodando como root sem ser do sistema
            if usuario == 'root':
                eh_sistema = any(s in nome for s in PROCESSOS_SISTEMA)
                if not eh_sistema and exe and not exe.startswith('/usr'):
                    alertas.append(
                        f"⚠️  SUSPEITO — Processo '{nome}' (PID {pid}) "
                        f"rodando como ROOT fora do sistema: {exe}"
                    )

            # Nome de processo disfarçado
            # Ex: processo com nome parecido com sistema mas em local errado
            nomes_sistema = ['systemd', 'sshd', 'cron', 'init']
            for nome_sys in nomes_sistema:
                if nome_sys in nome and exe and not exe.startswith('/usr') and not exe.startswith('/lib') and not exe.startswith('/sbin') and not exe.startswith('/bin'):
                    alertas.append(
                        f"⛔ CRÍTICO — Processo '{nome}' se disfarça de "
                        f"processo do sistema mas roda de: {exe}"
                    )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return alertas
