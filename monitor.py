import psutil
import datetime
import config

def coletar_dados():
    dados = {}

    # CPU e RAM
    dados['cpu'] = psutil.cpu_percent(interval=1)
    dados['ram'] = psutil.virtual_memory().percent
    dados['hora'] = datetime.datetime.now().strftime("%H:%M:%S")

    # Processos suspeitos
    processos = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            if proc.info['cpu_percent'] > 20:
                processos.append(proc.info)
        except:
            pass
    dados['processos_suspeitos'] = processos

    # Conexões de rede
    conexoes = psutil.net_connections()
    dados['total_conexoes'] = len(conexoes)
    
    # Conexões externas
    externas = []
    for c in conexoes:
        if c.raddr and c.status == 'ESTABLISHED':
            externas.append({
                'ip': c.raddr.ip,
                'porta': c.raddr.port,
                'pid': c.pid
            })
    dados['conexoes_externas'] = externas

    return dados

def verificar_alertas(dados):
    alertas = []

    if dados['cpu'] > config.CPU_LIMITE:
        alertas.append(f"CPU ALTA: {dados['cpu']}%")

    if dados['ram'] > config.RAM_LIMITE:
        alertas.append(f"RAM ALTA: {dados['ram']}%")

    if dados['total_conexoes'] > config.CONEXOES_LIMITE:
        alertas.append(f"MUITAS CONEXOES: {dados['total_conexoes']}")

    return alertas
