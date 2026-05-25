import time
import schedule
import datetime
import os
import hashlib
import psutil
from groq import Groq
import config
import detector_tokens
import detector_processos
import detector_ameacas
import mitigacao
import dashboard

cliente = Groq(api_key=config.GROQ_API_KEY)
eventos_do_dia = []
baseline_arquivos = {}

def coletar_dados_sistema():
    dados = {}
    dados['hora'] = datetime.datetime.now().strftime("%H:%M:%S")
    dados['cpu'] = psutil.cpu_percent(interval=1)
    dados['ram'] = psutil.virtual_memory().percent
    processos = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'username']):
        try:
            if proc.info['cpu_percent'] > 20:
                processos.append(proc.info)
        except:
            pass
    dados['processos_suspeitos'] = processos
    conexoes = psutil.net_connections()
    dados['total_conexoes'] = len(conexoes)
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

def verificar_alertas_sistema(dados):
    alertas = []
    if dados['cpu'] > config.CPU_LIMITE:
        alertas.append(f"CPU ALTA: {dados['cpu']}%")
    if dados['ram'] > config.RAM_LIMITE:
        alertas.append(f"RAM ALTA: {dados['ram']}%")
    if dados['total_conexoes'] > config.CONEXOES_LIMITE:
        alertas.append(f"MUITAS CONEXOES: {dados['total_conexoes']}")
    return alertas

def calcular_hash(caminho):
    try:
        h = hashlib.md5()
        with open(caminho, 'rb') as f:
            h.update(f.read(8192))
        return h.hexdigest()
    except:
        return None

def construir_baseline():
    global baseline_arquivos
    print("📁 Construindo baseline de arquivos...")
    for diretorio in config.DIRETORIOS_MONITORADOS:
        if not os.path.exists(diretorio):
            continue
        for root, dirs, files in os.walk(diretorio):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for arquivo in files:
                caminho = os.path.join(root, arquivo)
                try:
                    stat = os.stat(caminho)
                    baseline_arquivos[caminho] = {
                        'hash': calcular_hash(caminho),
                        'tamanho': stat.st_size,
                        'modificado': stat.st_mtime
                    }
                except:
                    pass
    dashboard.baseline_count = len(baseline_arquivos)
    print(f"✅ Baseline construído: {len(baseline_arquivos)} arquivos monitorados")

def verificar_arquivos():
    alertas_arquivos = []
    for diretorio in config.DIRETORIOS_MONITORADOS:
        if not os.path.exists(diretorio):
            continue
        for root, dirs, files in os.walk(diretorio):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for arquivo in files:
                caminho = os.path.join(root, arquivo)
                ext = os.path.splitext(arquivo)[1].lower()
                try:
                    stat = os.stat(caminho)
                    if caminho not in baseline_arquivos:
                        alertas_arquivos.append(f"ARQUIVO NOVO: {caminho}")
                        if ext in config.EXTENSOES_SUSPEITAS:
                            for local in config.LOCAIS_SUSPEITOS:
                                if caminho.startswith(local):
                                    alertas_arquivos.append(
                                        f"⛔ CRÍTICO — EXECUTÁVEL EM LOCAL SUSPEITO: {caminho}"
                                    )
                        baseline_arquivos[caminho] = {
                            'hash': calcular_hash(caminho),
                            'tamanho': stat.st_size,
                            'modificado': stat.st_mtime
                        }
                        continue
                    anterior = baseline_arquivos[caminho]
                    if stat.st_mtime != anterior['modificado']:
                        novo_hash = calcular_hash(caminho)
                        if novo_hash != anterior['hash']:
                            alertas_arquivos.append(f"ARQUIVO MODIFICADO: {caminho}")
                            if caminho.startswith('/etc'):
                                alertas_arquivos.append(
                                    f"⛔ CRÍTICO — ARQUIVO DE SISTEMA ALTERADO: {caminho}"
                                )
                            baseline_arquivos[caminho]['hash'] = novo_hash
                            baseline_arquivos[caminho]['modificado'] = stat.st_mtime
                except:
                    pass
    return alertas_arquivos

def analisar_com_ia(dados_sistema, todos_alertas, contexto_mitre):
    prompt = f"""
Você é um analista de segurança SOC Tier 1 experiente.
Analise os dados abaixo e responda em português de forma direta.

DADOS DO SISTEMA:
- Hora: {dados_sistema['hora']}
- CPU: {dados_sistema['cpu']}%
- RAM: {dados_sistema['ram']}%
- Total de conexões: {dados_sistema['total_conexoes']}
- Conexões externas: {dados_sistema['conexoes_externas'][:5]}

ALERTAS DETECTADOS: {todos_alertas[:15]}

CONTEXTO MITRE ATT&CK:
{contexto_mitre if contexto_mitre else 'Nenhuma técnica identificada'}

Responda exatamente neste formato:
RISCO: [BAIXO/MÉDIO/ALTO/CRÍTICO]
SITUAÇÃO: [o que está acontecendo em 2 linhas]
AÇÃO: [o que fazer agora em 1 linha]
"""
    resposta = cliente.chat.completions.create(
        model=config.MODELO,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=400
    )
    return resposta.choices[0].message.content

def extrair_risco(analise):
    for linha in analise.split('\n'):
        if 'RISCO:' in linha:
            if 'CRÍTICO' in linha:
                return 'CRÍTICO'
            elif 'ALTO' in linha:
                return 'ALTO'
            elif 'MÉDIO' in linha:
                return 'MÉDIO'
    return 'BAIXO'

def verificar_sistema():
    print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] Verificando sistema...")
    try:
        dados = coletar_dados_sistema()
        alertas_sistema = verificar_alertas_sistema(dados)
        alertas_arquivos = verificar_arquivos()
        alertas_tokens = detector_tokens.verificar_acesso_tokens()
        alertas_processos = detector_processos.verificar_processos_suspeitos()
        alertas_exfil = detector_tokens.verificar_exfiltracao(alertas_tokens, dados['conexoes_externas'])
        alertas_ameacas = detector_ameacas.verificar_ips_maliciosos(dados['conexoes_externas'])
        todos_alertas = alertas_sistema + alertas_arquivos + alertas_tokens + alertas_processos + alertas_exfil + alertas_ameacas
        if todos_alertas:
            print(f"⚠️  ALERTAS DETECTADOS:")
            for a in todos_alertas:
                print(f"   → {a}")
            contexto_mitre = mitigacao.formatar_contexto_mitre(todos_alertas)
            if contexto_mitre:
                print(f"\n📚 CONTEXTO MITRE ATT&CK:{contexto_mitre}")
            try:
                analise = analisar_com_ia(dados, todos_alertas, contexto_mitre)
                print(f"\n🤖 ANÁLISE IA:\n{analise}")
                risco = extrair_risco(analise)
                acoes = mitigacao.agir_automaticamente(todos_alertas, risco)
                if acoes:
                    print(f"\n⚡ AÇÕES AUTOMÁTICAS:")
                    for acao in acoes:
                        print(f"   → {acao}")
                evento = {
                    'hora': dados['hora'],
                    'alertas': todos_alertas,
                    'analise': analise,
                    'risco': risco,
                    'acoes': acoes
                }
                eventos_do_dia.append(evento)
                dashboard.eventos_compartilhados.append(evento)
            except Exception as e:
                print(f"⚠️  IA indisponível: {e}")
                evento = {
                    'hora': dados['hora'],
                    'alertas': todos_alertas,
                    'analise': 'IA indisponível',
                    'risco': 'DESCONHECIDO',
                    'acoes': []
                }
                eventos_do_dia.append(evento)
                dashboard.eventos_compartilhados.append(evento)
        else:
            print(f"✅ Normal — CPU: {dados['cpu']}% | RAM: {dados['ram']}% | Conexões: {dados['total_conexoes']} | Ameaças: OK")
    except Exception as e:
        print(f"❌ Erro: {e}")

def gerar_relatorio():
    agora = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    criticos = [e for e in eventos_do_dia if e.get('risco') in ['ALTO', 'CRÍTICO']]
    resumo = f"{len(eventos_do_dia)} evento(s) — {len(criticos)} crítico(s)." if eventos_do_dia else "Nenhum evento suspeito hoje."
    relatorio = f"\n{'='*50}\nRELATÓRIO DIÁRIO DE SEGURANÇA\nData: {agora}\n{'='*50}\nRESUMO: {resumo}\n\nEVENTOS:\n"
    for e in eventos_do_dia:
        acoes_str = '\n'.join(e.get('acoes', [])) if e.get('acoes') else 'Nenhuma ação automática'
        relatorio += f"\n[{e['hora']}] RISCO: {e.get('risco','?')}\nAlertas: {e['alertas']}\nAnálise: {e['analise']}\nAções: {acoes_str}\n{'-'*30}\n"
    with open(config.RELATORIO_PATH, 'a') as f:
        f.write(relatorio)
    print(relatorio)
    eventos_do_dia.clear()
    dashboard.eventos_compartilhados.clear()

print("🛡️  Agente de Segurança SOC iniciado!")
print(f"Diretórios monitorados: {len(config.DIRETORIOS_MONITORADOS)}")
print("Verificação a cada 1 minuto | Relatório às 23:59")
print("Mitigação automática: ATIVA para riscos ALTO e CRÍTICO")
print("Dashboard: http://localhost:5000")
print("CTRL+C para parar\n")

construir_baseline()
schedule.every(1).minutes.do(verificar_sistema)
schedule.every().day.at("23:59").do(gerar_relatorio)
verificar_sistema()

while True:
    try:
        schedule.run_pending()
        time.sleep(30)
    except KeyboardInterrupt:
        print("\n🛑 Agente encerrado.")
        gerar_relatorio()
        break
    except Exception as e:
        print(f"❌ Erro: {e}")
        time.sleep(30)
