import time
import schedule
import datetime
import os
import hashlib
import psutil
import sys
import queue
import threading
from pathlib import Path
# from groq import Groq
import httpx

# Importações de módulos de detecção locais
import config
import detector_tokens
import detector_processos
import detector_ameacas
import mitigacao
import dashboard
import detector_lotl
import detector_registro  # Novo detector para persistência no registro do Windows

# Configuração do Ollama local
OLLAMA_MODEL = getattr(config, 'OLLAMA_MODEL', os.getenv("OLLAMA_MODEL", "llama3.1"))
OLLAMA_URL_ENV = getattr(config, 'OLLAMA_URL', os.getenv("OLLAMA_URL", "http://localhost:11434"))
if "v1/chat/completions" not in OLLAMA_URL_ENV:
    OLLAMA_URL = f"{OLLAMA_URL_ENV.rstrip('/')}/v1/chat/completions"
else:
    OLLAMA_URL = OLLAMA_URL_ENV

def chamar_ia(mensagens: list, timeout: int = 60) -> str:
    """
    Chama Ollama local primeiro com timeout de 60s. Se falhar, cai para Groq como fallback.
    """
    # Tenta Ollama local
    try:
        resp = httpx.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "messages": mensagens,
                "stream": False
            },
            timeout=timeout
        )
        if resp.status_code == 200:
            return resp.json()['choices'][0]['message']['content']
    except Exception as e:
        print(f"⚠️ Ollama indisponível: {e}. Usando Groq como fallback.")

    # Fallback: Groq
    if config.GROQ_API_KEY and config.GROQ_API_KEY != "sua_chave_groq":
        try:
            resp = httpx.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {config.GROQ_API_KEY}"},
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": mensagens,
                    "max_tokens": 500
                },
                timeout=timeout
            )
            if resp.status_code == 200:
                return resp.json()['choices'][0]['message']['content']
        except Exception as e:
            print(f"⚠️ Groq também falhou: {e}")

    return "RISCO: DESCONHECIDO\nSITUAÇÃO: IA indisponível\nAÇÃO: Verificar Ollama e Groq"

def enviar_para_central(alertas, metricas, hora):
    try:
        response = httpx.post(
            f"{config.API_CENTRAL_URL}/analisar",
            headers={"Authorization": f"Bearer {config.API_CENTRAL_TOKEN}"},
            json={
                "alertas": alertas,
                "metricas": metricas,
                "hora": hora,
                "os": sys.platform
            },
            timeout=30
        )
        if response.status_code == 200:
            return response.json()
        else:
            print(f"⚠️ API Central retornou erro: {response.status_code}")
    except Exception as e:
        print(f"⚠️ API Central indisponível: {e}")
    return None

eventos_do_dia = []
baseline_arquivos = {}

# Locks e filas para concorrência segura
estado_lock = threading.Lock()
fila_eventos = queue.Queue()

# --- HANDLER DE EVENTOS DO WATCHDOG (FIM EVENT-DRIVEN) ---
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

class FIMHandler(FileSystemEventHandler):
    """
    Escuta em tempo real eventos de modificação, criação e remoção
    de arquivos nos diretórios configurados, enfileirando-os de forma segura.
    """
    def on_created(self, event):
        if not event.is_directory:
            fila_eventos.put(('created', event.src_path))

    def on_modified(self, event):
        if not event.is_directory:
            fila_eventos.put(('modified', event.src_path))

    def on_deleted(self, event):
        if not event.is_directory:
            fila_eventos.put(('deleted', event.src_path))


def coletar_dados_sistema():
    dados = {}
    dados['hora'] = datetime.datetime.now().strftime("%H:%M:%S")
    
    try:
        dados['cpu'] = psutil.cpu_percent(interval=0.1)
    except:
        dados['cpu'] = 0.0
        
    try:
        dados['ram'] = psutil.virtual_memory().percent
    except:
        dados['ram'] = 0.0
        
    processos = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'username']):
            try:
                cpu_p = proc.info.get('cpu_percent')
                if cpu_p is not None and cpu_p > 20:
                    processos.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as e:
        print(f"⚠️ Erro ao iterar processos: {e}")
        
    dados['processos_suspeitos'] = processos
    
    conexoes = []
    try:
        conexoes = psutil.net_connections()
    except (psutil.AccessDenied, Exception):
        try:
            conexoes = psutil.Process().connections()
        except:
            pass
            
    dados['total_conexoes'] = len(conexoes)
    
    externas = []
    for c in conexoes:
        try:
            if c.raddr and c.status == 'ESTABLISHED':
                nome_processo = "Desconhecido"
                if c.pid:
                    try:
                        nome_processo = psutil.Process(c.pid).name()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                externas.append({
                    'ip': c.raddr.ip,
                    'porta': c.raddr.port,
                    'pid': c.pid,
                    'processo': nome_processo
                })
        except:
            pass
    dados['conexoes_externas'] = externas
    return dados


def verificar_alertas_sistema(dados):
    alertas = []
    if dados['cpu'] > config.CPU_LIMITE:
        alertas.append({
            'tipo': 'cpu_alta',
            'mensagem': f"CPU ALTA: {dados['cpu']}%",
            'detalhes': {'cpu': dados['cpu']}
        })
    if dados['ram'] > config.RAM_LIMITE:
        alertas.append({
            'tipo': 'ram_alta',
            'mensagem': f"RAM ALTA: {dados['ram']}%",
            'detalhes': {'ram': dados['ram']}
        })
    if dados['total_conexoes'] > config.CONEXOES_LIMITE:
        alertas.append({
            'tipo': 'conexoes_altas',
            'mensagem': f"MUITAS CONEXOES: {dados['total_conexoes']}",
            'detalhes': {'total_conexoes': dados['total_conexoes']}
        })
    return alertas


def calcular_hash(caminho):
    """
    Calcula o hash SHA-256 em blocos do arquivo fornecido.
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
    except:
        return None


def construir_baseline():
    """
    Cria o baseline estático na inicialização de todos os diretórios monitorados.
    """
    global baseline_arquivos
    print("📁 Construindo baseline inicial de arquivos...")
    for diretorio in config.DIRETORIOS_MONITORADOS:
        if not os.path.exists(diretorio):
            continue
        try:
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
        except Exception as e:
            print(f"⚠️ Erro ao escanear diretório {diretorio} para baseline: {e}")
            
    print(f"✅ Baseline de arquivos construído: {len(baseline_arquivos)} arquivos monitorados")


def verificar_arquivos():
    """
    FIM baseado em eventos (Watchdog). Em vez de os.walk periódico, consome a fila de eventos.
    """
    alertas_arquivos = []
    
    # Coleta todos os eventos de arquivo acumulados na fila
    eventos_a_processar = []
    while not fila_eventos.empty():
        try:
            eventos_a_processar.append(fila_eventos.get_nowait())
        except queue.Empty:
            break
            
    # Deduplica os eventos por caminho, mantendo apenas a última mudança
    mudancas = {}
    for tipo_evento, caminho in eventos_a_processar:
        mudancas[caminho] = tipo_evento
        
    for caminho, tipo in mudancas.items():
        ext = os.path.splitext(os.path.basename(caminho))[1].lower()
        
        # Trata remoções de arquivos
        if tipo == 'deleted':
            if caminho in baseline_arquivos:
                del baseline_arquivos[caminho]
                alertas_arquivos.append({
                    'tipo': 'arquivo_deletado',
                    'mensagem': f"ARQUIVO DELETADO: {caminho}",
                    'detalhes': {'caminho': caminho}
                })
            continue
            
        # Trata criações e modificações de arquivos
        try:
            if not os.path.exists(caminho):
                continue
            stat = os.stat(caminho)
            
            if caminho not in baseline_arquivos:
                # Novo arquivo detectado
                alertas_arquivos.append({
                    'tipo': 'arquivo_novo',
                    'mensagem': f"ARQUIVO NOVO: {caminho}",
                    'detalhes': {'caminho': caminho}
                })
                
                # Verifica se está em local suspeito com extensão de executável
                if ext in config.EXTENSOES_SUSPEITAS:
                    for local in config.LOCAIS_SUSPEITOS:
                        if caminho.lower().startswith(local.lower()):
                            alertas_arquivos.append({
                                'tipo': 'executavel_suspeito_tmp',
                                'mensagem': f"⛔ CRÍTICO — EXECUTÁVEL EM LOCAL SUSPEITO: {caminho}",
                                'detalhes': {'caminho': caminho}
                            })
                            
                baseline_arquivos[caminho] = {
                    'hash': calcular_hash(caminho),
                    'tamanho': stat.st_size,
                    'modificado': stat.st_mtime
                }
            else:
                anterior = baseline_arquivos[caminho]
                # Verifica se o arquivo foi de fato modificado (tamanho ou timestamp de escrita)
                if stat.st_mtime != anterior['modificado'] or stat.st_size != anterior['tamanho']:
                    novo_hash = calcular_hash(caminho)
                    if novo_hash != anterior['hash']:
                        alertas_arquivos.append({
                            'tipo': 'arquivo_modificado',
                            'mensagem': f"ARQUIVO MODIFICADO: {caminho}",
                            'detalhes': {'caminho': caminho}
                        })
                        
                        eh_etc = False
                        if sys.platform.startswith("win32"):
                            eh_etc = "drivers\\etc" in caminho.lower()
                        else:
                            eh_etc = caminho.startswith('/etc')
                            
                        if eh_etc:
                            alertas_arquivos.append({
                                'tipo': 'arquivo_sistema_alterado',
                                'mensagem': f"⛔ CRÍTICO — ARQUIVO DE SISTEMA ALTERADO: {caminho}",
                                'detalhes': {'caminho': caminho}
                            })
                        baseline_arquivos[caminho]['hash'] = novo_hash
                        baseline_arquivos[caminho]['modificado'] = stat.st_mtime
                        baseline_arquivos[caminho]['tamanho'] = stat.st_size
        except:
            pass
            
    return alertas_arquivos


def analisar_com_ia(dados_sistema, todos_alertas, contexto_mitre):
    mensagens_alertas = [a['mensagem'] for a in todos_alertas]
    
    prompt = f"""
Você é um analista de segurança SOC Tier 1 experiente.
Analise os dados abaixo e responda em português de forma direta.

DADOS DO SISTEMA:
- Hora: {dados_sistema['hora']}
- CPU: {dados_sistema['cpu']}%
- RAM: {dados_sistema['ram']}%
- Total de conexões: {dados_sistema['total_conexoes']}
- Conexões externas: {dados_sistema['conexoes_externas'][:5]}

ALERTAS DETECTADOS: {mensagens_alertas[:15]}

CONTEXTO MITRE ATT&CK:
{contexto_mitre if contexto_mitre else 'Nenhuma técnica identificada'}

Responda exatamente neste formato:
RISCO: [BAIXO/MÉDIO/ALTO/CRÍTICO]
SITUAÇÃO: [o que está acontecendo em 2 linhas]
AÇÃO: [o que fazer agora em 1 linha]
"""
    return chamar_ia([{"role": "user", "content": prompt}], timeout=60)


def extrair_risco(analise):
    for linha in analise.split('\n'):
        if 'RISCO:' in linha:
            if 'CRÍTICO' in linha or 'CRITICO' in linha:
                return 'CRÍTICO'
            elif 'ALTO' in linha:
                return 'ALTO'
            elif 'MÉDIO' in linha or 'MEDIO' in linha:
                return 'MÉDIO'
    return 'BAIXO'


def _salvar_estado_json(dados, risco, total_alertas):
    """
    Função auxiliar para persistir com segurança o estado em estado.json.
    """
    try:
        import json
        estado = {
            "hora": dados['hora'],
            "cpu": dados['cpu'],
            "ram": dados['ram'],
            "conexoes": dados['total_conexoes'],
            "arquivos_monitorados": len(baseline_arquivos),
            "total_alertas_hoje": total_alertas,
            "status": risco,
            "eventos": eventos_do_dia[-20:]
        }
        with open(Path(__file__).parent / "estado.json", "w", encoding="utf-8") as f:
            json.dump(estado, f, ensure_ascii=False)
    except Exception as e:
        print(f"⚠️ Erro ao salvar estado.json: {e}")


def verificar_sistema():
    print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] Verificando sistema...")
    detector_tokens.reset_supressoes_ciclo()
    try:
        dados = coletar_dados_sistema()
        alertas_sistema = verificar_alertas_sistema(dados)
        alertas_arquivos = verificar_arquivos()
        alertas_tokens = detector_tokens.verificar_acesso_tokens()
        alertas_processos = detector_processos.verificar_processos_suspeitos()
        alertas_exfil = detector_tokens.verificar_exfiltracao(alertas_tokens, dados['conexoes_externas'])
        alertas_ameacas = detector_ameacas.verificar_ips_maliciosos(dados['conexoes_externas'], houve_acesso_token=bool(alertas_tokens))
        
        alertas_lotl = []
        if getattr(config, 'LOTL_ATIVADO', False):
            alertas_lotl = detector_lotl.verificar_lotl()

        # Adiciona verificação de persistência no registro do Windows
        alertas_registro = detector_registro.verificar_alteracoes_registro()
        
        # Junta todos os alertas estruturados
        todos_alertas = (alertas_sistema + alertas_arquivos + alertas_tokens + 
                         alertas_processos + alertas_exfil + alertas_ameacas + 
                         alertas_lotl + alertas_registro)
                         
        todos_alertas = [
            {'tipo': 'generico', 'mensagem': a, 'detalhes': {}} if isinstance(a, str) else a
            for a in todos_alertas
        ]
        
        # Deduplicação de alertas no ciclo
        alertas_vistos = set()
        alertas_deduplicados = []
        for alerta in todos_alertas:
            detalhes = alerta.get('detalhes', {})
            caminho = alerta.get('caminho') or detalhes.get('caminho', '')
            ip = alerta.get('ip') or detalhes.get('ip', '')
            pid = alerta.get('pid') or detalhes.get('pid', '')
            
            chave = f"{alerta['tipo']}:{caminho or ip or pid}"
            if chave in alertas_vistos:
                continue
            alertas_vistos.add(chave)
            alertas_deduplicados.append(alerta)
            
        todos_alertas = alertas_deduplicados
        
        if todos_alertas:
            print(f"⚠️  ALERTAS DETECTADOS:")
            for a in todos_alertas:
                print(f"   → {a['mensagem']}")
                
            # Extrai mensagens para MITRE e IA
            mensagens_alertas = [a['mensagem'] for a in todos_alertas]
            contexto_mitre = mitigacao.formatar_contexto_mitre(mensagens_alertas)
            if contexto_mitre:
                print(f"\n📚 CONTEXTO MITRE ATT&CK:{contexto_mitre}")
                
            # --- MITIGAÇÃO IMEDIATA (Alta Severidade) ---
            # Bloqueia IPs, mata PIDs e move arquivos de imediato se forem altamente severos
            alertas_alta_severidade = [
                a for a in todos_alertas
                if a.get('tipo') in [
                    'infostealer_copia_massa', 
                    'acesso_token_suspeito', 
                    'exfiltracao', 
                    'ip_malicioso', 
                    'executavel_suspeito_tmp', 
                    'processo_local_suspeito', 
                    'processo_disfarcado',
                    'registro_persistência_novo',
                    'registro_persistência_modificado'
                ]
            ]
            acoes_imediatas = []
            if alertas_alta_severidade:
                print("\n⚡ MITIGAÇÃO IMEDIATA (Alta Severidade):")
                # Dispara ações com severidade 'CRÍTICO' na Thread Principal
                acoes_imediatas = mitigacao.agir_automaticamente(alertas_alta_severidade, 'CRÍTICO')
                for acao in acoes_imediatas:
                    print(f"   → {acao}")

            # --- PROCESSAMENTO ASSÍNCRONO DA IA (Groq) ---
            # Evita travamento por latência da API externa
            def processar_ia_background(dados_sistema, alertas_lista, mitre_ctx, acoes_previas):
                try:
                    hora_atual = dados_sistema['hora']
                    resultado = enviar_para_central(alertas_lista, dados_sistema, hora_atual)
                    if resultado:
                        risco_ia = resultado.get("risco", "DESCONHECIDO")
                        analise_ia = resultado.get("analise", "")
                        ameacas_coletivas = resultado.get("ameacas_coletivas", [])
                        if ameacas_coletivas:
                            print(f"🌐 AMEAÇAS COLETIVAS DETECTADAS: {ameacas_coletivas}")
                        risco = risco_ia
                        analise = analise_ia
                    else:
                        print("⚠️ Usando análise local — API Central indisponível")
                        analise = analisar_com_ia(dados_sistema, alertas_lista, mitre_ctx)
                        risco = extrair_risco(analise)
                    
                    # Executa mitigação adicional de acordo com a classificação de risco da IA
                    novas_acoes = mitigacao.agir_automaticamente(alertas_lista, risco)
                    todas_acoes = list(set(acoes_previas + novas_acoes))
                    
                    evento = {
                        'hora': dados_sistema['hora'],
                        'alertas': [a['mensagem'] for a in alertas_lista],
                        'analise': analise,
                        'risco': risco,
                        'acoes': todas_acoes
                    }
                    
                    with estado_lock:
                        eventos_do_dia.append(evento)
                        _salvar_estado_json(dados_sistema, risco, len(alertas_lista))
                except Exception as e:
                    print(f"⚠️ Erro no processamento da IA em background: {e}")

            t = threading.Thread(
                target=processar_ia_background,
                args=(dados, todos_alertas, contexto_mitre, acoes_imediatas),
                daemon=True
            )
            t.start()
        else:
            print(f"✅ Normal — CPU: {dados['cpu']:.1f}% | RAM: {dados['ram']:.1f}% | Conexões: {dados['total_conexoes']} | Ameaças: OK")
            with estado_lock:
                _salvar_estado_json(dados, "Normal", 0)
            
    except Exception as e:
        print(f"❌ Erro ao verificar sistema: {e}")


def gerar_relatorio():
    agora = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    with estado_lock:
        criticos = [e for e in eventos_do_dia if e.get('risco') in ['ALTO', 'CRÍTICO']]
        resumo = f"{len(eventos_do_dia)} evento(s) — {len(criticos)} crítico(s)." if eventos_do_dia else "Nenhum evento suspeito hoje."
        relatorio = f"\n{'='*50}\nRELATÓRIO DIÁRIO DE SEGURANÇA\nData: {agora}\n{'='*50}\nRESUMO: {resumo}\n\nEVENTOS:\n"
        for e in eventos_do_dia:
            acoes_str = '\n'.join(e.get('acoes', [])) if e.get('acoes') else 'Nenhuma ação automática'
            relatorio += f"\n[{e['hora']}] RISCO: {e.get('risco','?')}\nAlertas: {e['alertas']}\nAnálise: {e['analise']}\nAções: {acoes_str}\n{'-'*30}\n"
        
        try:
            with open(config.RELATORIO_PATH, 'a', encoding='utf-8') as f:
                f.write(relatorio)
            print(relatorio)
        except Exception as e:
            print(f"❌ Erro ao salvar relatório: {e}")
            
        eventos_do_dia.clear()


if __name__ == '__main__':
    print("🛡️  Agente de Segurança SOC iniciado!")
    print(f"Sistema Operacional detectado: {sys.platform}")
    print(f"Diretórios monitorados: {len(config.DIRETORIOS_MONITORADOS)}")
    print("Monitoramento por eventos de arquivo ativo | Relatório às 23:59")
    print("Mitigação automática: ATIVA para riscos ALTO e CRÍTICO")
    print("Dashboard: http://localhost:5000")
    print("CTRL+C para parar\n")

    construir_baseline()
    
    # Inicializa baseline do registro do Windows
    try:
        detector_registro.construir_baseline_registro()
    except Exception as e:
        print(f"⚠️ Erro ao inicializar baseline do registro: {e}")

    # Inicia o monitoramento assíncrono de tokens sensíveis
    try:
        detector_tokens.iniciar_monitoramento_assincrono()
    except Exception as e:
        print(f"⚠️ Erro ao iniciar monitoramento assíncrono de tokens: {e}")
        
    # Inicializa watchdog para FIM baseado em eventos
    observer = Observer()
    handler = FIMHandler()
    diretorios_registrados = 0
    for diretorio in config.DIRETORIOS_MONITORADOS:
        if os.path.exists(diretorio):
            try:
                observer.schedule(handler, path=diretorio, recursive=True)
                diretorios_registrados += 1
            except Exception as e:
                print(f"⚠️ Erro ao registrar watchdog para {diretorio}: {e}")
    if diretorios_registrados > 0:
        observer.start()
        print(f"👁️  Watchdog iniciado para FIM em {diretorios_registrados} diretório(s)!")

    # Agendamentos periódicos
    schedule.every(1).minutes.do(verificar_sistema)
    schedule.every().day.at("23:59").do(gerar_relatorio)
    
    # Executa verificação inicial
    verificar_sistema()

    try:
        while True:
            schedule.run_pending()
            time.sleep(10)
    except KeyboardInterrupt:
        print("\n🛑 Agente encerrado.")
        gerar_relatorio()
    except Exception as e:
        print(f"❌ Erro no loop do agente: {e}")
    finally:
        if diretorios_registrados > 0:
            observer.stop()
            observer.join()
