import os
import datetime
import json
import httpx
from fastapi import FastAPI, Depends, HTTPException, Security, Header, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List

import config
import banco
import auth
import models
import cerebro
import cerebro_ti




app = FastAPI(title="🛡️ SOC Central API", version="1.0.0")

# Inicializa o banco de dados e as tabelas na inicialização da aplicação



@app.on_event("startup")
def startup_event():
    banco.inicializar_banco()


# --- ROTAS DA API ---

@app.post("/cliente/registrar")
def registrar_cliente(entrada: models.RegistrarClienteEntrada, db: Session = Depends(auth.obter_db)):
    """
    Cadastra um novo cliente/host no banco de dados e gera seu token Bearer único.
    """
    token_gerado = auth.gerar_token_cliente()
    novo_cliente = banco.Cliente(
        nome=entrada.nome,
        token=token_gerado,
        ativo=True
    )
    db.add(novo_cliente)
    db.commit()
    db.refresh(novo_cliente)
    
    print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] NOVO CLIENTE REGISTRADO: {entrada.nome} (ID: {novo_cliente.id})")
    
    return {
        "token": token_gerado,
        "cliente_id": novo_cliente.id
    }


@app.post("/analisar", response_model=models.RespostaAnalise)
async def analisar_evento(
    evento: models.EventoEntrada, 
    cliente: banco.Cliente = Depends(auth.validar_token_cliente), 
    db: Session = Depends(auth.obter_db)
):
    """
    Recebe as métricas e alertas de um agente local, realiza detecção de anomalias no cérebro central,
    consulta reputação de novos IPs no OTX, categoriza o risco via Groq e retorna as ações recomendadas.
    """
    cliente_id = cliente.id
    
    # Garante a normalização automática dos alertas de strings para dicionários
    alertas_normalizados = [
        a if isinstance(a, dict) else {"tipo": "generico", "mensagem": a}
        for a in evento.alertas
    ]
    
    # 1. Salva o evento bruto/normalizado no banco de dados
    evento_db = banco.Evento(
        cliente_id=cliente_id,
        hora=evento.hora,
        alertas=alertas_normalizados,
        risco="PROCESSANDO",
        analise="",
        acoes=[]
    )
    db.add(evento_db)
    db.commit()
    db.refresh(evento_db)
    
    # 2. Executa o aprendizado de baseline no cérebro central
    cerebro.aprender_padrao(db, cliente_id, evento.metricas)
    
    # 3. Detecta anomalias comparando métricas atuais com baseline
    anomalias = cerebro.detectar_anomalia(db, cliente_id, evento.metricas)
    
    # 4. Registra IPs vistos nos alertas e verifica ameaças coletivas
    ips_extraidos = cerebro.extrair_ips(alertas_normalizados)
    for ip in ips_extraidos:
        cerebro.registrar_ip_malicioso(db, ip, cliente_id)
        
    ameacas_coletivas = cerebro.consultar_ameacas_coletivas(db, alertas_normalizados)
    
    # --- INTEGRAÇÃO OTX ALIENVAULT (ASYNCHRONOUS HTTPX) ---
    otx_alertas_extras = []
    async with httpx.AsyncClient() as client:
        for ip in ips_extraidos:
            try:
                # Timeout de 10s configurado conforme requisitos
                otx_resp = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                    headers={"X-OTX-API-KEY": config.OTX_API_KEY},
                    timeout=10.0
                )
                if otx_resp.status_code == 200:
                    dados = otx_resp.json()
                    pulsos_count = dados.get('pulse_info', {}).get('count', 0)
                    reputacao = dados.get('reputation', 0)
                    if pulsos_count > 0:
                        otx_alertas_extras.append(f"OTX confirmou IP malicioso: {ip} ({pulsos_count} pulses)")
                    elif reputacao < -1:
                        otx_alertas_extras.append(f"OTX indicou reputação negativa para {ip}: {reputacao}")
            except Exception as e:
                # Tolerância a falhas na API do OTX
                print(f"⚠️ Erro ao consultar OTX em soc-central para {ip}: {e}")

    # --- PROCESSAMENTO E DECISÃO LOCAL (FALLBACK DO CÉREBRO) ---
    local_risco = "BAIXO"
    local_acoes = []
    
    if anomalias:
        local_risco = "MÉDIO"
        local_acoes.append("Investigar processo consumindo CPU ou criando conexões anômalas.")
        
    for ac in ameacas_coletivas:
        if ac.get("ameaca_coletiva"):
            local_risco = "CRÍTICO"
            local_acoes.append(f"Bloquear IP de Ameaça Coletiva confirmada no firewall: {ac['ip']}")
        else:
            local_risco = "ALTO"
            local_acoes.append(f"Suspender temporariamente conexões externas para o IP suspeito: {ac['ip']}")
            
    if otx_alertas_extras:
        local_risco = "ALTO"
        local_acoes.append("IP suspeito confirmado via consulta reputacional OTX.")
        
    local_analise = (
        f"Anomalias Locais: {anomalias if anomalias else 'Nenhuma'}.\n"
        f"Ameaças Coletivas: {ameacas_coletivas if ameacas_coletivas else 'Nenhuma'}.\n"
        f"OTX Status: {otx_alertas_extras if otx_alertas_extras else 'Sem novas informações'}."
    )

    # --- INTEGRAÇÃO GROQ IA (ASYNCHRONOUS HTTPX) ---
    risco_final = local_risco
    analise_final = local_analise
    acoes_finais = local_acoes
    
    # 1. Consulta base local de Threat Intelligence
    print(f"[TI] Consultando base local para {len(ips_extraidos)} IPs: {ips_extraidos}")
    contexto_ti = ""
    cerebro_ti.reset_stats()
    for ip in ips_extraidos:
        alerta_ip = None
        for alerta in alertas_normalizados:
            if isinstance(alerta, dict) and (alerta.get('detalhes', {}).get('ip') == ip or ip in alerta.get('mensagem', '')):
                alerta_ip = alerta
                break
        
        processo = None
        pid = None
        risco = None
        porta = None
        if alerta_ip:
            det = alerta_ip.get('detalhes', {})
            processo = det.get('processo')
            pid = det.get('pid')
            risco = det.get('risco') or ("CRÍTICO" if local_risco == "CRÍTICO" else "ALTO")
            for conn in evento.metricas.get('conexoes_externas', []):
                if conn.get('ip') == ip:
                    porta = conn.get('porta')
                    break
        if not porta:
            porta = "443"
        
        resultado_ti = await cerebro_ti.consultar_base_local(
            ip,
            processo=processo,
            pid=str(pid) if pid else None,
            risco=risco,
            porta=str(porta) if porta else None
        )
        print(f"[TI] Resultado para {ip}: {len(resultado_ti)} chars")
        contexto_ti += resultado_ti

    # Constrói prompt completo enviando todo o contexto do cérebro
    prompt = f"""
Você é o cérebro de análise de IA central do EDR/HIDS do SOC.
Analise os dados de segurança do host (ID: {cliente_id}, SO: {evento.os}) e tome uma decisão.

CONTEXTO DE THREAT INTELLIGENCE DA BASE DE CONHECIMENTO:
{contexto_ti}

ALERTAS DO AGENTE:
{alertas_normalizados}

DADOS DE RECURSOS DO HOST:
- CPU: {evento.metricas.get('cpu')}%
- RAM: {evento.metricas.get('ram')}%
- Conexões Ativas: {evento.metricas.get('conexoes')}

ANOMALIAS DETECTADAS PELO CÉREBRO CENTRAL:
{anomalias}

AMEAÇAS COLETIVAS E OTX:
{ameacas_coletivas}
{otx_alertas_extras}

Responda exatamente neste formato:
RISCO: [BAIXO/MÉDIO/ALTO/CRÍTICO]
SITUAÇÃO: [descrição resumida em 2 linhas]
AÇÃO: [ação imediata a ser tomada]
"""
    # Tenta Ollama local (assíncrono) com timeout de 60 segundos
    conteudo = None
    try:
        ollama_url_env = os.getenv("OLLAMA_URL", "http://localhost:11434")
        if "v1/chat/completions" not in ollama_url_env:
            ollama_url = f"{ollama_url_env.rstrip('/')}/v1/chat/completions"
        else:
            ollama_url = ollama_url_env
            
        async with httpx.AsyncClient() as client:
            resp_ia = await client.post(
                ollama_url,
                json={
                    "model": os.getenv("OLLAMA_MODEL", "llama3.1"),
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False
                },
                timeout=60.0
            )
            if resp_ia.status_code == 200:
                conteudo = resp_ia.json()['choices'][0]['message']['content']
    except Exception as e:
        print(f"⚠️ Ollama local indisponível em soc-central: {e}. Tentando Groq como fallback.")

    # Fallback para Groq se o Ollama falhar/não estiver disponível
    if conteudo is None:
        if config.GROQ_API_KEY and config.GROQ_API_KEY != "sua_chave_groq":
            try:
                async with httpx.AsyncClient() as client:
                    resp_ia = await client.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {config.GROQ_API_KEY}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "model": "llama-3.3-70b-versatile",
                            "messages": [{"role": "user", "content": prompt}],
                            "max_tokens": 400
                        },
                        timeout=10.0
                    )
                    if resp_ia.status_code == 200:
                        conteudo = resp_ia.json()['choices'][0]['message']['content']
            except Exception as e:
                print(f"⚠️ Erro ao consultar Groq em soc-central: {e}.")
        else:
            print("⚠️ Groq não configurado como fallback.")

    if conteudo:
        # Faz o parse da resposta
        for linha in conteudo.split('\n'):
            if 'RISCO:' in linha:
                if 'CRÍTICO' in linha or 'CRITICO' in linha:
                    risco_final = 'CRÍTICO'
                elif 'ALTO' in linha:
                    risco_final = 'ALTO'
                elif 'MÉDIO' in linha or 'MEDIO' in linha:
                    risco_final = 'MÉDIO'
                else:
                    risco_final = 'BAIXO'
                    
        analise_final = conteudo
        # Se risco for alto/crítico, adiciona ações adicionais recomendadas pela IA
        acoes_finais = list(set(local_acoes + [f"Recomendação IA: {linha.split('AÇÃO:')[-1].strip()}" for linha in conteudo.split('\n') if 'AÇÃO:' in linha]))
    else:
        print("⚠️ IA (Ollama e Groq) indisponível. Utilizando decisão local.")

    # 5. Atualiza o registro do evento no banco de dados com a análise conclusiva
    evento_db.risco = risco_final
    evento_db.analise = analise_final
    evento_db.acoes = acoes_finais
    db.commit()

    # 6. Log de rastreamento com data, hora, cliente_id e risco retornado
    print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] CLIENTE_ID: {cliente_id} | RISCO: {risco_final}")

    resultado = {
        "risco": risco_final,
        "analise": analise_final,
        "acoes": acoes_finais,
        "ameacas_coletivas": ameacas_coletivas
    }
    return JSONResponse(content=resultado, media_type="application/json; charset=utf-8")


@app.get("/status")
def obter_status_cliente(cliente: banco.Cliente = Depends(auth.validar_token_cliente), db: Session = Depends(auth.obter_db)):
    """
    Retorna os últimos 20 eventos de segurança registrados para o cliente solicitante.
    """
    eventos = db.query(banco.Evento).filter(
        banco.Evento.cliente_id == cliente.id
    ).order_by(banco.Evento.id.desc()).limit(20).all()
    
    resumos = []
    for ev in eventos:
        resumos.append({
            "id": ev.id,
            "hora": ev.hora,
            "alertas": ev.alertas,
            "risco": ev.risco,
            "analise": ev.analise,
            "acoes": ev.acoes
        })
    return JSONResponse(content=resumos, media_type="application/json; charset=utf-8")


@app.get("/admin/clientes")
def obter_clientes_admin(admin_token: str = Depends(auth.validar_admin_token), db: Session = Depends(auth.obter_db)):
    """
    Rota administrativa protegida que lista todos os hosts cadastrados, a contagem de eventos
    de cada um e o risco do último evento reportado.
    """
    clientes = db.query(banco.Cliente).all()
    lista_retorno = []
    for c in clientes:
        total_eventos = db.query(banco.Evento).filter(banco.Evento.cliente_id == c.id).count()
        ultimo_evento = db.query(banco.Evento).filter(
            banco.Evento.cliente_id == c.id
        ).order_by(banco.Evento.id.desc()).first()
        
        lista_retorno.append({
            "cliente_id": c.id,
            "nome": c.nome,
            "ativo": c.ativo,
            "criado_em": c.criado_em,
            "total_eventos": total_eventos,
            "ultimo_risco_detectado": ultimo_evento.risco if ultimo_evento else "N/A"
        })
    return lista_retorno
