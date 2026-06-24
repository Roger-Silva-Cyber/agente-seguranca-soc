import os
import re
import datetime
from sqlalchemy.orm import Session
from banco import PadraoCliente, Evento, IPMalicioso

def aprender_padrao(db: Session, cliente_id: int, metricas: dict):
    """
    Salva/atualiza no banco a média histórica de CPU, RAM e conexões do cliente.
    Usa média móvel simples — não substitui, acumula.
    """
    # Conta eventos salvos para servir de peso (n)
    n = db.query(Evento).filter(Evento.cliente_id == cliente_id).count()
    # Se n for 0, consideramos o peso inicial como 1
    if n == 0:
        n = 1
        
    for chave_metrica in ['cpu', 'ram', 'conexoes']:
        valor_atual = float(metricas.get(chave_metrica, 0.0))
        chave_registro = f"{chave_metrica}_avg"
        
        # Busca se já existe um padrão armazenado
        padrao = db.query(PadraoCliente).filter(
            PadraoCliente.cliente_id == cliente_id,
            PadraoCliente.chave == chave_registro
        ).first()
        
        if not padrao:
            # Primeiro registro do cliente para esta métrica
            nova_media = valor_atual
            padrao = PadraoCliente(
                cliente_id=cliente_id,
                chave=chave_registro,
                valor=str(nova_media)
            )
            db.add(padrao)
        else:
            # Atualiza média acumulada
            media_anterior = float(padrao.valor)
            nova_media = (media_anterior * (n - 1) + valor_atual) / n
            padrao.valor = str(nova_media)
            
    db.commit()


def detectar_anomalia(db: Session, cliente_id: int, metricas: dict):
    """
    Compara métricas atuais com padrão aprendido.
    Conexões > média × 2 → anomalia
    CPU > média × 3 → anomalia
    Retorna lista de anomalias com descrição.
    """
    anomalias = []
    
    # Busca as médias históricas registradas
    cpu_avg_padrao = db.query(PadraoCliente).filter(
        PadraoCliente.cliente_id == cliente_id,
        PadraoCliente.chave == "cpu_avg"
    ).first()
    conexoes_avg_padrao = db.query(PadraoCliente).filter(
        PadraoCliente.cliente_id == cliente_id,
        PadraoCliente.chave == "conexoes_avg"
    ).first()
    
    cpu_atual = float(metricas.get('cpu', 0.0))
    conexoes_atual = float(metricas.get('conexoes', 0.0))
    
    if cpu_avg_padrao:
        cpu_media = float(cpu_avg_padrao.valor)
        # Regra: CPU > média × 3
        if cpu_atual > (cpu_media * 3) and cpu_media > 0:
            anomalias.append(f"Uso de CPU anômalo: {cpu_atual}% (Média histórica: {cpu_media:.2f}%)")
            
    if conexoes_avg_padrao:
        conexoes_media = float(conexoes_avg_padrao.valor)
        # Regra: Conexões > média × 2
        if conexoes_atual > (conexoes_media * 2) and conexoes_media > 0:
            anomalias.append(f"Número de conexões de rede anômalo: {conexoes_atual} (Média histórica: {conexoes_media:.2f})")
            
    return anomalias


def registrar_ip_malicioso(db: Session, ip: str, cliente_id: int):
    """
    Salva ou atualiza o IP malicioso no banco de dados.
    Se o mesmo IP foi visto em 3+ clientes diferentes → marca como ameaça coletiva confirmada.
    Retorna se é ameaça coletiva (bool).
    """
    ip_reg = db.query(IPMalicioso).filter(IPMalicioso.ip == ip).first()
    
    if not ip_reg:
        # Primeiro registro do IP
        ip_reg = IPMalicioso(
            ip=ip,
            total_deteccoes=1,
            clientes_afetados=[cliente_id],
            primeiro_visto=datetime.datetime.utcnow(),
            ultimo_visto=datetime.datetime.utcnow()
        )
        db.add(ip_reg)
        db.commit()
        return False
    else:
        # IP já existente - incrementa contagem
        ip_reg.total_deteccoes += 1
        afetados = list(ip_reg.clientes_afetados)
        if cliente_id not in afetados:
            afetados.append(cliente_id)
            ip_reg.clientes_afetados = afetados
        ip_reg.ultimo_visto = datetime.datetime.utcnow()
        db.commit()
        
        # Ameaça coletiva se visto em 3 ou mais clientes diferentes
        return len(afetados) >= 3


def extrair_ips(alertas: list):
    """
    Função auxiliar para pescar padrões IPv4 válidos nos dicionários ou strings de alertas.
    """
    alertas_normalizados = [
        a if isinstance(a, dict) else {"tipo": "generico", "mensagem": a}
        for a in alertas
    ]
    ips = set()
    ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    for alerta in alertas_normalizados:
        if isinstance(alerta, dict):
            # Tenta ler a chave de detalhes
            detalhes = alerta.get('detalhes', {})
            ip_det = detalhes.get('ip')
            if ip_det:
                ips.add(str(ip_det))
            # Tenta buscar regex na mensagem
            msg = alerta.get('mensagem', '')
            for ip in re.findall(ip_regex, msg):
                ips.add(ip)
        elif isinstance(alerta, str):
            for ip in re.findall(ip_regex, alerta):
                ips.add(ip)
    return list(ips)


def consultar_ameacas_coletivas(db: Session, alertas: list):
    """
    Extrai IPs dos alertas, consulta o banco e retorna uma lista contendo
    quais desses IPs são ameaças coletivas e a quantidade de clientes afetados.
    """
    alertas_normalizados = [
        a if isinstance(a, dict) else {"tipo": "generico", "mensagem": a}
        for a in alertas
    ]
    ips = extrair_ips(alertas_normalizados)
    resultados = []
    
    for ip in ips:
        ip_reg = db.query(IPMalicioso).filter(IPMalicioso.ip == ip).first()
        if ip_reg:
            afetados = ip_reg.clientes_afetados
            resultados.append({
                "ip": ip,
                "clientes_afetados_count": len(afetados),
                "ameaca_coletiva": len(afetados) >= 3
            })
            
    return resultados
    
OBSIDIAN_VAULT_PATH = os.getenv("OBSIDIAN_VAULT_PATH", "")