import requests
import config

BASE_URL = "https://otx.alienvault.com/api/v1"
HEADERS = {"X-OTX-API-KEY": config.OTX_API_KEY}

cache_ips = {}

def consultar_ip(ip):
    if ip in cache_ips:
        return cache_ips[ip]

    try:
        url = f"{BASE_URL}/indicators/IPv4/{ip}/general"
        resp = requests.get(url, headers=HEADERS, timeout=5)

        if resp.status_code != 200:
            return None

        dados = resp.json()
        pulsos = dados.get('pulse_info', {})
        total_pulsos = pulsos.get('count', 0)
        nomes_malware = []

        for pulso in pulsos.get('pulses', []):
            nome = pulso.get('name', '')
            if nome:
                nomes_malware.append(nome)

        resultado = {
            'ip': ip,
            'reputacao': dados.get('reputation', 0),
            'total_pulsos': total_pulsos,
            'malwares': nomes_malware[:5],
            'pais': dados.get('country_name', 'Desconhecido')
        }

        cache_ips[ip] = resultado
        return resultado

    except Exception as e:
        return None

def verificar_ips_maliciosos(conexoes_externas):
    alertas = []

    IPS_IGNORADOS = [
        '8.8.8.8', '8.8.4.4',      # Google DNS
        '1.1.1.1', '1.0.0.1',      # Cloudflare DNS
        '104.16.', '104.17.',      # Cloudflare
        '151.101.',                # Fastly CDN
        '140.82.',                 # GitHub
        '34.107.',  		   # Google Cloud legitimo
    	'34.149.',  		   # Google Cloud legitimo

	]

    for conexao in conexoes_externas:
        ip = conexao.get('ip', '')

        if not ip:
            continue

        # Ignora IPs conhecidos e seguros
        ignorar = any(ip.startswith(prefix) for prefix in IPS_IGNORADOS)
        if ignorar:
            continue

        resultado = consultar_ip(ip)

        if not resultado:
            continue

        if resultado['total_pulsos'] > 0:
            malwares = ', '.join(resultado['malwares']) if resultado['malwares'] else 'Desconhecido'
            alertas.append(
                f"🚨 IP MALICIOSO DETECTADO: {ip} ({resultado['pais']}) — "
                f"{resultado['total_pulsos']} ocorrência(s) — "
                f"Associado a: {malwares}"
            )
        elif resultado['reputacao'] < -1:
            alertas.append(
                f"⚠️  IP SUSPEITO: {ip} ({resultado['pais']}) — "
                f"Reputação negativa: {resultado['reputacao']}"
            )

    return alertas
