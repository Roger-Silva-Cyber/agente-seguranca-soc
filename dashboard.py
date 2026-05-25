from flask import Flask, jsonify, render_template_string
import json
import os
import psutil
import datetime
import config

app = Flask(__name__)

HTML = '''
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ SOC Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', sans-serif; }
        header { background: #161b22; padding: 20px 40px; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 12px; }
        header h1 { font-size: 1.4rem; color: #58a6ff; }
        header span { font-size: 0.8rem; color: #8b949e; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; padding: 24px 40px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 20px; }
        .card h3 { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; margin-bottom: 8px; }
        .card .valor { font-size: 2rem; font-weight: bold; }
        .card .sub { font-size: 0.75rem; color: #8b949e; margin-top: 4px; }
        .verde { color: #3fb950; }
        .amarelo { color: #d29922; }
        .vermelho { color: #f85149; }
        .azul { color: #58a6ff; }
        .section { padding: 0 40px 24px; }
        .section h2 { font-size: 1rem; color: #8b949e; margin-bottom: 12px; text-transform: uppercase; }
        .alerta { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px 18px; margin-bottom: 8px; display: flex; align-items: flex-start; gap: 12px; }
        .alerta.critico { border-left: 3px solid #f85149; }
        .alerta.alto { border-left: 3px solid #d29922; }
        .alerta.medio { border-left: 3px solid #58a6ff; }
        .alerta.baixo { border-left: 3px solid #3fb950; }
        .alerta .hora { font-size: 0.75rem; color: #8b949e; min-width: 60px; }
        .alerta .texto { font-size: 0.85rem; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: 0.7rem; font-weight: bold; margin-left: 8px; }
        .badge.critico { background: #f8514922; color: #f85149; }
        .badge.alto { background: #d2992222; color: #d29922; }
        .badge.medio { background: #58a6ff22; color: #58a6ff; }
        .badge.baixo { background: #3fb95022; color: #3fb950; }
        .barra-bg { background: #21262d; border-radius: 4px; height: 6px; margin-top: 8px; }
        .barra { height: 6px; border-radius: 4px; transition: width 0.5s; }
        .normal { color: #3fb950; font-size: 0.9rem; padding: 20px; text-align: center; }
        footer { text-align: center; padding: 20px; color: #8b949e; font-size: 0.75rem; border-top: 1px solid #30363d; margin-top: 20px; }
    </style>
</head>
<body>
    <header>
        <span style="font-size:1.5rem">🛡️</span>
        <div>
            <h1>SOC Dashboard</h1>
            <span id="ultima-atualizacao">Carregando...</span>
        </div>
    </header>

    <div class="grid">
        <div class="card">
            <h3>CPU</h3>
            <div class="valor" id="cpu-val">--</div>
            <div class="sub">Utilização atual</div>
            <div class="barra-bg"><div class="barra verde" id="cpu-barra" style="width:0%"></div></div>
        </div>
        <div class="card">
            <h3>RAM</h3>
            <div class="valor" id="ram-val">--</div>
            <div class="sub">Utilização atual</div>
            <div class="barra-bg"><div class="barra azul" id="ram-barra" style="width:0%"></div></div>
        </div>
        <div class="card">
            <h3>Conexões</h3>
            <div class="valor azul" id="con-val">--</div>
            <div class="sub">Ativas agora</div>
        </div>
        <div class="card">
            <h3>Arquivos monitorados</h3>
            <div class="valor azul" id="arq-val">--</div>
            <div class="sub">No baseline</div>
        </div>
        <div class="card">
            <h3>Alertas hoje</h3>
            <div class="valor" id="alertas-val">--</div>
            <div class="sub">Eventos detectados</div>
        </div>
        <div class="card">
            <h3>Status</h3>
            <div class="valor verde" id="status-val">--</div>
            <div class="sub">Sistema</div>
        </div>
    </div>

    <div class="section">
        <h2>Alertas recentes</h2>
        <div id="alertas-lista"></div>
    </div>

    <footer>Agente de Segurança SOC — Roger Silva | Atualiza a cada 10 segundos</footer>

    <script>
        async function atualizar() {
            try {
                const r = await fetch('/api/status');
                const d = await r.json();

                document.getElementById('cpu-val').textContent = d.cpu + '%';
                document.getElementById('cpu-val').className = 'valor ' + (d.cpu > 80 ? 'vermelho' : d.cpu > 60 ? 'amarelo' : 'verde');
                document.getElementById('cpu-barra').style.width = d.cpu + '%';
                document.getElementById('cpu-barra').className = 'barra ' + (d.cpu > 80 ? 'vermelho' : d.cpu > 60 ? 'amarelo' : 'verde');

                document.getElementById('ram-val').textContent = d.ram + '%';
                document.getElementById('ram-val').className = 'valor ' + (d.ram > 85 ? 'vermelho' : d.ram > 70 ? 'amarelo' : 'verde');
                document.getElementById('ram-barra').style.width = d.ram + '%';

                document.getElementById('con-val').textContent = d.conexoes;
                document.getElementById('arq-val').textContent = d.arquivos_monitorados;
                document.getElementById('alertas-val').textContent = d.total_alertas_hoje;
                document.getElementById('alertas-val').className = 'valor ' + (d.total_alertas_hoje > 0 ? 'vermelho' : 'verde');
                document.getElementById('status-val').textContent = d.status;
                document.getElementById('status-val').className = 'valor ' + (d.status === 'Normal' ? 'verde' : 'vermelho');
                document.getElementById('ultima-atualizacao').textContent = 'Última atualização: ' + d.hora;

                const lista = document.getElementById('alertas-lista');
                if (d.eventos.length === 0) {
                    lista.innerHTML = '<div class="normal">✅ Nenhum alerta detectado hoje</div>';
                } else {
                    lista.innerHTML = d.eventos.slice().reverse().map(e => {
                        const nivel = e.risco ? e.risco.toLowerCase() : 'baixo';
                        const alertasTexto = Array.isArray(e.alertas) ? e.alertas.join('<br>') : e.alertas;
                        return `
                        <div class="alerta ${nivel}">
                            <span class="hora">${e.hora}</span>
                            <div class="texto">
                                <span class="badge ${nivel}">${e.risco || 'INFO'}</span>
                                <br><br>${alertasTexto}
                                <br><br><small style="color:#8b949e">${e.analise || ''}</small>
                            </div>
                        </div>`;
                    }).join('');
                }
            } catch(e) {
                console.error(e);
            }
        }

        atualizar();
        setInterval(atualizar, 10000);
    </script>
</body>
</html>
'''

eventos_compartilhados = []
baseline_count = 0

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/status')
def status():
    cpu = psutil.cpu_percent(interval=0.1)
    ram = psutil.virtual_memory().percent
    conexoes = len(psutil.net_connections())
    hora = datetime.datetime.now().strftime("%H:%M:%S")
    tem_alerta = len(eventos_compartilhados) > 0
    return jsonify({
        'cpu': cpu,
        'ram': ram,
        'conexoes': conexoes,
        'arquivos_monitorados': baseline_count,
        'total_alertas_hoje': len(eventos_compartilhados),
        'status': 'Alerta' if tem_alerta else 'Normal',
        'hora': hora,
        'eventos': eventos_compartilhados[-20:]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
