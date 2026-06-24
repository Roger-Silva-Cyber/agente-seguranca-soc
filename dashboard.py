from flask import Flask, jsonify, render_template
from flask_httpauth import HTTPBasicAuth
import bcrypt
import json
import os
import psutil
import datetime
import sys
from pathlib import Path

import config

app = Flask(__name__)
auth = HTTPBasicAuth()

# Senha padrão: "admin" (armazenada de forma segura como hash bcrypt)
USUARIO_CONFIG = "admin"
SENHA_HASH_CONFIG = b"$2b$12$FgxWj8p.tot/lnBTMwUc5.e.ADwjbZ5x2bCSarKVnlmuGTxU6f1ZK"

@auth.verify_password
def verify_password(username, password):
    if username == USUARIO_CONFIG:
        try:
            return bcrypt.checkpw(password.encode('utf-8'), SENHA_HASH_CONFIG)
        except Exception:
            return False
    return False


@app.route('/')
@auth.login_required
def index():
    return render_template('index.html')


@app.route('/api/status')
@auth.login_required
def status():
    try:
        with open(Path(__file__).parent / "estado.json", "r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    except FileNotFoundError:
        return jsonify({
            "hora": "--",
            "cpu": 0, "ram": 0, "conexoes": 0,
            "arquivos_monitorados": 0,
            "total_alertas_hoje": 0,
            "status": "Aguardando primeiro ciclo...",
            "eventos": []
        })


if __name__ == '__main__':
    # Ligação local segura para evitar conexões remotas arbitrárias
    app.run(host='127.0.0.1', port=5000, debug=False)
