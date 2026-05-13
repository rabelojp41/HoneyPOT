"""
HTTP Honeypot — simula um WordPress vulnerável.
Registra todas as requisições em JSON compatível com o formato Cowrie.
"""

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

LOG_DIR  = Path(os.environ.get("LOG_DIR", "/logs"))
LOG_FILE = LOG_DIR / "http-honeypot.json"
SERVER_IP = os.environ.get("SERVER_IP", "10.0.0.1")

# ──────────────────────────────────────────────
# Logger
# ──────────────────────────────────────────────

def log_event(eventid: str, extra: dict = None):
    entry = {
        "eventid"   : eventid,
        "timestamp" : datetime.now(timezone.utc).isoformat(),
        "src_ip"    : request.headers.get("X-Forwarded-For", request.remote_addr),
        "user_agent": request.headers.get("User-Agent", ""),
        "method"    : request.method,
        "path"      : request.full_path if request.query_string else request.path,
        "session"   : str(uuid.uuid4()),
    }
    if extra:
        entry.update(extra)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # não deixa o honeypot cair por erro de log


# ──────────────────────────────────────────────
# Rotas
# ──────────────────────────────────────────────

@app.route("/")
def index():
    log_event("http.request")
    return render_template("index.html", server_ip=SERVER_IP)


@app.route("/wp-login.php", methods=["GET", "POST"])
@app.route("/wp-admin", methods=["GET", "POST"])
@app.route("/wp-admin/", methods=["GET", "POST"])
def wp_login():
    error = None
    if request.method == "POST":
        username = request.form.get("log", "")
        password = request.form.get("pwd", "")

        if username == "admin" and password == "admin":
            # Login bem-sucedido — loga e mostra o dashboard falso
            log_event("http.login.success", {
                "username": username,
                "password": password,
                "note": "attacker logged in with default credentials",
            })
            return render_template("wp-admin-dashboard.html", server_ip=SERVER_IP)

        # Qualquer outra credencial — nega e registra
        log_event("http.login.attempt", {
            "username": username,
            "password": password,
        })
        error = "<strong>ERRO</strong>: Senha incorreta para o usuário."

    log_event("http.request")
    return render_template("wp-login.html", error=error, server_ip=SERVER_IP)


@app.route("/wp-admin/dashboard")
@app.route("/wp-admin/admin.php")
def wp_admin_dashboard():
    log_event("http.request")
    return render_template("wp-admin-dashboard.html", server_ip=SERVER_IP)


@app.route("/server-info.php")
@app.route("/info.php")
@app.route("/phpinfo.php")
def server_info():
    log_event("http.sensitive.access", {"note": "attacker accessed exposed server info page"})
    return render_template("server-info.html", server_ip=SERVER_IP)


@app.route("/phpmyadmin", methods=["GET", "POST"])
@app.route("/phpmyadmin/", methods=["GET", "POST"])
@app.route("/pma", methods=["GET", "POST"])
def phpmyadmin():
    log_event("http.request", {"note": "phpmyadmin probe"})
    return render_template("wp-login.html", error=None, server_ip=SERVER_IP)


# Captura qualquer rota não mapeada — registra scanners
@app.errorhandler(404)
def not_found(e):
    log_event("http.probe.404")
    return render_template("index.html", server_ip=SERVER_IP), 404


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=False)
