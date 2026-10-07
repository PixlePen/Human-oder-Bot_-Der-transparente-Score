# Human Check Flask Experiment

Dateien:

- `human-check-flask-app.py` - die verbesserte Flask-App
- `requirements-human-check.txt` - Python-Abhängigkeiten

Start lokal:

```bash
python3 -m venv .venv-human-check
. .venv-human-check/bin/activate
pip install -r requirements-human-check.txt
python human-check-flask-app.py
```

Dann öffnen:

```text
https://127.0.0.1:8080/test
```

Wichtig:

- Das ist kein perfekter Mensch-vs-Bot-Beweis, sondern ein Human-Likelihood-Score.
- Öffentlich besser hinter Apache/Nginx/Caddy mit echtem TLS betreiben; `ssl_context='adhoc'` ist nur Testbetrieb.
- `/metrics` ist nur zum Debuggen gedacht und sollte öffentlich nicht ohne Auth erreichbar sein.
- Wenn die App hinter einem Reverse Proxy läuft, `client_ip()` bewusst anpassen und Forwarded-Header nicht blind vertrauen.
