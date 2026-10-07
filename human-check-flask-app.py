#!/usr/bin/env python3
"""
Human-likelihood test for small experiments.

This is not a perfect bot detector. It combines several weak signals:
- signed one-time challenge token
- per-session cookie
- honeypot field
- minimum/maximum response time
- simple semantic question
- request/header/timing logging

Run:
    python3 human-check-flask-app.py

Open:
    https://127.0.0.1:8080/test

For public use, put it behind Apache/Nginx/Caddy TLS instead of Flask's
adhoc certificate.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from flask import Flask, jsonify, make_response, redirect, render_template_string, request, url_for
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

app = Flask(__name__)

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("HUMAN_CHECK_DB", APP_DIR / "human-check.sqlite3"))
LOG_PATH = Path(os.environ.get("HUMAN_CHECK_LOG", APP_DIR / "human-check.jsonl"))
SECRET_KEY = os.environ.get("HUMAN_CHECK_SECRET") or secrets.token_hex(32)
COOKIE_NAME = "hc_session"
TOKEN_TTL_SECONDS = 10 * 60
MIN_SOLVE_SECONDS = 2.0
MAX_SOLVE_SECONDS = 180.0

QUESTIONS = [
    {
        "id": "odd_it_word",
        "question": "Welches Wort passt nicht in die Reihe?",
        "options": ["Router", "Switch", "Firewall", "Banane"],
        "answer": "Banane",
    },
    {
        "id": "admin_context",
        "question": "Welche Handlung klingt am ehesten nach sicherem Admin-Alltag?",
        "options": [
            "Erst Backup prüfen, dann Änderung durchführen",
            "Firewall-Regeln blind löschen",
            "Produktivserver ohne Plan neu installieren",
            "Passwörter in eine öffentliche Webseite schreiben",
        ],
        "answer": "Erst Backup prüfen, dann Änderung durchführen",
    },
    {
        "id": "not_protocol",
        "question": "Was ist kein typisches Netzwerkprotokoll?",
        "options": ["DNS", "HTTP", "SSH", "Kaffee"],
        "answer": "Kaffee",
    },
]


@dataclass
class Verdict:
    classification: str
    score: int
    max_score: int
    reasons: list[str]
    signals: dict[str, Any]


def now() -> float:
    return time.time()


def client_ip() -> str:
    # Trust only the direct peer by default. If you deploy behind a trusted
    # reverse proxy, configure that proxy and adapt this function deliberately.
    return request.remote_addr or "unknown"


def ensure_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS challenges (
                token TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                question_id TEXT NOT NULL,
                answer_hash TEXT NOT NULL,
                issued_at REAL NOT NULL,
                used_at REAL,
                ip TEXT,
                user_agent TEXT
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                session_id TEXT,
                ip TEXT,
                path TEXT,
                method TEXT,
                user_agent TEXT,
                data TEXT
            )
            """
        )


def log_event(path: str, session_id: str | None, data: dict[str, Any]) -> None:
    ensure_db()
    event = {
        "created_at": now(),
        "session_id": session_id,
        "ip": client_ip(),
        "path": path,
        "method": request.method,
        "user_agent": request.headers.get("User-Agent", ""),
        "data": data,
    }
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            """
            INSERT INTO requests (created_at, session_id, ip, path, method, user_agent, data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["created_at"],
                session_id,
                event["ip"],
                event["path"],
                event["method"],
                event["user_agent"],
                json.dumps(data, ensure_ascii=False, sort_keys=True),
            ),
        )
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


def answer_hash(answer: str) -> str:
    return hashlib.sha256(answer.strip().casefold().encode("utf-8")).hexdigest()


def sign(value: str) -> str:
    return hmac.new(SECRET_KEY.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def signed_session_cookie(raw: str) -> str:
    return f"{raw}.{sign(raw)}"


def verify_session_cookie(cookie: str | None) -> str | None:
    if not cookie or "." not in cookie:
        return None
    raw, sig = cookie.rsplit(".", 1)
    if hmac.compare_digest(sign(raw), sig):
        return raw
    return None


def get_or_create_session_id() -> tuple[str, bool]:
    existing = verify_session_cookie(request.cookies.get(COOKIE_NAME))
    if existing:
        return existing, False
    return secrets.token_urlsafe(24), True


def create_challenge(session_id: str) -> dict[str, Any]:
    ensure_db()
    q = secrets.choice(QUESTIONS)
    token = secrets.token_urlsafe(32)
    issued_at = now()
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            """
            INSERT INTO challenges (token, session_id, question_id, answer_hash, issued_at, ip, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token,
                session_id,
                q["id"],
                answer_hash(q["answer"]),
                issued_at,
                client_ip(),
                request.headers.get("User-Agent", ""),
            ),
        )
    return {
        "token": token,
        "issued_at": issued_at,
        "question": q["question"],
        "options": q["options"],
    }


def fetch_challenge(token: str) -> dict[str, Any] | None:
    ensure_db()
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        row = con.execute("SELECT * FROM challenges WHERE token = ?", (token,)).fetchone()
    return dict(row) if row else None


def mark_used(token: str) -> None:
    with sqlite3.connect(DB_PATH) as con:
        con.execute("UPDATE challenges SET used_at = ? WHERE token = ?", (now(), token))


def classify(score: int) -> str:
    if score >= 6:
        return "human-likely"
    if score >= 3:
        return "unclear"
    return "automation-likely"


def score_submission(session_id: str, form: dict[str, str]) -> Verdict:
    score = 0
    max_score = 8
    reasons: list[str] = []
    signals: dict[str, Any] = {}

    token = form.get("token", "")
    answer = form.get("answer", "")
    honeypot = form.get("website", "")
    loaded_at_raw = form.get("loaded_at", "0")

    challenge = fetch_challenge(token)
    if not challenge:
        reasons.append("token fehlt oder unbekannt")
        return Verdict("automation-likely", 0, max_score, reasons, {"token_known": False})

    elapsed = now() - float(challenge["issued_at"])
    try:
        client_elapsed = now() - float(loaded_at_raw)
    except ValueError:
        client_elapsed = -1

    signals.update(
        {
            "token_known": True,
            "server_elapsed_seconds": round(elapsed, 3),
            "client_elapsed_seconds": round(client_elapsed, 3),
            "ip": client_ip(),
            "issued_ip": challenge.get("ip"),
            "user_agent": request.headers.get("User-Agent", ""),
            "issued_user_agent": challenge.get("user_agent"),
            "honeypot_filled": bool(honeypot.strip()),
            "token_reused": bool(challenge.get("used_at")),
        }
    )

    if challenge["session_id"] == session_id:
        score += 2
        reasons.append("Session passt zum Token")
    else:
        reasons.append("Session passt nicht zum Token")

    if not challenge.get("used_at"):
        score += 1
        reasons.append("Token wurde noch nicht benutzt")
    else:
        score -= 3
        reasons.append("Token wurde wiederverwendet")

    if elapsed <= TOKEN_TTL_SECONDS:
        score += 1
        reasons.append("Token ist nicht abgelaufen")
    else:
        score -= 2
        reasons.append("Token ist abgelaufen")

    if hmac.compare_digest(answer_hash(answer), challenge["answer_hash"]):
        score += 2
        reasons.append("Antwort ist korrekt")
    else:
        score -= 2
        reasons.append("Antwort ist falsch")

    if MIN_SOLVE_SECONDS <= elapsed <= MAX_SOLVE_SECONDS:
        score += 1
        reasons.append("Antwortzeit wirkt plausibel")
    elif elapsed < MIN_SOLVE_SECONDS:
        score -= 2
        reasons.append("Antwort kam auffällig schnell")
    else:
        reasons.append("Antwortzeit ist ungewöhnlich lang")

    if honeypot.strip():
        score -= 3
        reasons.append("Honeypot-Feld wurde ausgefüllt")
    else:
        score += 1
        reasons.append("Honeypot ist leer")

    ua = request.headers.get("User-Agent", "")
    if ua and not any(x in ua.lower() for x in ["curl", "wget", "python-requests", "httpx", "bot", "crawler", "spider"]):
        score += 1
        reasons.append("User-Agent wirkt nicht wie ein einfacher Script-Client")
    else:
        reasons.append("User-Agent wirkt automatisiert oder fehlt")

    mark_used(token)
    score = max(-5, min(score, max_score))
    return Verdict(classify(score), score, max_score, reasons, signals)


HTML = """
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Human Check Experiment</title>
  <style>
    :root { color-scheme: dark; --bg:#06100c; --panel:#0d1b15; --line:#1c3a2d; --text:#e7f4eb; --muted:#9fb6a8; --accent:#7dffb2; --warn:#ffd27d; }
    body { margin:0; min-height:100vh; display:grid; place-items:center; background:radial-gradient(circle at top,#123524,var(--bg)); color:var(--text); font:16px/1.55 system-ui,Segoe UI,sans-serif; }
    main { width:min(760px, calc(100vw - 32px)); background:rgba(13,27,21,.92); border:1px solid var(--line); border-radius:22px; padding:28px; box-shadow:0 20px 80px #0008; }
    h1 { margin:0 0 8px; font-size:clamp(1.6rem,4vw,2.4rem); }
    p { color:var(--muted); }
    fieldset { border:1px solid var(--line); border-radius:16px; padding:16px; margin:18px 0; }
    legend { color:var(--accent); padding:0 8px; }
    label { display:block; padding:10px 0; cursor:pointer; }
    button { background:var(--accent); color:#04100a; border:0; border-radius:999px; padding:12px 18px; font-weight:700; cursor:pointer; }
    button:disabled { opacity:.45; cursor:not-allowed; }
    .hp { position:absolute; left:-10000px; width:1px; height:1px; overflow:hidden; }
    .hint { border-left:3px solid var(--warn); padding-left:12px; }
    code { color:var(--accent); }
  </style>
</head>
<body>
<main>
  <h1>Human Check</h1>
  <p>Ein kleines Experiment: nicht perfekt, aber besser als nur IP, Header und Timing zu loggen.</p>
  <p class="hint">Bitte lies die Frage kurz und antworte bewusst. Der Button wird nach wenigen Sekunden freigegeben.</p>

  <form method="post" action="{{ verify_url }}">
    <input type="hidden" name="token" value="{{ token }}">
    <input type="hidden" name="loaded_at" id="loaded_at" value="">
    <p class="hp"><label>Website <input name="website" autocomplete="off"></label></p>

    <fieldset>
      <legend>{{ question }}</legend>
      {% for option in options %}
        <label><input required type="radio" name="answer" value="{{ option }}"> {{ option }}</label>
      {% endfor %}
    </fieldset>

    <button id="submit" disabled>Antwort prüfen</button>
  </form>

  <p><small>API: <code>POST /verify</code>, Ergebnis als HTML oder JSON per <code>Accept: application/json</code>.</small></p>
</main>
<script>
  document.getElementById('loaded_at').value = String(Date.now() / 1000);
  const btn = document.getElementById('submit');
  setTimeout(() => { btn.disabled = false; }, 2500);
</script>
</body>
</html>
"""

RESULT_HTML = """
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Human Check Ergebnis</title>
  <style>
    :root { color-scheme: dark; --bg:#06100c; --panel:#0d1b15; --line:#1c3a2d; --text:#e7f4eb; --muted:#9fb6a8; --accent:#7dffb2; }
    body { margin:0; min-height:100vh; display:grid; place-items:center; background:var(--bg); color:var(--text); font:16px/1.55 system-ui,Segoe UI,sans-serif; }
    main { width:min(760px, calc(100vw - 32px)); background:var(--panel); border:1px solid var(--line); border-radius:22px; padding:28px; }
    .badge { display:inline-block; padding:6px 10px; border:1px solid var(--line); border-radius:999px; color:var(--accent); }
    pre { white-space:pre-wrap; background:#020806; border:1px solid var(--line); border-radius:14px; padding:14px; overflow:auto; }
    a { color:var(--accent); }
  </style>
</head>
<body>
<main>
  <h1>Ergebnis</h1>
  <p class="badge">{{ verdict.classification }} · {{ verdict.score }}/{{ verdict.max_score }}</p>
  <h2>Gründe</h2>
  <ul>{% for reason in verdict.reasons %}<li>{{ reason }}</li>{% endfor %}</ul>
  <h2>Signale</h2>
  <pre>{{ signals }}</pre>
  <p><a href="{{ test_url }}">Noch einmal testen</a></p>
</main>
</body>
</html>
"""


@app.route("/")
def index():
    return redirect(url_for("test"))


@app.route("/test", methods=["GET"])
def test():
    session_id, is_new = get_or_create_session_id()
    challenge = create_challenge(session_id)
    log_event("/test", session_id, {"new_session": is_new, "token": challenge["token"]})
    response = make_response(
        render_template_string(
            HTML,
            verify_url=url_for("verify"),
            token=challenge["token"],
            question=challenge["question"],
            options=challenge["options"],
        )
    )
    if is_new:
        response.set_cookie(
            COOKIE_NAME,
            signed_session_cookie(session_id),
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=60 * 60,
        )
    return response


@app.route("/verify", methods=["POST"])
def verify():
    session_id, is_new = get_or_create_session_id()
    form = {k: request.form.get(k, "") for k in ["token", "answer", "website", "loaded_at"]}
    verdict = score_submission(session_id, form)
    log_event("/verify", session_id, {"new_session": is_new, "verdict": asdict(verdict)})

    wants_json = "application/json" in request.headers.get("Accept", "")
    if wants_json:
        response = jsonify(asdict(verdict))
    else:
        response = make_response(
            render_template_string(
                RESULT_HTML,
                verdict=verdict,
                signals=json.dumps(verdict.signals, ensure_ascii=False, indent=2, sort_keys=True),
                test_url=url_for("test"),
            )
        )

    if is_new:
        response.set_cookie(
            COOKIE_NAME,
            signed_session_cookie(session_id),
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=60 * 60,
        )
    return response


@app.route("/metrics", methods=["GET"])
def metrics():
    # Simple local debugging endpoint. Do not expose publicly without auth.
    ensure_db()
    limit = min(int(request.args.get("limit", "20")), 100)
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT created_at, session_id, ip, path, method, user_agent, data FROM requests ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    ensure_db()
    print(f"DB:  {DB_PATH}")
    print(f"Log: {LOG_PATH}")
    print("Open: https://127.0.0.1:8080/test")
    app.run(host="0.0.0.0", port=8080, ssl_context="adhoc")
