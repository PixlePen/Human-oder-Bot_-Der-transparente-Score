# Human Check Experiment

Ein kleines Flask-Projekt zur Frage:

> Wenn das Internet immer stärker aus Bots, Scraper-Requests, KI-Agenten und automatisierten Browsern besteht: Wie kann eine Webseite zumindest einschätzen, ob auf der anderen Seite wahrscheinlich ein Mensch sitzt?

Dieses Projekt ist kein CAPTCHA-Ersatz, kein perfekter Bot-Schutz und kein Beweis für Menschlichkeit. Es ist ein bewusst transparentes Experiment: Mehrere schwache Signale werden gesammelt, bewertet und zu einem nachvollziehbaren Score zusammengeführt.

Das Ziel ist nicht, Bots magisch auszusperren. Das Ziel ist, die Illusion eines einfachen Tests zu durchbrechen und zu zeigen, wie viel — und wie wenig — man auf Anwendungsebene erkennen kann.

---

## Grundidee

Der erste naive Ansatz war ein einfacher Flask-Endpunkt, der Requests protokolliert:

- IP-Adresse
- User-Agent
- Header
- Zeitabstand zwischen Requests

Das ist nützlich als Messpunkt, aber nicht als Mensch-vs-Bot-Test. Ein Script kann Header fälschen. Ein Bot kann User-Agent-Werte imitieren. Ein Scraper kann langsam wirken. Und ein echter Mensch kann über Proxy, Mobilfunknetz, VPN oder Privacy-Browser kommen.

Deshalb verfolgt diese Version einen anderen Ansatz:

> Nicht ein einzelnes Signal entscheidet. Mehrere kleine Hinweise ergeben zusammen eine Wahrscheinlichkeit.

Das Ergebnis ist deshalb bewusst kein `human = true`, sondern eine Einordnung:

- `human-likely`
- `unclear`
- `automation-likely`

---

## Was das Projekt macht

Die Anwendung stellt unter `/test` eine kleine Challenge bereit. Ein Besucher erhält eine HTML-Seite mit einer einfachen Multiple-Choice-Frage. Beim Absenden wertet der Server mehrere Signale aus und erstellt daraus ein Verdict.

Die wichtigsten Komponenten:

1. Session-Cookie
2. signierter Challenge-Token
3. Einmalverwendung des Tokens
4. Ablaufzeit der Challenge
5. Mindest- und Maximalzeit für die Antwort
6. Honeypot-Feld
7. einfache semantische Frage
8. User-Agent-Heuristik
9. SQLite-Logging
10. JSONL-Logdatei
11. Debug-Endpunkt `/metrics`

---

## Warum mehrere schwache Signale?

Keines der verwendeten Signale ist alleine zuverlässig.

Ein User-Agent kann gefälscht werden. Ein Cookie kann von einem echten Browser oder einem Headless Browser stammen. Eine Wartezeit kann simuliert werden. Eine Multiple-Choice-Frage kann ein LLM beantworten. Ein Honeypot blockiert nur einfache Formularbots.

Aber kombiniert entsteht ein brauchbarer Reibungstest:

- einfache Skripte scheitern oft an Cookies, Tokens oder Formularstruktur
- cURL-/wget-Requests liefern auffällige Header
- naive Bots füllen versteckte Felder aus
- extrem schnelle Antworten fallen auf
- wiederverwendete Tokens fallen auf
- fehlende Sessions fallen auf

Das ist Defense in Depth: Nicht eine Mauer, sondern mehrere kleine Hürden.

---

## Ablauf

1. Besucher öffnet `/test`.
2. Der Server erzeugt oder prüft eine Session.
3. Der Server erstellt eine Challenge mit zufälliger Frage.
4. Die Challenge wird mit einem einmaligen Token in SQLite gespeichert.
5. Die HTML-Seite enthält:
   - Token
   - Frage
   - Antwortoptionen
   - verstecktes Honeypot-Feld
   - clientseitigen Zeitstempel
   - deaktivierten Button, der erst nach kurzer Zeit aktiv wird
6. Besucher sendet das Formular an `/verify`.
7. Der Server prüft Token, Session, Antwort, Zeit, Honeypot und Header.
8. Aus allen Signalen entsteht ein Score.
9. Das Ergebnis wird als HTML oder JSON zurückgegeben.

---

## Scoring-Prinzip

Die Anwendung vergibt Plus- und Minuspunkte.

Positive Signale:

- Session passt zum Token
- Token ist bekannt und noch nicht benutzt
- Token ist nicht abgelaufen
- Antwort ist korrekt
- Antwortzeit wirkt plausibel
- Honeypot ist leer
- User-Agent wirkt nicht wie ein einfacher Script-Client

Negative Signale:

- Token fehlt oder ist unbekannt
- Token wurde wiederverwendet
- Token ist abgelaufen
- Antwort ist falsch
- Antwort kam auffällig schnell
- Honeypot wurde ausgefüllt
- User-Agent wirkt automatisiert oder fehlt

Am Ende entsteht eine Klassifizierung:

```text
6+ Punkte  -> human-likely
3-5 Punkte -> unclear
0-2 Punkte -> automation-likely
```

Die genauen Werte sind bewusst einfach gehalten und können je nach Experiment angepasst werden.

---

## Warum keine absolute Aussage?

Weil es im Web keine einfache, saubere Trennlinie zwischen Mensch und Bot gibt.

Ein echter Mensch kann ungewöhnlich wirken:

- VPN
- Tor
- Firmenproxy
- Screenreader
- restriktiver Browser
- deaktiviertes JavaScript
- Mobile-Netz
- aggressive Privacy-Extensions

Ein Bot kann menschlich wirken:

- echter Browser über Playwright oder Selenium
- realistische Wartezeiten
- gespeicherte Cookies
- gültige Header
- LLM-basierte Antwortauswahl
- Mausbewegungen und Klicksimulation

Deshalb sagt das Projekt nicht:

```text
Das ist ein Mensch.
```

Sondern:

```text
Dieses Verhalten wirkt eher menschlich.
Dieses Verhalten ist unklar.
Dieses Verhalten wirkt automatisiert.
```

---

## Die Realität 2026

Gegen einfache Skripte, cURL-Requests, Standard-Scraper und naive Formularbots ist dieser Ansatz sehr stark. Für diese Klasse von Automatisierung wirkt er fast wie ein hermetisches Schloss.

Aber gegen moderne autonome Bots bleibt eine klare Grenze.

Ein moderner Angreifer kann:

1. die Seite mit Playwright oder Selenium öffnen
2. Cookies akzeptieren und speichern
3. JavaScript ausführen
4. 2,5 Sekunden warten
5. die Frage auslesen
6. ein LLM die richtige Antwort wählen lassen
7. den Button klicken
8. sich wie ein echter Browser verhalten

Damit kann ein guter Bot den Test bestehen.

Das ist kein Fehler des Projekts, sondern genau die Erkenntnis:

> Auf Anwendungsebene kann man einfache Automatisierung gut erkennen und bremsen. Einen gut gebauten KI-Agenten mit echtem Browser kann man nicht zuverlässig als Bot beweisen, ohne stärkere externe Faktoren einzubeziehen.

Solche stärkeren Faktoren wären zum Beispiel:

- Account-Historie
- Reputation
- Rate-Limits über längere Zeit
- WebAuthn/Passkeys
- Zahlungs- oder Identitätsnachweise
- Gerätebindung
- Netzwerk-Reputation
- serverseitige Verhaltensanalyse über viele Interaktionen
- manuelle Moderation

Diese Maßnahmen sind aber schwerer, invasiver oder weniger datenschutzfreundlich.

---

## Warum keine Google reCAPTCHA-Lösung?

Das Projekt will bewusst ohne zentrale Drittanbieter auskommen.

reCAPTCHA, hCaptcha und ähnliche Systeme können wirksam sein, bringen aber neue Abhängigkeiten mit:

- externe Dienste
- Tracking-Risiken
- Datenschutzfragen
- Barrierefreiheitsprobleme
- Blackbox-Bewertungen
- mögliche Benachteiligung von Privacy-Nutzern

Dieses Projekt ist dagegen klein, lokal nachvollziehbar und kontrollierbar. Es passt besser zu einem Homelab-/Admin-/Privacy-Kontext.

---

## Was dieses Projekt gut kann

- einfache Bots sichtbar machen
- naive Scraper ausfiltern
- Request-Verhalten protokollieren
- Experimente im eigenen Netzwerk ermöglichen
- erklären, warum Bot-Erkennung schwierig ist
- einen Human-Likelihood-Score nachvollziehbar machen
- ohne externe CAPTCHA-Dienste funktionieren

---

## Was dieses Projekt nicht kann

- Menschlichkeit beweisen
- moderne Headless-Browser sicher erkennen
- LLM-gestützte Bots zuverlässig blockieren
- professionelle Fraud-Detection ersetzen
- Missbrauch im großen Maßstab alleine verhindern
- rechtssichere Identitätsprüfung leisten

---

## Projektstruktur

```text
human-check-flask-app.py        Hauptanwendung
requirements-human-check.txt    Python-Abhängigkeiten
README-human-check.md           kurze Startanleitung
human-check.sqlite3             SQLite-Datenbank, wird beim Start erzeugt
human-check.jsonl               JSONL-Logdatei, wird beim Start erzeugt
```

---

## Installation

```bash
python3 -m venv .venv-human-check
. .venv-human-check/bin/activate
pip install -r requirements-human-check.txt
python human-check-flask-app.py
```

Danach öffnen:

```text
https://127.0.0.1:8080/test
```

Hinweis: Flask nutzt hier `ssl_context='adhoc'`. Das ist nur für lokale Tests gedacht.

Für öffentliche Nutzung sollte TLS über einen Reverse Proxy wie Apache, Nginx oder Caddy terminiert werden.

---

## Endpunkte

### `GET /test`

Zeigt die Challenge-Seite an.

### `POST /verify`

Prüft die Antwort und gibt ein Ergebnis zurück.

Wenn der Request `Accept: application/json` enthält, kommt JSON zurück.

Beispiel:

```json
{
  "classification": "human-likely",
  "score": 8,
  "max_score": 8,
  "reasons": [
    "Session passt zum Token",
    "Token wurde noch nicht benutzt",
    "Antwort ist korrekt"
  ],
  "signals": {
    "token_known": true,
    "honeypot_filled": false
  }
}
```

### `GET /metrics`

Zeigt die letzten geloggten Requests.

Wichtig: Dieser Endpunkt ist nur für lokale Tests gedacht und sollte öffentlich nicht ohne Authentifizierung erreichbar sein.

---

## Sicherheitshinweise

Für öffentliche Tests:

- `/metrics` schützen oder deaktivieren
- echtes TLS über Reverse Proxy nutzen
- Rate-Limits setzen
- Logs regelmäßig rotieren
- keine IP-Header blind vertrauen
- Reverse-Proxy-Header nur von bekannten Proxies akzeptieren
- Secret-Key stabil per Environment setzen
- Datenminimierung beachten

Beispiel:

```bash
export HUMAN_CHECK_SECRET='lange-zufaellige-geheime-zeichenfolge'
export HUMAN_CHECK_DB='/opt/human-check/human-check.sqlite3'
export HUMAN_CHECK_LOG='/var/log/human-check.jsonl'
```

---

## Datenschutzgedanke

Das Projekt speichert technische Signale:

- IP-Adresse
- User-Agent
- Request-Pfad
- Methode
- Zeitstempel
- ausgewertete Signale

Das ist für ein Experiment sinnvoll, sollte aber nicht unbegrenzt gesammelt werden.

Empfehlung:

- klar kennzeichnen, dass es ein Experiment ist
- Logs regelmäßig löschen oder anonymisieren
- keine unnötigen personenbezogenen Daten erfassen
- keine Drittanbieter-Tracker einbauen

---

## Mögliche Erweiterungen

- Admin-Oberfläche für Auswertung
- CSV-/JSON-Export
- IP-Rate-Limiting
- automatische Logrotation
- schwerere, aber barrierearme Fragen
- optionaler Modus ohne JavaScript
- WebAuthn/Passkey als starke freiwillige Verifikation
- Nginx/Apache-Beispielkonfiguration
- Dockerfile
- Prometheus-Metriken
- kleine Visualisierung der Scores

---

## Fazit

Dieses Projekt ist ein Experiment zur Frage, wie man im modernen Web zwischen Mensch und Automatisierung unterscheiden kann.

Die Antwort ist unbequem:

> Man kann einfache Bots gut erkennen. Man kann menschliches Verhalten plausibel machen. Aber man kann Menschlichkeit nicht sicher aus einem einzelnen Webseitenbesuch beweisen.

Gerade deshalb ist der Score-Ansatz ehrlich. Er verkauft keine Magie. Er zeigt, welche Signale vorhanden sind, wie sie bewertet werden und wo die Grenzen liegen.

Für ein Homelab-, Lern- oder Forschungsprojekt ist das ein starker Ausgangspunkt: klein, nachvollziehbar, lokal betreibbar und ohne externe CAPTCHA-Abhängigkeit.

---

## Lizenzidee

Falls das Projekt öffentlich auf GitHub landet, passt eine einfache MIT-Lizenz gut, weil andere den Code frei ausprobieren und anpassen können.

Optionaler Projektsatz:

```text
Human Check Experiment is a small Flask-based human-likelihood scoring demo for studying the limits of bot detection in a post-scraper, LLM-assisted web.
```
