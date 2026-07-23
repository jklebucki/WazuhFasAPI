# Wazuh Bootstrap API

Bezpieczny, asynchroniczny i wyłącznie odczytowy serwis FastAPI dla skryptów GPO.
Publikuje manifest wersji klienta, stan agentów i kontrolowane widoki administracyjne,
korzystając wyłącznie z HTTPS Wazuh Server API. Nie odczytuje `client.keys`, nie wykonuje
enrollmentu i nie modyfikuje Wazuh.

Kod aplikacji, skrypty wdrożeniowe i pełny opis znajdują się w katalogu
[wazuh-bootstrap-api](wazuh-bootstrap-api/README.md). Kontraktem projektu pozostaje
[specyfikacja Bootstrap API](CODEX_WAZUH_BOOTSTRAP_API_SPEC.md).

```text
Windows/GPO -- HTTPS + X-API-Key --> Nginx 192.168.21.17:8443
                                      |
                                      +--> FastAPI 192.168.21.15:8765
                                                   |
                                                   +--> Wazuh API https://localhost:55000
```

## Wymagania i uruchomienie deweloperskie

- Python 3.12 lub nowszy;
- działający Wazuh Server API;
- konto Wazuh z `agent:read`, `group:read`, `manager:read`.

```bash
cd wazuh-bootstrap-api
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
python3 scripts/generate-api-keys.py
# Uzupełnij .env, szczególnie wszystkie CHANGE_ME.
uvicorn app.main:app --host 127.0.0.1 --port 8765 --workers 1
```

## Instalacja produkcyjna

Rekomendowany checkout produkcyjny znajduje się w `/srv/WazuhFasAPI`, a instalator tworzy
oddzielny runtime w `/opt/wazuh-bootstrap-api`:

```bash
cd /srv
sudo gh repo clone jklebucki/WazuhFasAPI /srv/WazuhFasAPI
cd /srv/WazuhFasAPI/wazuh-bootstrap-api
sudo ./scripts/install.sh
```

Instalator nie nadpisuje `/etc/wazuh-bootstrap-api.env`, nie instaluje Nginx i nie zmienia
centralnego proxy `192.168.21.17`. Szczegóły zawiera
[instrukcja wdrożenia](wazuh-bootstrap-api/docs/DEPLOYMENT.md).

## Konfiguracja

Pełny, opisany wzorzec znajduje się w
[wazuh-bootstrap-api.env.example](wazuh-bootstrap-api/deploy/env/wazuh-bootstrap-api.env.example).
Klucze API muszą być różne i mieć co najmniej 32 znaki. `TARGET_AGENT_VERSION=auto` używa
wersji managera. Przy TLS Wazuh ustaw `WAZUH_API_VERIFY_TLS=true` i opcjonalnie wskaż
`WAZUH_API_CA_FILE`; pusty plik CA oznacza systemowy magazyn zaufania.

## Kontrole jakości

```bash
cd wazuh-bootstrap-api
ruff check .
ruff format --check .
mypy app
pytest --cov=app --cov-report=term-missing --cov-fail-under=90
```

## Przykłady

```bash
curl -fsS http://127.0.0.1:8765/health/live
curl -fsS -H "X-API-Key: $CLIENT_API_KEY" http://127.0.0.1:8765/api/v1/manifest
curl -fsS -H "X-API-Key: $CLIENT_API_KEY" http://127.0.0.1:8765/api/v1/agents/LAP006
curl -fsS -H "X-Admin-API-Key: $ADMIN_API_KEY" http://127.0.0.1:8765/api/v1/agents
```

## Agent Windows przez GPO

[Install-WazuhAgent.ps1](wazuh-bootstrap-api/deploy/gpo/Install-WazuhAgent.ps1) instaluje,
aktualizuje i naprawia agenta Wazuh. Ponowne uruchomienie po przerwanym MSI naprawia częściową
instalację, nie zachowuje pustego lub nieprawidłowego `client.keys` i wykonuje świeży enrollment
wyłącznie wtedy, gdy manager nie ma konfliktującego rekordu.

Przed wdrożeniem uruchom
[Test-WazuhGpoReadiness.ps1](wazuh-bootstrap-api/deploy/gpo/Test-WazuhGpoReadiness.ps1).
Pełne procedury opisują
[wdrożenie GPO](wazuh-bootstrap-api/docs/GPO-DEPLOYMENT.md) i
[testy destrukcyjne](wazuh-bootstrap-api/docs/GPO-TESTING.md).

## Aktualizacja i rollback

`sudo ./scripts/install.sh --upgrade` wykonuje `git pull --ff-only`, zachowuje konfigurację,
zatrzymuje usługę, aktualizuje runtime, uruchamia usługę i sprawdza health. Błąd wdrożenia
automatycznie przywraca poprzednie wydanie. Sekrety w `/etc/wazuh-bootstrap-api.env` pozostają
poza katalogiem aplikacji.

## Diagnostyka

- `journalctl -u wazuh-bootstrap-api -n 100 --no-pager` — logi JSON bez sekretów;
- `systemctl status wazuh-bootstrap-api` — stan procesu;
- `/health/live` działa bez Wazuh, `/health/ready` wymaga zgodnej wersji i dostępu do API;
- odpowiedź 503 oznacza niedostępność, brak RBAC albo niezgodną wersję manager/agent;
- odpowiedź stale ma `stale: true` i nagłówek `Warning: 110`.

## Dokumentacja

- [README aplikacji](wazuh-bootstrap-api/README.md)
- [API](wazuh-bootstrap-api/docs/API.md)
- [Wdrożenie](wazuh-bootstrap-api/docs/DEPLOYMENT.md)
- [Bezpieczeństwo](wazuh-bootstrap-api/docs/SECURITY.md)
- [RBAC Wazuh](wazuh-bootstrap-api/docs/WAZUH-RBAC.md)
- [Kontrakt konsumenta GPO](wazuh-bootstrap-api/docs/GPO-CONSUMER.md)
- [Wdrożenie agenta Windows przez GPO](wazuh-bootstrap-api/docs/GPO-DEPLOYMENT.md)
- [Testy destrukcyjne agenta Windows](wazuh-bootstrap-api/docs/GPO-TESTING.md)
