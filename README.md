# Wazuh Bootstrap API

Bezpieczny, asynchroniczny i wyłącznie odczytowy serwis FastAPI dla skryptów GPO.
Publikuje manifest wersji klienta, stan agentów i kontrolowane widoki administracyjne,
korzystając wyłącznie z HTTPS Wazuh Server API. Nie odczytuje `client.keys`, nie wykonuje
enrollmentu i nie modyfikuje Wazuh.

```text
Windows/GPO -- HTTPS + X-API-Key --> Nginx :8443
                                      |
                                      +--> FastAPI 127.0.0.1:8765
                                                   |
                                                   +--> Wazuh API 127.0.0.1:55000
```

## Wymagania i uruchomienie deweloperskie

- Python 3.12 lub nowszy;
- działający Wazuh Server API;
- konto Wazuh z `agent:read`, `group:read`, `manager:read`.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
python3 scripts/generate-api-keys.py
# Uzupełnij .env, szczególnie wszystkie CHANGE_ME.
uvicorn app.main:app --host 127.0.0.1 --port 8765 --workers 1
```

## Instalacja produkcyjna

Skopiuj repozytorium na Ubuntu/Debian i uruchom jako root:

```bash
./scripts/install.sh --with-nginx
editor /etc/wazuh-bootstrap-api.env
python3 /opt/wazuh-bootstrap-api/scripts/validate-config.py --env-file /etc/wazuh-bootstrap-api.env
systemctl restart wazuh-bootstrap-api
```

Instalator nie nadpisuje istniejącego env. Przed wystawieniem portu 8443 dostosuj allowlistę,
DNS oraz ścieżki do certyfikatu z firmowego CA w konfiguracji Nginx. FastAPI pozostaje na
localhost. Szczegóły zawiera [instrukcja wdrożenia](docs/DEPLOYMENT.md).

## Konfiguracja

Pełny, opisany wzorzec znajduje się w `deploy/env/wazuh-bootstrap-api.env.example`.
Klucze API muszą być różne i mieć co najmniej 32 znaki. `TARGET_AGENT_VERSION=auto` używa
wersji managera. Przy TLS Wazuh ustaw `WAZUH_API_VERIFY_TLS=true` i opcjonalnie wskaż
`WAZUH_API_CA_FILE`; pusty plik CA oznacza systemowy magazyn zaufania.

## Kontrole jakości

```bash
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

## Aktualizacja i rollback

`./scripts/install.sh --upgrade` zachowuje konfigurację, odtwarza venv, sprawdza import,
restartuje usługę i weryfikuje health. Przed aktualizacją zachowaj poprzedni katalog wydania;
rollback polega na przywróceniu go do `/opt/wazuh-bootstrap-api`, odtworzeniu venv i restarcie.
Sekrety w `/etc/wazuh-bootstrap-api.env` pozostają poza katalogiem aplikacji.

## Diagnostyka

- `journalctl -u wazuh-bootstrap-api -n 100 --no-pager` — logi JSON bez sekretów;
- `systemctl status wazuh-bootstrap-api` — stan procesu;
- `/health/live` działa bez Wazuh, `/health/ready` wymaga zgodnej wersji i dostępu do API;
- odpowiedź 503 oznacza niedostępność, brak RBAC albo niezgodną wersję manager/agent;
- odpowiedź stale ma `stale: true` i nagłówek `Warning: 110`.

## Dokumentacja

- [API](docs/API.md)
- [Wdrożenie](docs/DEPLOYMENT.md)
- [Bezpieczeństwo](docs/SECURITY.md)
- [RBAC Wazuh](docs/WAZUH-RBAC.md)
- [Kontrakt konsumenta GPO](docs/GPO-CONSUMER.md)
