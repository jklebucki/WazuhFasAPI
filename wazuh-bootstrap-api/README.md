# Wazuh Bootstrap API

Bezpieczne, asynchroniczne i wyłącznie odczytowe API dla skryptów GPO. Serwis publikuje
manifest klienta Wazuh, stan agentów i kontrolowane widoki administracyjne. Nie odczytuje
`client.keys`, nie wykonuje enrollmentu i nie modyfikuje Wazuh.

```text
Komputery domenowe / GPO
          |
          | HTTPS :8443 + X-API-Key
          v
Nginx 192.168.21.17 (wazuh.ad.citronex.pl, wildcard TLS)
          |
          | HTTP :8765, dozwolony wyłącznie z 192.168.21.17
          v
FastAPI 192.168.21.15:8765
          |
          | HTTPS + JWT
          v
Wazuh Server API https://localhost:55000
```

## Wymagania

- Ubuntu/Debian z Pythonem 3.12+ na serwerze Wazuh `192.168.21.15`;
- konto Wazuh API z `agent:read`, `group:read`, `manager:read`;
- centralny Nginx `192.168.21.17`;
- firewall dopuszczający TCP/8765 wyłącznie z centralnego proxy.

## Uruchomienie deweloperskie

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
python3 scripts/generate-api-keys.py
# Uzupełnij .env.
uvicorn app.main:app --host 127.0.0.1 --port 8765 --workers 1
```

## Wdrożenie produkcyjne

Rekomendowany checkout produkcyjny to `/srv/WazuhFasAPI`; runtime jest instalowany osobno
w `/opt/wazuh-bootstrap-api`. Instalator uruchamiany na `192.168.21.15` nie instaluje,
nie konfiguruje i nie usuwa Nginx:

```bash
cd /srv
sudo gh repo clone jklebucki/WazuhFasAPI /srv/WazuhFasAPI
cd /srv/WazuhFasAPI/wazuh-bootstrap-api
sudo ./scripts/install.sh
```

Produkcja używa `/etc/wazuh-bootstrap-api.env`. Lokalny, gotowy plik
`deploy/env/wazuh-bootstrap-api.env` jest wykluczony przez `.gitignore`, a wersjonowany wzorzec
znajduje się w
[wazuh-bootstrap-api.env.example](deploy/env/wazuh-bootstrap-api.env.example). Przed startem
utwórz `/etc/wazuh-bootstrap-api-wazuh-ca.pem` oraz ustaw uprawnienia opisane w
[instrukcji wdrożenia](docs/DEPLOYMENT.md).

Centralny vhost jest utrzymywany niezależnie na `192.168.21.17` i odpowiada pod:

```text
https://wazuh.ad.citronex.pl:8443
```

Jego źródło znajduje się w
[wazuh-bootstrap-api.conf](deploy/nginx/wazuh-bootstrap-api.conf).

Opcjonalna dokumentacja OpenAPI jest sterowana przez `DOCS_ENABLED`. Po ustawieniu wartości
`true` dostępne są Swagger UI pod `/docs`, ReDoc pod `/redoc` i schemat pod
`/openapi.json`. Swagger udostępnia osobne pola autoryzacji dla klucza klienta i administratora.
Szczegóły bezpiecznej aktywacji opisuje [instrukcja wdrożenia](docs/DEPLOYMENT.md).

## Kontrole jakości

```bash
ruff check .
ruff format --check .
mypy app
pytest --cov=app --cov-report=term-missing --cov-fail-under=90
```

## Przykłady

```bash
curl -fsS https://wazuh.ad.citronex.pl:8443/health/live

curl -fsS \
  -H "X-API-Key: $CLIENT_API_KEY" \
  https://wazuh.ad.citronex.pl:8443/api/v1/manifest

curl -fsS \
  -H "X-API-Key: $CLIENT_API_KEY" \
  https://wazuh.ad.citronex.pl:8443/api/v1/agents/LAP006

curl -fsS \
  -H "X-Admin-API-Key: $ADMIN_API_KEY" \
  https://wazuh.ad.citronex.pl:8443/api/v1/agents
```

Nie używaj `-k` w produkcyjnych konsumentach. Komputery domenowe powinny ufać firmowemu CA.

## Agent Windows przez GPO

[Install-WazuhAgent.ps1](deploy/gpo/Install-WazuhAgent.ps1) jest idempotentnym skryptem
startowym dla komputerów AD. Instaluje, naprawia lub aktualizuje agenta na podstawie manifestu,
zachowuje wyłącznie prawidłową lokalną tożsamość, weryfikuje SHA-256 i Authenticode oraz odmawia
automatycznego enrollmentu przy konflikcie nazwy. Ponowne uruchomienie po przerwanym MSI naprawia
częściową instalację; pusty lub nieprawidłowy `client.keys` nie jest przywracany jako kopia
tożsamości.

Konfiguracja przykładowa startuje w trybie `auditOnly=true`; tajemnice są odczytywane z osobnego,
chronionego udziału dostępnego dla kont komputerów i nigdy nie trafiają do SYSVOL. Przed
aktywacją użyj [Test-WazuhGpoReadiness.ps1](deploy/gpo/Test-WazuhGpoReadiness.ps1), który
kontroluje udział, ACL, poświadczenia FastAPI i hasło enrollmentu Wazuh.

Procedura pilota, podpisania PowerShell, konfiguracji GPMC, ACL udziału i aktywacji znajduje się
w [instrukcji wdrożenia GPO](docs/GPO-DEPLOYMENT.md). Kontrolowaną macierz awarii i procedurę
odtworzeniową opisuje [instrukcja testów destrukcyjnych](docs/GPO-TESTING.md).

## Aktualizacja i rollback

`sudo ./scripts/install.sh --upgrade` najpierw wykonuje bezpieczne `git pull --ff-only` jako
właściciel checkoutu, zachowuje env, zatrzymuje usługę, tworzy kopię poprzedniego wydania,
odtwarza venv, waliduje import, restartuje usługę i wykonuje smoke test. Błąd po podmianie
automatycznie przywraca poprzedni runtime, jednostkę systemd i wcześniejszy stan usługi.
Smoke test czeka do 30 sekund na osiągnięcie liveness po restarcie, aby nie wywoływać rollbacku
w trakcie normalnego startu Uvicorna.
Checkout z lokalnymi zmianami nie zostanie wdrożony. Opcja `--no-git-pull` służy kontrolowanym
wdrożeniom offline. Pełne logi instalatora są zapisywane jako pliki root-only w
`/var/log/wazuh-bootstrap-api/`. Konfiguracja centralnego Nginx nie jest zmieniana przez ten proces.

## Diagnostyka

- `journalctl -u wazuh-bootstrap-api -n 100 --no-pager` — logi JSON;
- `systemctl status wazuh-bootstrap-api` — stan backendu;
- `curl http://192.168.21.15:8765/health/live` — test bezpośredni na managerze;
- `curl https://wazuh.ad.citronex.pl:8443/health/ready` — test całej ścieżki;
- 503 przed wdrożeniem backendu jest kontrolowaną odpowiedzią centralnego proxy;
- błąd Windows `CRYPT_E_REVOCATION_OFFLINE` oznacza niedostępność firmowego CRL.

## Dokumentacja

- [API](docs/API.md)
- [Wdrożenie](docs/DEPLOYMENT.md)
- [Bezpieczeństwo](docs/SECURITY.md)
- [RBAC Wazuh](docs/WAZUH-RBAC.md)
- [Konsument GPO](docs/GPO-CONSUMER.md)
- [Wdrożenie agenta Windows przez GPO](docs/GPO-DEPLOYMENT.md)
- [Testy destrukcyjne agenta Windows](docs/GPO-TESTING.md)
