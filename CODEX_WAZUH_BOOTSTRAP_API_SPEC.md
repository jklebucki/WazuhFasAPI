# Specyfikacja implementacyjna dla Codex
## Wazuh Bootstrap API — bezpieczne API tylko do odczytu dla skryptów GPO

> Ten dokument jest kompletnym poleceniem implementacyjnym.  
> Zbuduj cały projekt, testy, instalator, konfigurację `systemd`, przykładową konfigurację Nginx i dokumentację wdrożeniową.  
> Nie kończ na szkielecie, pseudokodzie ani fragmentach. Repozytorium po zakończeniu ma być gotowe do skopiowania na serwer Wazuh i uruchomienia.

---

## 1. Cel projektu

Utwórz niewielki, bezpieczny serwis **FastAPI** uruchamiany na tym samym serwerze Linux, na którym działa **Wazuh Manager**.

Serwis ma udostępniać kontrolowane, tylko do odczytu informacje potrzebne przez przyszły skrypt PowerShell uruchamiany przez GPO:

1. manifest oczekiwanej wersji klienta Wazuh dla Windows;
2. informację, czy agent o podanej nazwie komputera istnieje w Wazuh;
3. bieżący stan, grupę, wersję i ostatnie dane tego agenta;
4. pełną listę agentów — wyłącznie dla administratora;
5. listę grup — wyłącznie dla administratora;
6. stan działania samego serwisu i połączenia z Wazuh API.

Serwis **nie może**:

- rejestrować agentów;
- usuwać agentów;
- zwracać kluczy agentów;
- czytać ani publikować `/var/ossec/etc/client.keys`;
- zmieniać grup;
- uruchamiać aktualizacji;
- restartować managera lub agentów;
- modyfikować konfiguracji Wazuh;
- zapisywać danych do Wazuh.

Jedynym żądaniem `POST` do Wazuh Server API może być logowanie do:

```text
POST /security/user/authenticate?raw=true
```

Pozostałe wywołania Wazuh mają być wyłącznie `GET`.

---

## 2. Kontekst środowiska

Domyślne wartości wdrożeniowe:

```text
Wazuh Manager:                 192.168.21.15
Wazuh Server API:              https://127.0.0.1:55000
Docelowy klient Windows:       4.14.6
Rewizja pakietu MSI:           1
Pakiet:                        wazuh-agent-4.14.6-1.msi
Oficjalny URL MSI:             https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi
Port komunikacji agentów:      1514/TCP
Port enrollmentu:              1515/TCP
Nazwa usługi Windows:          WazuhSvc
Główna ścieżka Windows x64:    C:\Program Files (x86)\ossec-agent
Alternatywna ścieżka:          C:\Program Files\ossec-agent
```

Wszystkie wartości muszą być konfigurowalne przez zmienne środowiskowe. Nie wpisuj danych uwierzytelniających w kodzie ani repozytorium.

Serwis ma być przygotowany przede wszystkim dla Ubuntu/Debian i wdrożenia jako natywna usługa `systemd`, bez Dockera.

---

## 3. Ważne zasady Wazuh

Implementacja musi respektować poniższe założenia:

1. Wazuh Server API wymaga JWT dla wszystkich używanych endpointów poza endpointem logowania.
2. Domyślny czas życia JWT Wazuh 4.14.6 wynosi 900 sekund.
3. `GET /agents` wymaga uprawnienia RBAC `agent:read`.
4. `GET /groups` wymaga `group:read`.
5. `GET /manager/info` wymaga `manager:read`.
6. Pole `ip` z `GET /agents` jest ostatnim adresem używanym do komunikacji z managerem.
7. Pole `registerIP` może mieć wartość `any` i nie może zastępować pola `ip`.
8. Kompatybilność jest gwarantowana, gdy wersja managera jest równa lub nowsza od wersji agenta.
9. Agent Windows identyfikuje się lokalnym `client.keys`, ale Bootstrap API nie może tego klucza pobierać ani publikować.
10. Nazwy komputerów należy porównywać bez rozróżniania wielkości liter, ale w odpowiedzi zachowywać nazwę zwróconą przez Wazuh.

---

## 4. Architektura

Docelowy przepływ:

```text
Komputer domenowy / skrypt GPO
          |
          | HTTPS + X-API-Key
          v
Nginx na serwerze Wazuh :8443
          |
          | HTTP localhost
          v
FastAPI / Uvicorn 127.0.0.1:8765
          |
          | HTTPS + JWT
          v
Wazuh Server API 127.0.0.1:55000
```

FastAPI ma domyślnie nasłuchiwać wyłącznie na:

```text
127.0.0.1:8765
```

Dostęp sieciowy ma zapewniać Nginx:

- TLS;
- ograniczenie do wskazanych podsieci;
- limit rozmiaru żądania;
- rate limiting;
- bez ujawniania nagłówka `Server`;
- przekazywanie identyfikatora żądania;
- krótkie timeouty.

Nie modyfikuj kodu, konfiguracji ani plików instalacyjnych Wazuh.

---

## 5. Stos technologiczny

Użyj:

- Python 3.12+;
- FastAPI;
- Uvicorn;
- `httpx.AsyncClient`;
- Pydantic v2;
- `pydantic-settings`;
- `packaging.version.Version` do porównań wersji;
- `PyJWT` wyłącznie do odczytu pola `exp` z otrzymanego JWT bez weryfikacji podpisu;
- `pytest`;
- `pytest-asyncio`;
- `respx` do mockowania `httpx`;
- `ruff`;
- `mypy`.

Nie używaj bazy danych.

Stan ma być przechowywany wyłącznie w pamięci:

- token JWT;
- krótkotrwały cache managera;
- krótkotrwały cache agentów;
- krótkotrwały cache grup.

Projekt ma mieć `pyproject.toml`. Zależności produkcyjne i deweloperskie mają być jawnie określone. Wygeneruj także zamrożony plik zależności używany przez instalator, np. `requirements.lock`, z dokładnymi wersjami sprawdzonymi testami.

---

## 6. Struktura repozytorium

Utwórz co najmniej:

```text
wazuh-bootstrap-api/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── dependencies.py
│   │   └── routes/
│   │       ├── __init__.py
│   │       ├── health.py
│   │       ├── manifest.py
│   │       ├── agents.py
│   │       └── groups.py
│   ├── clients/
│   │   ├── __init__.py
│   │   └── wazuh.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── logging.py
│   │   ├── security.py
│   │   └── cache.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── common.py
│   │   ├── manifest.py
│   │   ├── agent.py
│   │   ├── group.py
│   │   └── health.py
│   └── services/
│       ├── __init__.py
│       ├── bootstrap.py
│       └── wazuh_data.py
├── tests/
│   ├── conftest.py
│   ├── unit/
│   │   ├── test_config.py
│   │   ├── test_security.py
│   │   ├── test_versions.py
│   │   ├── test_wazuh_client.py
│   │   └── test_cache.py
│   └── integration/
│       ├── test_health.py
│       ├── test_manifest.py
│       ├── test_agent_lookup.py
│       ├── test_agents_admin.py
│       └── test_groups_admin.py
├── deploy/
│   ├── systemd/
│   │   └── wazuh-bootstrap-api.service
│   ├── nginx/
│   │   └── wazuh-bootstrap-api.conf
│   ├── env/
│   │   └── wazuh-bootstrap-api.env.example
│   └── logrotate/
│       └── wazuh-bootstrap-api
├── scripts/
│   ├── install.sh
│   ├── uninstall.sh
│   ├── smoke-test.sh
│   ├── generate-api-keys.py
│   ├── calculate-msi-sha256.sh
│   └── validate-config.py
├── docs/
│   ├── DEPLOYMENT.md
│   ├── SECURITY.md
│   ├── WAZUH-RBAC.md
│   ├── API.md
│   └── GPO-CONSUMER.md
├── .gitignore
├── .env.example
├── pyproject.toml
├── requirements.lock
├── README.md
└── LICENSE
```

Możesz dodać dodatkowe pliki, jeżeli poprawiają jakość projektu.

---

## 7. Konfiguracja aplikacji

Zaimplementuj klasę `Settings` opartą na `pydantic-settings`.

Wymagane zmienne:

```dotenv
APP_NAME=Wazuh Bootstrap API
APP_ENV=production
APP_VERSION=1.0.0

BIND_HOST=127.0.0.1
BIND_PORT=8765
UVICORN_WORKERS=1

WAZUH_API_URL=https://127.0.0.1:55000
WAZUH_API_USERNAME=wazuh-wui
WAZUH_API_PASSWORD=CHANGE_ME
WAZUH_API_VERIFY_TLS=false
WAZUH_API_CA_FILE=
WAZUH_API_CONNECT_TIMEOUT_SECONDS=3
WAZUH_API_READ_TIMEOUT_SECONDS=10

WAZUH_MANAGER_ADDRESS=192.168.21.15
WAZUH_MANAGER_PORT=1514
WAZUH_REGISTRATION_ADDRESS=192.168.21.15
WAZUH_REGISTRATION_PORT=1515

TARGET_AGENT_VERSION=4.14.6
TARGET_AGENT_PACKAGE_REVISION=1
TARGET_AGENT_MSI_URL=https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi
TARGET_AGENT_SHA256=

CLIENT_API_KEY=CHANGE_ME
ADMIN_API_KEY=CHANGE_ME

MANAGER_CACHE_TTL_SECONDS=60
AGENTS_CACHE_TTL_SECONDS=30
GROUPS_CACHE_TTL_SECONDS=60
UPSTREAM_STALE_CACHE_SECONDS=300

DOCS_ENABLED=false
LOG_LEVEL=INFO
TRUST_PROXY_HEADERS=true
```

Wymagania:

- aplikacja ma nie wystartować, jeżeli którykolwiek klucz ma wartość `CHANGE_ME`;
- klucze muszą mieć co najmniej 32 znaki;
- `CLIENT_API_KEY` i `ADMIN_API_KEY` nie mogą być identyczne;
- hasło Wazuh nie może pojawić się w logach ani błędach;
- jeśli `WAZUH_API_VERIFY_TLS=true`, aplikacja ma korzystać z systemowego magazynu CA albo z `WAZUH_API_CA_FILE`;
- nie ustawiaj globalnie wyłączenia ostrzeżeń TLS;
- `TARGET_AGENT_VERSION=auto` ma oznaczać użycie wersji managera;
- przy jawnej wersji docelowej sprawdź, czy nie jest nowsza niż manager;
- do porównania usuń prefiksy `Wazuh`, `v` i tekst dodatkowy;
- `TARGET_AGENT_MSI_URL` może być pusty — wtedy zbuduj go według wzoru:
  `https://packages.wazuh.com/4.x/windows/wazuh-agent-{version}-{revision}.msi`.

---

## 8. Uwierzytelnianie klientów Bootstrap API

Zaimplementuj dwa poziomy kluczy.

### 8.1 Klucz kliencki

Nagłówek:

```http
X-API-Key: <CLIENT_API_KEY>
```

Dostęp:

```text
GET /api/v1/manifest
GET /api/v1/agents/{hostname}
```

### 8.2 Klucz administracyjny

Nagłówek:

```http
X-Admin-API-Key: <ADMIN_API_KEY>
```

Dostęp:

```text
GET /api/v1/agents
GET /api/v1/groups
GET /api/v1/groups/{group_name}
```

### 8.3 Endpointy bez uwierzytelnienia

Wyłącznie:

```text
GET /health/live
GET /health/ready
```

`/health/ready` nie może ujawniać nazw agentów, grup, adresów IP, URL API ani treści błędów uwierzytelnienia.

Porównuj klucze za pomocą `secrets.compare_digest`.

Dla błędnego lub brakującego klucza zwracaj zawsze ogólne:

```json
{
  "detail": "Unauthorized"
}
```

Nie ujawniaj, czy klucz nie istnieje, ma złą długość albo jest niepoprawny.

---

## 9. Klient Wazuh Server API

Utwórz jeden współdzielony `httpx.AsyncClient` w lifespan aplikacji.

### 9.1 Logowanie

Wywołanie:

```text
POST /security/user/authenticate?raw=true
```

Basic Auth z konfiguracji.

Obsłuż zarówno:

- odpowiedź surową zawierającą sam token;
- odpowiedź JSON z `data.token`, gdyby serwer zachowywał się inaczej.

Token przechowuj wyłącznie w pamięci.

Odczytaj `exp` z JWT przez PyJWT z wyłączoną weryfikacją podpisu. Używaj `exp` tylko do określenia czasu odświeżenia, nie jako dowodu autentyczności.

Odśwież token:

- co najmniej 60 sekund przed `exp`;
- natychmiast po odpowiedzi Wazuh `401`;
- maksymalnie jeden raz dla danego żądania.

Zabezpiecz odświeżanie `asyncio.Lock`, aby wiele równoległych żądań nie wykonywało równocześnie logowania.

### 9.2 Błędy

Zaimplementuj własne wyjątki:

```text
WazuhApiError
WazuhAuthenticationError
WazuhAuthorizationError
WazuhUnavailableError
WazuhInvalidResponseError
```

Mapowanie:

- timeout / brak połączenia → `WazuhUnavailableError`;
- `401` → odświeżenie tokenu, potem ewentualnie `WazuhAuthenticationError`;
- `403` → `WazuhAuthorizationError`;
- `429` → kontrolowany błąd upstream;
- `5xx` → `WazuhUnavailableError`;
- niepoprawny JSON lub struktura → `WazuhInvalidResponseError`;
- Wazuh JSON z `error != 0` → `WazuhApiError`.

Nigdy nie zwracaj klientowi pełnej odpowiedzi upstream ani stack trace.

### 9.3 Używane endpointy Wazuh

```text
GET /manager/info
GET /agents
GET /groups
```

Nie implementuj żadnych innych operacji.

### 9.4 Parametry `GET /agents`

Dla pojedynczego hosta używaj:

```text
name=<hostname>
select=id,name,group,status,status_code,version,ip,registerIP,lastKeepAlive,dateAdd,manager,node_name,os.platform,os.name,os.version
limit=100
```

Nawet gdy Wazuh filtruje po nazwie, po stronie aplikacji wykonaj dodatkowe dokładne porównanie `casefold()`.

Dla pełnej listy:

```text
select=id,name,group,status,status_code,version,ip,registerIP,lastKeepAlive,dateAdd,manager,node_name,os.platform,os.name,os.version
sort=name
limit=500
offset=<n>
```

Pobieraj wszystkie strony do momentu osiągnięcia `total_affected_items`.

Nie zwracaj rekordu managera o ID `000` jako agenta końcowego.

### 9.5 Parametry `GET /groups`

Obsłuż paginację tak samo jak dla agentów.

Nie zakładaj, że pojedyncze wywołanie zwróci wszystkie grupy.

---

## 10. Cache i odporność na awarie

Zaimplementuj bezpieczny cache asynchroniczny z blokadą per klucz.

Cache:

```text
manager info:  60 s
agent lookup:  30 s per hostname
agents list:   30 s
groups list:   60 s
```

Wymagania:

- `Cache-Control: no-store` dla odpowiedzi zawierających dane agentów;
- manifest może mieć `Cache-Control: private, max-age=30`;
- kiedy Wazuh API chwilowo nie odpowiada, można zwrócić ostatni poprawny cache maksymalnie przez `UPSTREAM_STALE_CACHE_SECONDS`;
- odpowiedź oparta na starym cache musi zawierać:
  - `stale: true`;
  - `dataAsOf`;
  - nagłówek `Warning: 110 - "Response is stale"`;
- nie używaj starego cache do `/health/ready`;
- brak jakiegokolwiek poprawnego cache i niedostępny Wazuh → `503 Service Unavailable`;
- nie cache’uj błędów uwwierzytelnienia ani autoryzacji.

---

## 11. Kontrakty endpointów

Wszystkie daty zwracaj jako ISO 8601 UTC z `Z`.

### 11.1 `GET /health/live`

Bez uwierzytelnienia.

Nie kontaktuje się z Wazuh.

```json
{
  "status": "ok",
  "service": "Wazuh Bootstrap API",
  "version": "1.0.0",
  "time": "2026-07-22T14:00:00Z"
}
```

Kod `200`, jeśli proces działa.

### 11.2 `GET /health/ready`

Bez uwierzytelnienia.

Wykonuje lekkie sprawdzenie Wazuh API lub korzysta z bardzo świeżego wyniku health-check, maksymalnie 10 sekund.

Sukces:

```json
{
  "status": "ready",
  "wazuhApi": "reachable",
  "managerVersion": "4.14.6",
  "time": "2026-07-22T14:00:00Z"
}
```

Błąd:

```json
{
  "status": "not_ready",
  "wazuhApi": "unreachable",
  "time": "2026-07-22T14:00:00Z"
}
```

Przy błędzie kod `503`.

Nie zwracaj szczegółów połączenia ani błędów logowania.

### 11.3 `GET /api/v1/manifest`

Wymaga `X-API-Key`.

Przykład:

```json
{
  "schemaVersion": 1,
  "targetAgent": {
    "version": "4.14.6",
    "packageRevision": "1",
    "fullPackageVersion": "4.14.6-1",
    "msiFileName": "wazuh-agent-4.14.6-1.msi",
    "downloadUrl": "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi",
    "sha256": null
  },
  "manager": {
    "version": "4.14.6",
    "address": "192.168.21.15",
    "communicationPort": 1514,
    "registrationAddress": "192.168.21.15",
    "registrationPort": 1515,
    "compatible": true
  },
  "windows": {
    "serviceName": "WazuhSvc",
    "installDirectories": [
      "C:\\Program Files (x86)\\ossec-agent",
      "C:\\Program Files\\ossec-agent"
    ],
    "keyFileName": "client.keys",
    "configFileName": "ossec.conf",
    "executableName": "wazuh-agent.exe"
  },
  "generatedAt": "2026-07-22T14:00:00Z",
  "dataAsOf": "2026-07-22T14:00:00Z",
  "stale": false
}
```

Jeżeli wersja docelowa jest nowsza niż manager:

- `/health/ready` zwraca `503`;
- `/api/v1/manifest` zwraca `503`;
- log zawiera jednoznaczny komunikat bez sekretów.

Nie próbuj automatycznie obniżać wersji.

### 11.4 `GET /api/v1/agents/{hostname}`

Wymaga `X-API-Key`.

Walidacja `hostname`:

- od 1 do 63 znaków;
- dozwolone litery ASCII, cyfry, myślnik i kropka;
- brak spacji;
- brak znaków URL/path traversal;
- usuń końcową kropkę;
- do wyszukiwania użyj krótkiej nazwy przed pierwszą kropką;
- zwróć `400`, jeśli walidacja nie przejdzie.

Agent nie istnieje:

```json
{
  "queryName": "LAP006",
  "registered": false,
  "duplicateCount": 0,
  "agent": null,
  "dataAsOf": "2026-07-22T14:00:00Z",
  "stale": false
}
```

Agent istnieje:

```json
{
  "queryName": "LAP006",
  "registered": true,
  "duplicateCount": 1,
  "agent": {
    "id": "123",
    "name": "LAP006",
    "groups": [
      "ADMINISTRACJA"
    ],
    "status": "disconnected",
    "statusCode": 1,
    "versionRaw": "Wazuh v4.14.6",
    "version": "4.14.6",
    "lastKnownIp": "192.168.29.20",
    "registrationIp": "any",
    "lastKeepAlive": "2026-07-20T10:15:00Z",
    "dateAdded": "2025-03-10T08:00:00Z",
    "manager": "wazuh-srv",
    "nodeName": "node01",
    "operatingSystem": {
      "platform": "windows",
      "name": "Microsoft Windows 11 Pro",
      "version": "10.0.26100"
    }
  },
  "dataAsOf": "2026-07-22T14:00:00Z",
  "stale": false
}
```

Jeżeli Wazuh zwróci więcej niż jeden rekord odpowiadający dokładnie tej samej nazwie bez uwzględnienia wielkości liter:

- `registered=true`;
- `duplicateCount` ma pokazywać liczbę;
- zwróć `409 Conflict`;
- w body zwróć bezpieczną listę rekordów zawierającą tylko `id`, `name`, `status`, `groups`, `lastKeepAlive`;
- zaloguj ostrzeżenie;
- nie wybieraj automatycznie jednego rekordu.

Pole `lastKnownIp` zawsze pochodzi z `ip`, nigdy z `registerIP`.

### 11.5 `GET /api/v1/agents`

Wymaga `X-Admin-API-Key`.

Parametry:

```text
status
group
platform
name
limit
offset
```

Walidacja:

- maksymalny `limit` odpowiedzi publicznej: 500;
- domyślnie 100;
- `offset >= 0`;
- filtrowanie może być wykonane upstream oraz ponownie lokalnie;
- brak możliwości przekazania dowolnego WQL przez klienta.

Odpowiedź:

```json
{
  "items": [],
  "total": 0,
  "limit": 100,
  "offset": 0,
  "dataAsOf": "2026-07-22T14:00:00Z",
  "stale": false
}
```

Nie zwracaj żadnych kluczy ani danych spoza jawnie określonego modelu.

### 11.6 `GET /api/v1/groups`

Wymaga `X-Admin-API-Key`.

Odpowiedź:

```json
{
  "items": [
    {
      "name": "ADMINISTRACJA",
      "agentCount": 25
    }
  ],
  "total": 1,
  "dataAsOf": "2026-07-22T14:00:00Z",
  "stale": false
}
```

Normalizuj różne możliwe nazwy pól Wazuh, ale nie zgaduj danych. Jeśli liczba agentów nie jest dostępna, `agentCount` ma być `null`.

### 11.7 `GET /api/v1/groups/{group_name}`

Wymaga `X-Admin-API-Key`.

Zwraca grupę i agentów przypisanych do tej grupy, ale tylko pola publicznego modelu agenta.

Dla braku grupy zwróć `404`.

---

## 12. Kontrola wersji

Zaimplementuj funkcję normalizującą przykłady:

```text
v4.14.6             -> 4.14.6
Wazuh v4.14.6       -> 4.14.6
Wazuh 4.14.6        -> 4.14.6
4.14.6-1            -> 4.14.6
```

Do porównań użyj `packaging.version.Version`.

Manifest ma zwracać:

```text
manager.compatible = managerVersion >= targetAgentVersion
```

Dla agentów lista administracyjna może opcjonalnie zwracać wyliczone pole:

```text
versionState:
  current
  outdated
  newer_than_target
  unknown
```

Reguły:

- `current`: agent == target;
- `outdated`: agent < target;
- `newer_than_target`: agent > target;
- `unknown`: brak lub niepoprawna wersja.

Nie uznawaj samego statusu `active` za dowód poprawnej wersji.

---

## 13. Sumy kontrolne MSI

`TARGET_AGENT_SHA256` jest opcjonalne.

Jeżeli podano:

- musi mieć dokładnie 64 znaki hex;
- zwracaj małymi literami;
- aplikacja ma odmówić startu przy niepoprawnej wartości.

Nie pobieraj automatycznie całego MSI przy każdym starcie.

Dodaj opcjonalny skrypt administracyjny:

```text
scripts/calculate-msi-sha256.sh
```

Skrypt:

1. pobiera MSI do pliku tymczasowego;
2. oblicza SHA-256;
3. wypisuje wynik;
4. usuwa plik tymczasowy;
5. działa z `set -Eeuo pipefail`;
6. nie modyfikuje automatycznie konfiguracji produkcyjnej.

---

## 14. Logowanie i obserwowalność

Loguj do stdout/stderr, aby logi trafiały do journald.

Format produkcyjny: jedna linia JSON.

Każdy wpis ma zawierać:

```text
timestamp
level
message
request_id
method
path
status_code
duration_ms
client_ip
upstream_status
```

Nie loguj:

- `Authorization`;
- `X-API-Key`;
- `X-Admin-API-Key`;
- hasła Wazuh;
- JWT;
- pełnej konfiguracji środowiska;
- odpowiedzi zawierających agentów;
- query string, jeżeli mógłby zawierać dane wrażliwe.

Obsłuż `X-Request-ID`:

- przyjmij poprawny, krótki identyfikator od Nginx;
- gdy brak — wygeneruj UUID;
- zwróć go w odpowiedzi.

Dodaj middleware czasu wykonania.

Loguj:

- start i zatrzymanie aplikacji;
- powodzenie pierwszego połączenia z Wazuh;
- odświeżenie JWT bez wartości tokenu;
- przejście na stale cache;
- duplikaty nazw agentów;
- niezgodność wersji managera i docelowego agenta;
- błędy upstream bez sekretów.

---

## 15. OpenAPI i dokumentacja

Gdy:

```text
DOCS_ENABLED=false
```

wyłącz:

```text
/docs
/redoc
/openapi.json
```

Gdy `true`, udostępnij je lokalnie przez FastAPI, ale przykładowa konfiguracja Nginx ma blokować je dla sieci klientów lub wymagać adresu administracyjnego.

Dodaj opisy, przykłady i poprawne modele odpowiedzi w OpenAPI.

---

## 16. Nagłówki bezpieczeństwa

Aplikacja lub Nginx ma zwracać:

```text
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cache-Control: no-store
Content-Security-Policy: default-src 'none'
```

Dla manifestu dopuszczalne jest prywatne cache maksymalnie 30 sekund.

CORS ma być całkowicie wyłączony.

Nie implementuj cookies ani sesji.

---

## 17. Konfiguracja Nginx

Przygotuj kompletny plik:

```text
deploy/nginx/wazuh-bootstrap-api.conf
```

Założenia:

```text
listen 8443 ssl;
server_name wazuh-srv.ad.citronex.pl;
proxy_pass http://127.0.0.1:8765;
```

Użyj placeholderów dla:

```text
ssl_certificate
ssl_certificate_key
dozwolonych podsieci
```

Przykładowe zasady:

```nginx
allow 192.168.0.0/16;
allow 172.16.0.0/12;
deny all;
```

Nie zakładaj, że dokładnie te sieci mają zostać użyte produkcyjnie. Oznacz je jako wymagające przeglądu.

Wymagania Nginx:

- TLS 1.2 i TLS 1.3;
- `server_tokens off`;
- `client_max_body_size 16k`;
- `proxy_http_version 1.1`;
- `proxy_set_header Host $host`;
- `proxy_set_header X-Real-IP $remote_addr`;
- `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`;
- `proxy_set_header X-Forwarded-Proto $scheme`;
- `proxy_set_header X-Request-ID $request_id`;
- connect timeout 3 s;
- read timeout 15 s;
- rate limit oddzielnie dla client i admin;
- brak buforowania odpowiedzi zawierających agentów;
- `/health/live` i `/health/ready` mogą mieć osobny, wyższy limit;
- nie przekazuj klientowi szczegółów błędu upstream.

Nie generuj automatycznie samopodpisanego certyfikatu produkcyjnego. W dokumentacji opisz użycie certyfikatu z firmowego CA.

---

## 18. Usługa systemd

Przygotuj:

```text
deploy/systemd/wazuh-bootstrap-api.service
```

Minimalne wymagania:

```ini
[Unit]
Description=Wazuh Bootstrap API
After=network-online.target wazuh-manager.service
Wants=network-online.target

[Service]
Type=simple
User=wazuh-bootstrap
Group=wazuh-bootstrap
WorkingDirectory=/opt/wazuh-bootstrap-api
EnvironmentFile=/etc/wazuh-bootstrap-api.env
ExecStart=/opt/wazuh-bootstrap-api/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8765 --workers 1 --proxy-headers --forwarded-allow-ips=127.0.0.1
Restart=on-failure
RestartSec=5
TimeoutStartSec=30
TimeoutStopSec=20

NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
```

Zweryfikuj, czy hardening nie blokuje wymaganych połączeń sieciowych ani importów Pythona.

Nie dawaj użytkownikowi serwisu dostępu do:

```text
/var/ossec/etc/client.keys
/usr/share/wazuh-dashboard/
/etc/shadow
```

Serwis ma korzystać wyłącznie z Wazuh HTTPS API.

Plik środowiskowy:

```text
/etc/wazuh-bootstrap-api.env
```

Uprawnienia:

```text
root:wazuh-bootstrap
0640
```

---

## 19. Instalator

`scripts/install.sh` ma:

1. wymagać roota;
2. wykrywać Ubuntu/Debian;
3. instalować tylko niezbędne pakiety:
   - `python3`;
   - `python3-venv`;
   - `python3-pip`;
   - opcjonalnie `nginx`, jeśli podano `--with-nginx`;
4. utworzyć systemowego użytkownika i grupę `wazuh-bootstrap`;
5. skopiować projekt do `/opt/wazuh-bootstrap-api`;
6. utworzyć `.venv`;
7. zainstalować zależności z `requirements.lock`;
8. nie instalować pakietów globalnie przez `pip`;
9. utworzyć `/etc/wazuh-bootstrap-api.env` z przykładu tylko wtedy, gdy nie istnieje;
10. nigdy nie nadpisywać istniejących sekretów;
11. sprawdzić właścicieli i uprawnienia;
12. zainstalować unit systemd;
13. wykonać `systemctl daemon-reload`;
14. wykonać walidację konfiguracji przed startem;
15. włączyć i uruchomić usługę dopiero po poprawnej walidacji;
16. wykonać lokalny smoke test;
17. jasno wypisać dalsze kroki dotyczące TLS i Nginx.

Obsłuż:

```text
./scripts/install.sh
./scripts/install.sh --with-nginx
./scripts/install.sh --upgrade
```

Tryb `--upgrade`:

- zachowuje env;
- aktualizuje kod i venv;
- wykonuje test importu;
- restartuje usługę;
- sprawdza health;
- w razie nieudanego health-check zwraca kod błędu i czytelny komunikat.

---

## 20. Deinstalator

`scripts/uninstall.sh`:

- zatrzymuje i wyłącza usługę;
- usuwa unit;
- usuwa `/opt/wazuh-bootstrap-api`;
- domyślnie zachowuje `/etc/wazuh-bootstrap-api.env`;
- usuwa env dopiero przy `--purge`;
- nie zmienia Wazuh Managera;
- nie usuwa Nginx jako pakietu;
- może usunąć tylko własny plik konfiguracyjny Nginx po jednoznacznym parametrze;
- wypisuje wykonane działania.

---

## 21. Skrypt generowania kluczy

`scripts/generate-api-keys.py` ma generować dwa niezależne klucze za pomocą `secrets.token_urlsafe`.

Wynik:

```dotenv
CLIENT_API_KEY=...
ADMIN_API_KEY=...
```

Nie zapisuj ich automatycznie do repozytorium.

Dodaj możliwość:

```text
python3 scripts/generate-api-keys.py --write /etc/wazuh-bootstrap-api.keys
```

Plik zapisany przez skrypt ma otrzymać tryb `0600`.

---

## 22. Smoke test

`scripts/smoke-test.sh` ma sprawdzić:

```text
/health/live
/health/ready
/api/v1/manifest
/api/v1/agents/<HOSTNAME>
```

Klucze pobiera z parametrów lub bezpiecznie z pliku env, jeśli uruchomiony jako root.

Nie wypisuje kluczy.

Zwraca kod różny od zera przy każdym błędzie.

---

## 23. Dokumentacja dla przyszłego skryptu GPO

W `docs/GPO-CONSUMER.md` opisz kontrakt, ale nie twórz jeszcze pełnego skryptu naprawczego.

Pokaż bezpieczne przykłady PowerShell:

```powershell
$Headers = @{
    'X-API-Key' = $ApiKey
}

$Manifest = Invoke-RestMethod `
    -Uri 'https://wazuh-srv.ad.citronex.pl:8443/api/v1/manifest' `
    -Headers $Headers

$AgentState = Invoke-RestMethod `
    -Uri ("https://wazuh-srv.ad.citronex.pl:8443/api/v1/agents/{0}" -f $env:COMPUTERNAME) `
    -Headers $Headers
```

Dokumentacja ma wyjaśniać przyszłą logikę:

```text
Prawidłowy client.keys:
    naprawa lub aktualizacja bez ponownego enrollmentu

Brak wazuh-agent.exe lub WazuhSvc, ale prawidłowy client.keys:
    kopia client.keys i ossec.conf
    MSI repair/update
    przywrócenie plików
    wazuh-agent.exe install-service, gdy usługa nie istnieje
    uruchomienie usługi

Brak client.keys, ale agent istnieje w managerze:
    nie zgaduj klucza
    wymagany kontrolowany re-enrollment zgodnie z polityką administratora

Brak client.keys i brak agenta w managerze:
    instalacja od zera i enrollment
```

Podkreśl, że Bootstrap API:

- nie potwierdza zgodności lokalnego `client.keys` z managerem;
- nie zwraca klucza;
- jedynie informuje, czy rekord nazwy istnieje po stronie managera.

---

## 24. RBAC Wazuh

W `docs/WAZUH-RBAC.md` opisz:

### Wariant startowy

Można tymczasowo użyć istniejącego konta `wazuh-wui` w pliku env, ale jest to rozwiązanie przejściowe.

### Wariant docelowy

Utworzyć dedykowanego użytkownika Wazuh Server API z minimalnymi prawami:

```text
agent:read
group:read
manager:read
```

Nie automatyzuj utworzenia użytkownika w `install.sh`.

Jeżeli podajesz konkretne polecenia Dev Tools do utworzenia polityki, roli, użytkownika i mapowania, muszą być zweryfikowane względem API Wazuh 4.14.6. Jeśli nie możesz ich wiarygodnie zweryfikować, podaj instrukcję ręczną i odwołanie do oficjalnej dokumentacji zamiast wymyślać payload.

Serwis powinien sprawdzać przy starcie dostęp do wszystkich trzech potrzebnych endpointów i zgłaszać brak uprawnień jako readiness failure.

---

## 25. Testy

Wymagane testy jednostkowe i integracyjne.

### 25.1 Konfiguracja

Testy:

- brak klucza;
- `CHANGE_ME`;
- klucz za krótki;
- identyczne klucze;
- nieprawidłowy SHA-256;
- `TARGET_AGENT_VERSION=auto`;
- nieprawidłowy URL;
- `verify_tls=true` z brakującym CA;
- poprawna konfiguracja.

### 25.2 Uwierzytelnianie

Testy:

- brak nagłówka;
- zły klucz;
- poprawny klucz kliencki;
- klucz kliencki na endpoint admina;
- poprawny admin;
- porównanie w stałym czasie na poziomie użytej funkcji.

### 25.3 Klient Wazuh

Testy:

- logowanie raw token;
- logowanie JSON token;
- cache JWT;
- odświeżenie przed `exp`;
- równoległe odświeżenie wykonuje tylko jedno logowanie;
- retry po `401`;
- brak retry po `403`;
- timeout;
- `429`;
- `5xx`;
- `error != 0`;
- niepoprawny JSON;
- paginacja agentów;
- paginacja grup.

### 25.4 Endpoint agentów

Testy:

- agent istnieje;
- agent nie istnieje;
- FQDN zostaje skrócony;
- różna wielkość liter;
- duplikaty nazw → `409`;
- `ip` jest używane zamiast `registerIP`;
- ID `000` jest pomijane;
- brak wersji;
- brak grup;
- zła nazwa hosta;
- cache świeży;
- stale cache;
- brak cache i niedostępny upstream → `503`.

### 25.5 Manifest

Testy:

- wersja jawna;
- wersja `auto`;
- URL wygenerowany;
- URL jawny;
- SHA-256;
- manager równy agentowi;
- manager nowszy;
- agent nowszy niż manager → `503`.

### 25.6 Bezpieczeństwo

Testy:

- odpowiedzi nie zawierają sekretów;
- błędy nie zawierają upstream response;
- docs wyłączone;
- nagłówki bezpieczeństwa;
- `Cache-Control`;
- `X-Request-ID`.

Minimalne pokrycie:

```text
90%
```

Komendy:

```bash
ruff check .
ruff format --check .
mypy app
pytest --cov=app --cov-report=term-missing --cov-fail-under=90
```

Wszystkie mają przechodzić.

---

## 26. Jakość kodu

Wymagania:

- pełne type hints;
- brak `Any`, gdy można określić typ;
- małe, testowalne funkcje;
- brak globalnego mutowalnego stanu poza kontrolowanym lifespan/cache;
- asynchroniczny klient HTTP;
- brak blokującego I/O w endpointach;
- zależności wstrzykiwane przez FastAPI;
- modele upstream oddzielone od modeli publicznych;
- brak zwracania surowych słowników Wazuh bez walidacji;
- brak `except Exception: pass`;
- kontrolowane zamknięcie `AsyncClient`;
- UTC wszędzie;
- czytelne komunikaty administratora;
- brak sekretów w repozytorium.

---

## 27. README

README ma zawierać:

1. krótki opis;
2. diagram architektury;
3. wymagania;
4. szybkie uruchomienie deweloperskie;
5. instalację produkcyjną;
6. konfigurację env;
7. konfigurację Nginx;
8. testy;
9. przykłady `curl`;
10. aktualizację;
11. rollback;
12. troubleshooting;
13. wskazanie, że API jest tylko do odczytu;
14. informacje o bezpieczeństwie;
15. linki do dokumentacji w katalogu `docs`.

Przykłady:

```bash
curl -fsS http://127.0.0.1:8765/health/live

curl -fsS \
  -H "X-API-Key: $CLIENT_API_KEY" \
  http://127.0.0.1:8765/api/v1/manifest

curl -fsS \
  -H "X-API-Key: $CLIENT_API_KEY" \
  http://127.0.0.1:8765/api/v1/agents/LAP006

curl -fsS \
  -H "X-Admin-API-Key: $ADMIN_API_KEY" \
  http://127.0.0.1:8765/api/v1/agents
```

---

## 28. Kryteria akceptacji

Projekt jest ukończony dopiero, gdy:

- aplikacja startuje na Pythonie 3.12;
- loguje się do lokalnego Wazuh API;
- poprawnie odświeża JWT;
- manifest zawiera managera i wersję docelową;
- agent jest wyszukiwany dokładnie po nazwie;
- `lastKnownIp` pochodzi z pola `ip`;
- grupy są poprawnie normalizowane;
- pełne listy są paginowane;
- klient i admin mają rozdzielone uprawnienia;
- endpointy nie wykonują zmian w Wazuh;
- błędy upstream nie ujawniają sekretów;
- stale cache działa zgodnie ze specyfikacją;
- testy mają minimum 90% pokrycia;
- `ruff` i `mypy` przechodzą;
- instalator tworzy usługę systemd;
- usługa działa jako nieuprzywilejowany użytkownik;
- domyślnie nasłuchuje tylko na localhost;
- przykładowy Nginx zapewnia TLS i allowlist;
- dokumentacja umożliwia wdrożenie bez czytania kodu;
- repozytorium nie zawiera prawdziwych poświadczeń.

---

## 29. Sposób pracy Codex

1. Najpierw utwórz kompletną strukturę projektu.
2. Zaimplementuj modele, konfigurację i klienta Wazuh.
3. Zaimplementuj endpointy.
4. Zaimplementuj cache, bezpieczeństwo i logowanie.
5. Napisz testy.
6. Uruchom wszystkie testy i narzędzia jakości.
7. Napraw wszystkie wykryte problemy.
8. Utwórz pliki wdrożeniowe i dokumentację.
9. Wykonaj lokalny smoke test z mockowanym Wazuh.
10. Na końcu pokaż:
   - drzewo plików;
   - wykonane komendy;
   - wyniki testów;
   - pokrycie;
   - listę ustawień, które administrator musi uzupełnić;
   - konkretne komendy wdrożenia na serwerze.

Nie pytaj o drobne decyzje implementacyjne. Przyjmij bezpieczne, rozsądne wartości zgodne z tym dokumentem.

Jeżeli lokalne API Wazuh 4.14.6 różni się od założonego kontraktu:

- nie twórz fikcyjnych danych;
- zachowaj publiczny kontrakt Bootstrap API;
- dodaj adapter dla faktycznej odpowiedzi Wazuh;
- udokumentuj różnicę;
- dodaj test regresyjny.

---

## 30. Oficjalne źródła do weryfikacji

Wazuh Server API:

- https://documentation.wazuh.com/current/user-manual/api/getting-started.html
- https://documentation.wazuh.com/current/user-manual/api/reference.html
- https://documentation.wazuh.com/current/user-manual/api/rbac/index.html
- https://documentation.wazuh.com/current/user-manual/api/rbac/reference.html
- https://documentation.wazuh.com/current/user-manual/agent/agent-management/listing/listing.html
- https://raw.githubusercontent.com/wazuh/wazuh/v4.14.6/api/api/spec/spec.yaml

Wazuh Agent:

- https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html
- https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/troubleshooting.html
- https://documentation.wazuh.com/current/user-manual/agent/agent-management/remote-upgrading/upgrading-agent.html

FastAPI:

- https://fastapi.tiangolo.com/advanced/settings/
- https://fastapi.tiangolo.com/deployment/concepts/
- https://fastapi.tiangolo.com/deployment/server-workers/

Nie kopiuj kodu z przypadkowych blogów. Oficjalna dokumentacja i aktualny schemat Wazuh 4.14.6 mają pierwszeństwo.
