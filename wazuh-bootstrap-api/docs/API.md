# Kontrakt HTTP

Bazowa ścieżka: `/api/v1`. Odpowiedzi z datami używają ISO 8601 UTC. API jest wyłącznie
do odczytu; jedyne logowanie upstream to `POST /security/user/authenticate?raw=true`, po nim
wykonywane są tylko `GET /manager/info`, `GET /agents` i `GET /groups`.

Po włączeniu `DOCS_ENABLED` kontrakt jest dostępny jako OpenAPI pod `/openapi.json`,
Swagger UI pod `/docs` oraz ReDoc pod `/redoc`. Schematy `ClientApiKey` i `AdminApiKey`
odpowiadają nagłówkom pokazanym w tabeli i są dostępne przez przycisk **Authorize**.

| Endpoint | Uwierzytelnienie | Znaczenie |
|---|---|---|
| `GET /health/live` | brak | proces działa; bez kontaktu z Wazuh |
| `GET /health/ready` | brak | świeży kontakt z managerem i zgodność wersji |
| `GET /api/v1/manifest` | `X-API-Key` | docelowa wersja MSI i parametry managera |
| `GET /api/v1/agents/{hostname}` | `X-API-Key` | dokładne, case-insensitive sprawdzenie nazwy |
| `GET /api/v1/agents` | `X-Admin-API-Key` | filtrowana, stronicowana lista agentów |
| `GET /api/v1/groups` | `X-Admin-API-Key` | lista grup |
| `GET /api/v1/groups/{name}` | `X-Admin-API-Key` | grupa i jej publiczne rekordy agentów |

Lista agentów przyjmuje wyłącznie `status`, `group`, `platform`, `name`, `limit` (1–500) i
`offset` (od 0). Nie przyjmuje WQL. Nazwa hosta ma 1–63 znaki ASCII: litery, cyfry, kropki
i myślniki. Końcowa kropka jest usuwana, a FQDN skracany przed pierwszą kropką.

Duplikaty dokładnej nazwy dają `409`, `duplicateCount` oraz wyłącznie `id`, `name`, `status`,
`groups`, `lastKeepAlive`. API nigdy nie wybiera arbitralnie rekordu. ID `000` jest pomijane.
`lastKnownIp` zawsze pochodzi z Wazuh `ip`, natomiast `registrationIp` z `registerIP`.

Brak/zły klucz daje zawsze `401 {"detail":"Unauthorized"}`. Niedostępny lub odmawiający
Wazuh bez użytecznego cache daje `503 {"detail":"Service Unavailable"}`. Stary cache ma
`stale: true`, pierwotne `dataAsOf` oraz `Warning: 110 - "Response is stale"`. Odpowiedzi
agentów mają `Cache-Control: no-store`; manifest `private, max-age=30`.
