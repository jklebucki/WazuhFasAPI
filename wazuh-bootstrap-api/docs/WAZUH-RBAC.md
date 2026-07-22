# Minimalny RBAC Wazuh

Konto potrzebuje dokładnie następujących akcji odczytowych dla odpowiednich zasobów:

- `agent:read` dla `agent:id:*`;
- `group:read` dla `group:id:*`;
- `manager:read` dla `*:*:*`.

Na start można tymczasowo wskazać istniejące konto `wazuh-wui` w chronionym pliku env. Jest
to wariant przejściowy, zwykle szerszy niż potrzebny. Docelowo administrator Wazuh powinien
utworzyć dedykowanego użytkownika API, politykę z trzema akcjami, rolę i mapowanie użytkownika
do roli. Instalator celowo tego nie automatyzuje.

Payloady i endpointy zarządzania security zależą od wersji. Nie zamieszczamy niezweryfikowanych
poleceń modyfikujących RBAC. Dla 4.14.6 wykonaj procedurę ręcznie według oficjalnego schematu
tej wersji: [Wazuh API RBAC](https://documentation.wazuh.com/4.14/user-manual/api/rbac/index.html)
oraz [spec.yaml 4.14.6](https://raw.githubusercontent.com/wazuh/wazuh/v4.14.6/api/api/spec/spec.yaml).

Po konfiguracji sprawdź tym kontem `GET /manager/info`, `GET /agents?limit=1` i
`GET /groups?limit=1`. `403` lub `401` powoduje brak readiness; treść błędu upstream nie jest
publikowana klientowi. Konto nie powinno otrzymać żadnych akcji `create`, `delete`, `update`,
`modify`, `restart`, `upgrade`, `enroll` ani dostępu do security management.
