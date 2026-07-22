# Model bezpieczeństwa

Serwis działa jako nieuprzywilejowany `wazuh-bootstrap`, nasłuchuje tylko na localhost i nie
ma dostępu do plików Wazuh. Nie odczytuje ani nie publikuje `client.keys`; nie rejestruje,
usuwa, aktualizuje ani restartuje agentów. Z Wazuh korzysta wyłącznie przez HTTPS API z
minimalnym RBAC. Klucze klienta i administratora są rozdzielone i porównywane przez
`secrets.compare_digest`.

Sekrety są tylko w `/etc/wazuh-bootstrap-api.env` (`root:wazuh-bootstrap`, `0640`). Nie
umieszczaj ich w repozytorium, parametrach URL, ticketach ani logach. Rotacja klucza wymaga
zmiany env i restartu usługi. JWT Wazuh pozostaje w pamięci procesu. Logi JSON nie zawierają
query stringów, nagłówków uwierzytelnienia, tokenów ani odpowiedzi z agentami.

W produkcji ustaw `WAZUH_API_VERIFY_TLS=true`. Bez `WAZUH_API_CA_FILE` używany jest systemowy
magazyn CA; przy prywatnym CA wskaż plik PEM czytelny przez usługę. `false` jest wyłącznie
wartością ułatwiającą lokalne połączenie z domyślnym certyfikatem Wazuh i powinno być
zaakceptowanym, udokumentowanym wyjątkiem.

Nginx zapewnia certyfikat z firmowego CA, TLS 1.2/1.3, allowlistę, osobne limity klient/admin,
małe body i timeouty. Przykładowe podsieci są placeholderami. Zapora hosta powinna dopuścić
8443 tylko ze zweryfikowanych sieci; port 8765 nie może być wystawiony. CORS, cookies i sesje
nie są implementowane. OpenAPI jest domyślnie wyłączone i blokowane przez Nginx.

Systemd ogranicza system plików, urządzenia, capabilities, rodziny adresów i bezpośrednio
blokuje `/var/ossec/etc/client.keys`, dashboard oraz `/etc/shadow`. Hardening nadal dopuszcza
AF_INET/AF_INET6 dla HTTPS do Wazuh i AF_UNIX dla działania bibliotek/runtime.
