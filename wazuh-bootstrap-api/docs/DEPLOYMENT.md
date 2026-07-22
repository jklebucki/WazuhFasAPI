# Wdrożenie Ubuntu/Debian

## Przygotowanie

Wymagane są Python 3.12+, dostęp localhost do `https://127.0.0.1:55000`, konto Wazuh z
minimalnym RBAC, firmowy rekord DNS/certyfikat oraz zaakceptowana allowlista. Serwis nie
wymaga i nie może otrzymać dostępu do katalogów Wazuh.

```bash
sudo ./scripts/install.sh --with-nginx
```

Pierwsza instalacja tworzy `/etc/wazuh-bootstrap-api.env` z placeholderami i bezpiecznie
kończy się przed startem. Wygeneruj klucze, wpisz sekrety i parametry:

```bash
sudo python3 /opt/wazuh-bootstrap-api/scripts/generate-api-keys.py \
  --write /root/wazuh-bootstrap.keys
sudoedit /etc/wazuh-bootstrap-api.env
sudo /opt/wazuh-bootstrap-api/.venv/bin/python \
  /opt/wazuh-bootstrap-api/scripts/validate-config.py \
  --env-file /etc/wazuh-bootstrap-api.env
sudo /path/to/source/scripts/install.sh --upgrade
```

Przenieś wartości kluczy ręcznie i bezpiecznie; usuń tymczasowy plik root po zatwierdzeniu.
Ustaw env `root:wazuh-bootstrap 0640`. Przy `TARGET_AGENT_VERSION=auto` docelowa wersja jest
wersją managera. Pusty URL MSI jest generowany. SHA-256 oblicz jednorazowo skryptem
`calculate-msi-sha256.sh URL`, zweryfikuj niezależnie i wstaw do env.

## TLS i Nginx

Umieść certyfikat firmowego CA i klucz w katalogu dostępnym tylko dla root/Nginx. Edytuj
`/etc/nginx/sites-available/wazuh-bootstrap-api.conf`: DNS, obie ścieżki TLS i każdą regułę
`allow`. Przykładowe RFC1918 nie są rekomendacją produkcyjną.

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo ss -lntp | grep -E ':(8443|8765)\b'
```

8765 ma widnieć wyłącznie na 127.0.0.1. Certyfikat powinien mieć SAN zgodny z DNS. Nie twórz
samopodpisanego certyfikatu produkcyjnego.

## Weryfikacja

```bash
sudo systemctl status wazuh-bootstrap-api
curl -fsS http://127.0.0.1:8765/health/live
curl -fsS http://127.0.0.1:8765/health/ready
sudo /opt/wazuh-bootstrap-api/scripts/smoke-test.sh --hostname LAP006
sudo journalctl -u wazuh-bootstrap-api -n 100 --no-pager
```

Z zaufanej stacji sprawdź HTTPS, łańcuch certyfikatu i odrzucenie adresu spoza allowlisty.

## Aktualizacja, rollback i usunięcie

`sudo ./scripts/install.sh --upgrade` zachowuje env, tworzy kopię poprzedniego katalogu,
odtwarza venv, waliduje, restartuje i wykonuje smoke test. Przy błędzie skrypt wypisuje ścieżkę
kopii rollback. Aby wycofać: zatrzymaj usługę, zamień `/opt/wazuh-bootstrap-api` na wskazaną
kopię, odtwórz venv z jej locka, uruchom usługę i smoke test.

```bash
sudo ./scripts/uninstall.sh
sudo ./scripts/uninstall.sh --purge --remove-nginx-config
```

Pierwsza forma zachowuje env. Druga usuwa również env i własne pliki Nginx, ale nigdy pakiet
Nginx ani Wazuh. Usunięcie env jest nieodwracalne bez kopii.

## Typowe problemy

- readiness 503: sprawdź logi, RBAC, poświadczenia, CA oraz zgodność wersji;
- manifest 503 przy działającym Wazuh: target jest nowszy niż manager;
- 401 Bootstrap: właściwy klucz/nagłówek i rotacja env;
- Nginx 403: allowlista;
- timeout: lokalny Wazuh API, firewall/namespace i ustawienia timeoutów;
- stale: upstream był chwilowo niedostępny; `dataAsOf` wskazuje wiek danych.
