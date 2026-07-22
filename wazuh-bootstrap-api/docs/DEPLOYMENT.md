# Wdrożenie produkcyjne

## Topologia

```text
GPO/Windows -> HTTPS wazuh.ad.citronex.pl:8443
            -> Nginx 192.168.21.17
            -> HTTP 192.168.21.15:8765
            -> FastAPI
            -> HTTPS localhost:55000 (Wazuh Server API)
```

Nginx jest usługą centralną i nie jest instalowany na serwerze Wazuh. `install.sh` oraz
`uninstall.sh` zarządzają wyłącznie aplikacją FastAPI na `192.168.21.15`.

## Katalog źródłowy i klonowanie repozytorium

Rekomendowanym miejscem na trwały checkout wdrożeniowy jest `/srv/WazuhFasAPI`. Dzięki temu
źródła pobierane z GitHuba są oddzielone od artefaktu uruchomieniowego w
`/opt/wazuh-bootstrap-api` oraz sekretów w `/etc/wazuh-bootstrap-api.env`.

```bash
cd /srv
sudo gh repo clone jklebucki/WazuhFasAPI /srv/WazuhFasAPI
cd /srv/WazuhFasAPI/wazuh-bootstrap-api
sudo ./scripts/install.sh
```

Polecenie z `sudo gh` jest właściwe dla publicznego repozytorium albo gdy konto `root` jest
uwierzytelnione w GitHub CLI. Dla prywatnego repozytorium bezpieczniej pozostawić checkout
własnością użytkownika posiadającego poświadczenia GitHuba:

```bash
sudo install -d -o jklebucki -g jklebucki -m 0755 /srv/WazuhFasAPI
gh repo clone jklebucki/WazuhFasAPI /srv/WazuhFasAPI
cd /srv/WazuhFasAPI/wazuh-bootstrap-api
sudo ./scripts/install.sh
```

Instalator rozpoznaje właściciela checkoutu i wykonuje operacje Git z jego uprawnieniami.
Alternatywnie checkout administrowany przez `root` może znajdować się w
`/usr/local/src/WazuhFasAPI`, a checkout użytkownika w
`/home/jklebucki/src/WazuhFasAPI`. Nie klonuj repozytorium bezpośrednio do
`/opt/wazuh-bootstrap-api`: ten katalog jest atomowo zastępowany podczas każdego wdrożenia.
Nie umieszczaj kodu w `/etc`, które służy wyłącznie konfiguracji hosta.

## 1. Centralny proxy 192.168.21.17

Aktywna konfiguracja:

```text
/etc/nginx/sites-available/wazuh-bootstrap-api.conf
/etc/nginx/sites-enabled/wazuh-bootstrap-api.conf
/etc/nginx/snippets/wazuh-bootstrap-proxy-headers.conf
```

Vhost używa wildcardu `/etc/ssl/cert_ad/ad.citronex.pl.{pem,key}`, TLS 1.2/1.3, portu 8443,
allowlisty `192.168.0.0/16`, osobnych rate limitów oraz backendu `192.168.21.15:8765`.
Moduł `libnginx-mod-http-headers-more-filter` usuwa nagłówek `Server`.

Po każdej zmianie:

```bash
sudo nginx -t
sudo systemctl reload nginx
curl -k -i https://127.0.0.1:8443/health/live \
  -H 'Host: wazuh.ad.citronex.pl'
```

Przed uruchomieniem FastAPI proxy zwraca kontrolowane 503.

## 2. Przygotowanie serwera Wazuh 192.168.21.15

Wymagane są Python 3.12+, konto API z minimalnym RBAC oraz dostęp do lokalnego portu 55000.
Pierwsze wywołanie tworzy użytkownika, grupę, katalog aplikacji i przykładowy env, po czym
bezpiecznie zatrzyma się, jeśli konfiguracja zawiera placeholdery:

```bash
sudo ./scripts/install.sh
```

Nie używaj `--with-nginx`; instalator celowo odrzuca tę opcję.

## 3. Konfiguracja i CA Wazuh API

Skopiuj ignorowany produkcyjny plik z komputera administracyjnego, a następnie zainstaluj go:

```bash
sudo install -o root -g wazuh-bootstrap -m 0640 \
  /ścieżka/do/wazuh-bootstrap-api.env \
  /etc/wazuh-bootstrap-api.env
```

Certyfikat API ma `SAN=localhost`, dlatego env używa `https://localhost:55000`. Utwórz
lokalny plik z publicznym certyfikatem serwera:

```bash
sudo sh -c \
  'openssl s_client -connect 127.0.0.1:55000 -servername localhost </dev/null 2>/dev/null |
   openssl x509 -out /etc/wazuh-bootstrap-api-wazuh-ca.pem'
sudo chown root:wazuh-bootstrap /etc/wazuh-bootstrap-api-wazuh-ca.pem
sudo chmod 0640 /etc/wazuh-bootstrap-api-wazuh-ca.pem
```

Zweryfikuj odcisk certyfikatu niezależnym kanałem przed zaufaniem mu.

## 4. Firewall backendu

FastAPI wiąże się wyłącznie z `192.168.21.15:8765`. Port ma być dostępny tylko z proxy:

```bash
sudo ufw allow from 192.168.21.17 to any port 8765 proto tcp
```

Przed zastosowaniem sprawdź bieżącą politykę `ufw status verbose`. Nie dodawaj ogólnego
`allow 8765`. W innych firewallach zastosuj równoważną regułę. Wazuh API 55000 nie jest
potrzebne centralnemu proxy i powinno pozostać ograniczone.

## 5. Start i test

Po zainstalowaniu env i CA:

```bash
sudo ./scripts/install.sh --upgrade
sudo systemctl status wazuh-bootstrap-api
sudo /opt/wazuh-bootstrap-api/scripts/smoke-test.sh --hostname LAP006
sudo ss -lntp | grep ':8765'
```

Oczekiwany bind to wyłącznie `192.168.21.15:8765`. Następnie z komputera domenowego:

```bash
curl -fsS https://wazuh.ad.citronex.pl:8443/health/live
curl -fsS https://wazuh.ad.citronex.pl:8443/health/ready
```

Nie używaj `-k`. Jeśli Windows zgłasza `CRYPT_E_REVOCATION_OFFLINE`, zapewnij klientom dostęp
do punktu dystrybucji CRL firmowego CA.

## Aktualizacja, rollback i usunięcie

```bash
cd /srv/WazuhFasAPI/wazuh-bootstrap-api
sudo ./scripts/install.sh --upgrade
sudo ./scripts/uninstall.sh
sudo ./scripts/uninstall.sh --purge
```

Przed instalacją i aktualizacją `install.sh` automatycznie wykonuje `git pull --ff-only`,
a następnie uruchamia ponownie aktualną wersję samego instalatora. Pull jest wykonywany jako
właściciel checkoutu. Wdrożenie zostaje przerwane, jeżeli checkout ma lokalne zmiany, działa
w trybie detached HEAD, nie ma upstreamu albo aktualizacja wymagałaby merge'a. Zapobiega to
niepowtarzalnym wdrożeniom i przypadkowemu nadpisaniu pracy administratora.

To jest pull-based deployment: jedno polecenie pobiera zatwierdzony stan gałęzi, buduje nowy
runtime, waliduje konfigurację, restartuje usługę i wykonuje smoke test. W kontrolowanym
wdrożeniu offline albo przy instalacji ze zweryfikowanego archiwum można pominąć synchronizację:

```bash
sudo ./scripts/install.sh --upgrade --no-git-pull
```

Deinstalator domyślnie zachowuje env. `--purge` usuwa env. Żadne z tych poleceń nie zmienia
centralnego Nginx ani Wazuh Managera.

## Typowe problemy

* proxy 503: backend jeszcze nie działa albo firewall blokuje 192.168.21.17;
* readiness 503: sprawdź RBAC, hasło, CA i zgodność wersji;
* 401: niewłaściwy klucz Bootstrap API;
* 403: klient jest poza allowlistą centralnego Nginx;
* TLS/CRL: sprawdź zaufanie do `ad-CERTSRV-CA` i dostępność CRL;
* stale: Wazuh był chwilowo niedostępny, a odpowiedź zawiera historyczne `dataAsOf`.


