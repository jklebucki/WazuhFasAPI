# Konsument GPO dla Windows

Produkcyjny skrypt znajduje się w `deploy/gpo/Install-WazuhAgent.ps1`, a jego konfiguracja
w `deploy/gpo/WazuhAgentGpo.config.example.json`. Pełną procedurę publikacji przez Active
Directory opisuje [GPO-DEPLOYMENT.md](GPO-DEPLOYMENT.md).

## Granica zaufania

Bootstrap API informuje, czy rekord nazwy komputera istnieje w managerze, ale nie potwierdza,
że lokalny `client.keys` odpowiada temu rekordowi. API nie udostępnia kluczy i nie wykonuje
enrollmentu. Skrypt GPO respektuje tę granicę i nigdy nie pobiera `client.keys` z managera.

Skrypt korzysta z dwóch tajemnic przechowywanych poza kodem, JSON-em i SYSVOL:

- klucz `X-API-Key` tylko do odczytu manifestu i stanu własnej nazwy komputera;
- hasło enrollmentu Wazuh, używane wyłącznie, gdy komputer nie ma klucza i manager nie ma
  rekordu tej nazwy.

Pliki są odczytywane przez konto komputera z chronionego udziału SMB. Hasło enrollmentu nie
jest przekazywane w argumentach `msiexec`; skrypt zapisuje je tymczasowo jako chroniony
`authd.pass`, oczekuje na utworzenie prawidłowego `client.keys`, a następnie usuwa plik hasła.
Aktywne uruchomienie usuwa również osierocony `authd.pass` pozostawiony przez awarię zasilania
lub przerwanie poprzedniej próby; tryb `auditOnly` nie modyfikuje plików.

## Macierz decyzji

| Lokalny stan | Stan Bootstrap API | Działanie |
|---|---|---|
| poprawny `client.keys`, wersja docelowa, kompletna usługa | dowolny jednoznaczny | zapewnij autostart i uruchomienie |
| poprawny `client.keys`, wersja starsza | dowolny jednoznaczny | kopia klucza i konfiguracji, aktualizacja MSI, odtworzenie, start |
| poprawny `client.keys`, brak/uszkodzenie EXE lub konfiguracji | dowolny jednoznaczny | chroniona kopia tożsamości, kontrolowana reinstalacja MSI, odtworzenie, start |
| poprawny `client.keys`, brak lub błędna rejestracja usługi | dowolny jednoznaczny | odtworzenie usługi z poprawną ścieżką i kontem `LocalSystem`, start |
| brak/poprawności klucza | rekord istnieje | kod 30, ręczna rekonsyliacja; brak enrollmentu |
| brak/poprawności klucza | duplikaty (`409`) | kod 30, ręczne usunięcie konfliktu |
| brak/poprawności klucza | rekord nie istnieje | instalacja/naprawa i enrollment z chronionym hasłem |
| dane API oznaczone `stale=true` | dowolny | brak mutacji, błąd kontrolowany |
| agent nowszy niż target | dowolny | brak downgrade'u; tylko kontrola usługi |

Za strukturalnie poprawny uznawany jest dokładnie jeden rekord `client.keys`, z ID innym niż
`000` i nazwą równą `%COMPUTERNAME%` bez uwzględniania wielkości liter. To nadal nie jest
dowód zgodności z wpisem managera; skrypt nie loguje ani nie przesyła zawartości klucza.

## Zabezpieczenia pakietu MSI

Przed `msiexec` skrypt:

1. akceptuje tylko HTTPS;
2. zezwala wyłącznie na hosty z `allowedDownloadHosts`, także po każdym przekierowaniu;
3. domyślnie wymaga SHA-256 zwróconego przez manifest;
4. wymaga poprawnego podpisu Authenticode i zgodnego podmiotu certyfikatu;
5. używa chronionego katalogu roboczego w `%ProgramData%`;
6. zachowuje `client.keys` i poprawny `ossec.conf` podczas reinstalacji lub aktualizacji;
7. przy uszkodzeniu tej samej wersji wykonuje kontrolowane odinstalowanie i ponowną
   instalację zweryfikowanego MSI (historyczne źródło Windows Installer nie jest wymagane);
8. rekonstruuje brakujący `ossec.conf` bez deklaracji XML, której parser Wazuh nie akceptuje;
9. nie wykonuje automatycznego downgrade'u ani trwałego odinstalowania agenta.

Po uszkodzeniu `ossec.conf` jego kopia diagnostyczna pozostaje wyłącznie w chronionym katalogu
roboczym. Plik `client.keys` nigdy nie jest umieszczany w raporcie jawnym.

Oficjalny instalator Wazuh obsługuje cichą instalację przez `msiexec /i ... /q`, zmienne
`WAZUH_MANAGER`, `WAZUH_REGISTRATION_SERVER`, `WAZUH_REGISTRATION_PORT`, `WAZUH_AGENT_NAME`
i inne opcje wdrożeniowe. Skrypt korzysta tylko z wartości zweryfikowanego manifestu. Zobacz
[oficjalną instrukcję Windows](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)
oraz [deployment variables](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/deployment-variables/deployment-variables-windows.html).

## Kody zakończenia

| Kod | Znaczenie |
|---:|---|
| 0 | sukces, brak wymaganej zmiany albo poprawny audyt |
| 10 | konfiguracja lokalna |
| 20 | Bootstrap API/TLS/uwierzytelnienie |
| 30 | konflikt wymagający administratora |
| 40 | pobranie, hash albo podpis MSI |
| 50 | błąd Windows Installer |
| 60 | usługa lub enrollment |
| 70 | nieoczekiwany błąd fail-closed |

Skrypt ustawia kategorię przed każdą fazą, dlatego GPO odróżnia konfigurację, API, paczkę,
Windows Installer i usługę. Konflikt to zawsze 30, a nieprzewidziany błąd poza tymi fazami ma
kod 70. Szczegółowa przyczyna jest zapisana bez sekretów w lokalnym logu JSONL.

## Logi

Domyślnie:

```text
C:\ProgramData\Citronex\WazuhBootstrap\Logs\WazuhAgentGpo-YYYYMMDD.jsonl
```

Katalog i pliki otrzymują ACL wyłącznie dla `SYSTEM` i lokalnych administratorów. Log zawiera
planowaną operację, wersje i wynik, ale nigdy klucz API, hasło enrollmentu ani `client.keys`.
Przy nieudanym MSI zabezpieczony katalog roboczy jest zachowywany do diagnostyki; po sukcesie
jest usuwany.

## Testy destrukcyjne

Harness `tests/powershell/Invoke-WazuhAgent.Destructive.Tests.ps1` jest przeznaczony wyłącznie
dla wyznaczonego komputera pilotażowego. Przed każdą zmianą kopiuje cały katalog agenta,
eksportuje rejestrację MSI, pobiera i weryfikuje paczki odtworzeniowe, a po każdym scenariuszu
oraz w zewnętrznym `finally` przywraca bazę. Szczegóły i komenda uruchomienia znajdują się w
[GPO-TESTING.md](GPO-TESTING.md).

## Wymagania sieciowe klienta

- HTTPS do `wazuh.ad.citronex.pl:8443`;
- HTTPS do hosta pakietów z manifestu (obecnie `packages.wazuh.com`) albo firmowego mirroru;
- TCP 1514 do managera;
- TCP 1515 do serwera enrollmentu tylko dla nowych agentów;
- zaufanie komputera do firmowego CA wystawiającego certyfikat Bootstrap API;
- dostęp SMB jako konto komputera do chronionych plików tajemnic.

Skrypt nie używa `-SkipCertificateCheck`, nie wyłącza walidacji TLS i nie otwiera portu 55000.
