# Testy instalatora Wazuh dla GPO

Testy destrukcyjne wolno wykonywać wyłącznie na wyznaczonym komputerze pilotażowym, z działającym
agentem stanowiącym bazę odtworzeniową. Harness nie jest skryptem GPO i nie może trafić do SYSVOL.

## Zabezpieczenia

`tests/powershell/Invoke-WazuhAgent.Destructive.Tests.ps1` przed pierwszym scenariuszem:

1. wymaga podniesionej sesji oraz jawnego przełącznika potwierdzającego;
2. zatrzymuje agenta i kopiuje cały katalog instalacji z ACL;
3. zapisuje hashe `client.keys`, `ossec.conf` i pliku wykonywalnego;
4. eksportuje wpis MSI z rejestru;
5. pobiera aktualny MSI z manifestu i sprawdza SHA-256 oraz Authenticode;
6. pobiera podpisany MSI poprzedniej wersji dla rzeczywistego testu aktualizacji;
7. odtwarza bazę po każdym scenariuszu oraz ponownie w zewnętrznym bloku `finally`.

Chroniona baza znajduje się w:

```text
C:\ProgramData\Citronex\WazuhBootstrap\DestructiveTests\<RUN-ID>\baseline
```

Jawny katalog raportu nie zawiera klucza API, hasła enrollmentu ani `client.keys`.

## Uruchomienie

W podniesionym Windows PowerShell 5.1, z katalogu repozytorium:

```powershell
.\wazuh-bootstrap-api\tests\powershell\Invoke-WazuhAgent.Destructive.Tests.ps1 `
  -DeploymentScript .\wazuh-bootstrap-api\deploy\gpo\Install-WazuhAgent.ps1 `
  -ApiEnvironmentFile .\wazuh-bootstrap-api\deploy\env\wazuh-bootstrap-api.env `
  -IUnderstandThisWillModifyWazuh `
  -ReportDirectory C:\Temp\wazuh-gpo-test-results
```

Pojedyncze przypadki można powtórzyć parametrem `-Scenario`, np.:

```powershell
-Scenario missing-ossec-conf,missing-service
```

## Zakres macierzy

Pełny przebieg obejmuje:

- poprawny audyt i idempotentne uruchomienie aktywne;
- błędny klucz API;
- zatrzymaną i wyłączoną usługę;
- osierocony `authd.pass`;
- nieprawidłowe ID, nazwę hosta i wiele rekordów w `client.keys`;
- brakujący i pusty `ossec.conf`;
- brakujący i uszkodzony plik wykonywalny;
- brak usługi i nieprawidłową ścieżkę binarną usługi;
- wymuszoną naprawę;
- niespójne metadane wersji w rejestrze;
- rzeczywistą aktualizację ze starszego podpisanego MSI;
- odmowę downgrade'u z wersji nowszej;
- pełną reinstalację z zachowaniem tożsamości.

Sukces wymaga kodu procesu `0`, wszystkich scenariuszy z `passed=true`, działającej usługi
`WazuhSvc` w trybie Automatic oraz zgodności hashy krytycznych plików z bazą. Na końcu należy
sprawdzić `/health/ready` i `/api/v1/agents/<HOSTNAME>`.

## Zweryfikowany przebieg pilota

Na komputerze `ZGOWST029007` wykonano pełną macierz na finalnym kodzie 23 lipca 2026 r.
Wynik przebiegu `20260723T070549Z`: 21/21 zaliczonych, 0 błędów. Końcowe odtworzenie pozostawiło
`WazuhSvc` jako Running/Automatic, a produkcyjne API zwróciło `ready`, jeden aktywny rekord
hosta, wersję agenta 4.14.6 i `stale=false`.
