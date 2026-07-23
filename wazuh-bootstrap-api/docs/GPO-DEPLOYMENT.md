# Wdrożenie skryptu Wazuh przez GPO

Instrukcja zakłada domenę `ad.citronex.pl`, Bootstrap API pod
`https://wazuh.ad.citronex.pl:8443` oraz uruchamianie skryptu jako `LocalSystem` w zasadach
komputera. Nazwy kontrolerów domeny, serwera plików, OU i grup dostosuj do środowiska.

## 1. Warunki wstępne

Przed GPO potwierdź:

```powershell
Invoke-RestMethod -Uri 'https://wazuh.ad.citronex.pl:8443/health/ready'
Test-NetConnection 192.168.21.15 -Port 1514
Test-NetConnection 192.168.21.15 -Port 1515
```

Bootstrap API powinno zwracać docelowy SHA-256 MSI. Skrypt domyślnie odmawia instalacji, jeśli
`targetAgent.sha256` jest pusty. Hash oficjalnej paczki oblicz jednorazowo na zaufanej stacji,
porównaj niezależnym kanałem i ustaw jako `TARGET_AGENT_SHA256` w konfiguracji API.

Manager musi mieć skonfigurowany bezpieczny enrollment. Wariant rekomendowany to hasło authd
oraz ograniczenie portu 1515 do sieci zarządzanych. Oficjalna procedura Wazuh znajduje się w
[Using password authentication](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/using-password-authentication.html).
Skrypt GPO nie modyfikuje managera ani jego `authd.pass`.

### Stan serwera `192.168.21.15`

Kontrola wykonana 23 lipca 2026 r. na Wazuh 4.14.6 wykazała:

* `wazuh-authd` działa i nasłuchuje na TCP/1515;
* enrollment jest włączony przez `<disabled>no</disabled>`;
* uwierzytelnienie hasłem jest włączone przez `<use_password>yes</use_password>`;
* `/var/ossec/etc/authd.pass` istnieje z właścicielem `root:wazuh` i trybem `640`.

Wazuh nie definiuje dla tego mechanizmu osobnego użytkownika. Agent przekazuje jedno wspólne
hasło enrollmentu. Przed aktywacją GPO trzeba więc skonfigurować hasło na managerze i zapisać
identyczną wartość w chronionym `enrollment-password.txt`.

### Włączenie hasła enrollmentu na managerze

Najpierw wykonaj kopię konfiguracji:

```bash
sudo cp -a /var/ossec/etc/ossec.conf "/var/ossec/etc/ossec.conf.before-enrollment-password.$(date -u +%Y%m%dT%H%M%SZ)"
```

Uruchom `sudoedit /var/ossec/etc/ossec.conf` i w istniejącej sekcji `<auth>` zmień wyłącznie:

```xml
<use_password>yes</use_password>
```

Utwórz hasło interaktywnie, aby nie trafiło do historii powłoki:

```bash
read -rsp 'Nowe hasło enrollmentu: ' WAZUH_ENROLLMENT_PASSWORD
printf '\n'
printf '%s\n' "$WAZUH_ENROLLMENT_PASSWORD" | sudo tee /var/ossec/etc/authd.pass >/dev/null
unset WAZUH_ENROLLMENT_PASSWORD
sudo chown root:wazuh /var/ossec/etc/authd.pass
sudo chmod 640 /var/ossec/etc/authd.pass
```

Użyj losowej wartości o długości co najmniej 16 znaków, najlepiej wygenerowanej przez firmowy
manager haseł. Nie używaj hasła konta domenowego, `WAZUH_API_PASSWORD`, `CLIENT_API_KEY` ani
`ADMIN_API_KEY`.

Przed restartem wykonaj test konfiguracji, następnie zrestartuj managera i sprawdź całość:

```bash
sudo /var/ossec/bin/wazuh-authd -t
sudo systemctl restart wazuh-manager
sudo ./scripts/check-wazuh-enrollment.sh
```

Skrypt kontrolny nie wyświetla hasła i nie tworzy rekordu agenta. Sprawdza konfigurację,
`root:wazuh`, tryb `640`, format jednej linii, proces, port i test `wazuh-authd -t`.
Opcjonalnie może bez ujawniania wartości porównać dwa chronione pliki:

```bash
sudo ./scripts/check-wazuh-enrollment.sh --expected-password-file /root/enrollment-password.expected
```

Porównanie jest lokalne. Plik oczekiwany usuń bezpiecznie po kontroli.

## 2. Zakres wszystkich komputerów domenowych

Docelowym zakresem jest wbudowana grupa domenowa o RID `515`, czyli `Domain Computers`.
Nie wpisuj jej nazwy tekstowo, ponieważ nazwa wyświetlana zależy od języka domeny. Poniższe
polecenia wyliczają SID bieżącej domeny, dodają RID `515` i tłumaczą wynik na lokalną nazwę
konta. Wdrożenie pilotażowe realizuj przez początkowe podłączenie GPO tylko do testowego OU,
a następnie podłączanie go do kolejnych OU. Nie łącz tego GPO z OU `Domain Controllers`.

## 3. Chroniony udział z tajemnicami

Nie zapisuj klucza API ani hasła enrollmentu w skrypcie, JSON-ie, GPP, SYSVOL lub parametrach
GPO. Rekomendowany jest ukryty udział na serwerze plików, nie dodatkowa rola na kontrolerze
domeny. Konto komputera odczytuje pliki przez Kerberos.

Przykład na serwerze `fssrv.ad.citronex.pl`:

```powershell
$SecretRoot = 'D:\WazuhDeploymentSecrets'
$DomainEntry = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry()
$DomainSid = [System.Security.Principal.SecurityIdentifier]::new([byte[]]$DomainEntry.Properties['objectSid'][0], 0)
$DeploymentGroup = ([System.Security.Principal.SecurityIdentifier]::new("$($DomainSid.Value)-515")).Translate([System.Security.Principal.NTAccount]).Value
$AdminsName = ([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate([System.Security.Principal.NTAccount]).Value
$EveryoneName = ([System.Security.Principal.SecurityIdentifier]'S-1-1-0').Translate([System.Security.Principal.NTAccount]).Value
New-Item -ItemType Directory -Path $SecretRoot -Force | Out-Null
icacls.exe $SecretRoot /inheritance:r
icacls.exe $SecretRoot /remove:g '*S-1-1-0'
icacls.exe $SecretRoot /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "$DeploymentGroup`:(OI)(CI)RX"
$ExistingShare = Get-SmbShare -Name 'WazuhDeployment$' -ErrorAction SilentlyContinue
if ($null -eq $ExistingShare) { New-SmbShare -Name 'WazuhDeployment$' -Path $SecretRoot -FullAccess $AdminsName -ReadAccess $DeploymentGroup -EncryptData $true | Out-Null } elseif (-not $ExistingShare.Path.Equals($SecretRoot, [System.StringComparison]::OrdinalIgnoreCase)) { throw "Udział WazuhDeployment$ wskazuje na $($ExistingShare.Path), oczekiwano $SecretRoot." } else { Set-SmbShare -Name 'WazuhDeployment$' -EncryptData $true -Force }
Grant-SmbShareAccess -Name 'WazuhDeployment$' -AccountName $AdminsName -AccessRight Full -Force | Out-Null
Grant-SmbShareAccess -Name 'WazuhDeployment$' -AccountName $DeploymentGroup -AccessRight Read -Force | Out-Null
Revoke-SmbShareAccess -Name 'WazuhDeployment$' -AccountName $EveryoneName -Force -ErrorAction SilentlyContinue
```

Utwórz dwa jednoliniowe pliki bez BOM:

```text
client-api-key.txt
enrollment-password.txt
```

Wpisz wartości interaktywnie albo za pomocą zatwierdzonego systemu zarządzania sekretami.
`client-api-key.txt` zawiera samą wartość `CLIENT_API_KEY`, a `enrollment-password.txt`
zawiera dokładnie tę samą pojedynczą linię co `/var/ossec/etc/authd.pass` na managerze.
Nie dodawaj nazw zmiennych, cudzysłowów ani spacji.
Zweryfikuj, że udział nie przyznaje dostępu `Everyone`, `Authenticated Users`, `Domain Users`
ani użytkownikom interaktywnym. Ponieważ `Domain Computers` obejmuje wszystkie komputery
domenowe, kompromitacja dowolnego z nich umożliwia odczyt współdzielonego hasła enrollmentu.
Ogranicz port 1515 do zarządzanych podsieci, monitoruj enrollment i rotuj hasło po wdrożeniu.

Jeśli organizacja posiada system zarządzania sekretami wydający tajemnice per urządzenie,
zastąp udział SMB takim mechanizmem. Skrypt wymaga jedynie ścieżki do jednoliniowego pliku
dostępnego dla `LocalSystem`.

## 4. Certyfikaty komputera

W GPMC utwórz albo uzupełnij GPO z zaufaniem do firmowego CA:

```text
Computer Configuration
  Policies
    Windows Settings
      Security Settings
        Public Key Policies
          Trusted Root Certification Authorities
```

Zaimportuj root CA, a pośrednie CA umieść w `Intermediate Certification Authorities`. Nie
wyłączaj kontroli certyfikatów i nie używaj `-SkipCertificateCheck`.

## 5. Publikacja skryptu i JSON w SYSVOL

W konsoli GPMC utwórz GPO `Citronex - Wazuh Agent Bootstrap`. Otwórz katalog skryptów przez
przycisk **Show Files** w ustawieniach Startup i utwórz podkatalog `WazuhAgent`. Skopiuj do niego:

```text
Install-WazuhAgent.ps1
WazuhAgentGpo.config.json
```

JSON utwórz z `deploy/gpo/WazuhAgentGpo.config.example.json`, zmieniając co najmniej nazwę
serwera plików. Nie wpisuj do niego wartości tajemnic. Pierwsze wdrożenie pozostaw z:

```json
"auditOnly": true,
"requireManifestSha256": true,
"forceRepair": false
```

`forceRepair=true` służy wyłącznie kontrolowanej akcji naprawczej, nie stałej polityce.

## 6. Podpisanie PowerShell

Wydaj administratorowi publikującemu certyfikat Code Signing z firmowego PKI. Certyfikat
wydawcy i jego łańcuch rozprowadź do magazynów `Trusted Publishers` i odpowiednich CA komputerów.
Podpisz finalną, niezmienną kopię:

```powershell
$Certificate = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.NotAfter -gt (Get-Date).AddMonths(1) } | Select-Object -First 1
Set-AuthenticodeSignature -FilePath '.\Install-WazuhAgent.ps1' -Certificate $Certificate -HashAlgorithm SHA256
```

Sprawdź `Status=Valid`. Każda zmiana skryptu unieważnia podpis i wymaga ponownego podpisania.
Włącz `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on Script Execution` jako **Allow only signed scripts** po potwierdzeniu
dystrybucji zaufania.

## 7. Konfiguracja skryptu startowego

W GPO przejdź do:

```text
Computer Configuration
  Policies
    Windows Settings
      Scripts (Startup/Shutdown)
        Startup
          PowerShell Scripts
```

Dodaj `Install-WazuhAgent.ps1` i parametr wskazujący JSON z tego samego katalogu, np.:

```text
-ConfigPath "\\ad.citronex.pl\SYSVOL\ad.citronex.pl\Policies\{GPO-GUID}\Machine\Scripts\Startup\WazuhAgent\WazuhAgentGpo.config.json"
```

Nie używaj `-ExecutionPolicy Bypass`. W ustawieniach zasad włącz również:

```text
Computer Configuration > Administrative Templates > System > Logon
  Always wait for the network at computer startup and logon = Enabled

Computer Configuration > Administrative Templates > System > Scripts
  Specify maximum wait time for Group Policy scripts = 600 seconds
```

Skrypt ma własny mutex, retry API i retry dostępu do plików, dlatego równoległe uruchomienia nie
wykonają dwóch instalacji.

## 8. Delegacja i linkowanie GPO

Połącz GPO z OU wszystkich docelowych stacji i serwerów — nigdy z OU `Domain Controllers`.
W Security Filtering dodaj przetłumaczoną przez system grupę z RID `515` (`Domain Computers`)
z prawami `Read` i `Apply group policy`. Jeżeli usuwasz `Authenticated Users` z filtrowania,
upewnij się, że `Domain Computers` zachowuje oba wymagane prawa.

Sprawdź wynik:

```powershell
gpupdate.exe /force
gpresult.exe /h C:\Windows\Temp\gpresult-wazuh.html
```

Ponieważ jest to Startup Script, test wykonaj po restarcie komputera.

## 9. Faza audit-only

Przy `auditOnly=true` skrypt:

* pobiera manifest i stan rekordu;
* ocenia lokalną wersję, usługę i klucz;
* nie pobiera MSI, nie zatrzymuje usługi i nie wykonuje enrollmentu;
* zapisuje planowaną operację do chronionego logu.

Na pilocie sprawdź:

```powershell
Get-Content 'C:\ProgramData\Citronex\WazuhBootstrap\Logs\WazuhAgentGpo-*.jsonl' | Select-Object -Last 20
Get-Service WazuhSvc -ErrorAction SilentlyContinue
```

Zweryfikuj w logach co najmniej stany `None`, `Install`, `Repair` oraz kontrolowany konflikt
braku klucza przy istniejącym rekordzie managera.

## 10. Aktywacja zmian

Po zaakceptowaniu pilota ustaw w JSON:

```json
"auditOnly": false
```

Podpis PowerShell nie zmienia się, ponieważ JSON nie jest wykonywalny i nie zawiera sekretów.
Rozszerzaj linkowanie GPO z testowego OU na kolejne OU etapami. Monitoruj lokalne logi, stan
`WazuhSvc`, ruch 1515 i nowe rekordy w managerze.

Skrypt zachowuje poprawny `client.keys` i nie wykonuje downgrade'u. Naprawa uszkodzonej
instalacji tej samej wersji może wykonać kontrolowane odinstalowanie i ponowną instalację
zweryfikowanego MSI, po czym odtwarza tożsamość i konfigurację. Wycofanie GPO zatrzymuje kolejne
działania, ale celowo nie odinstalowuje już wdrożonego Wazuh.

## 11. Diagnostyka

Najczęstsze przypadki:

* kod 20: zaufanie TLS, klucz API, DNS, proxy lub chwilowa niedostępność API;
* kod 30: rekord managera istnieje bez lokalnego klucza albo duplikat nazwy;
* brak instalacji w audycie: `auditOnly` nadal ma wartość `true`;
* kod 40 przy paczce: brak SHA-256, niedozwolony host, podpis lub CRL;
* kod 50: zabezpieczony katalog roboczy i `msiexec.log` pozostają w `%ProgramData%`;
* kod 60: usługa, lokalny klucz lub enrollment;
* enrollment timeout: port 1515, hasło authd, unikalność nazwy i log
  `C:\Program Files (x86)\ossec-agent\ossec.log`.

Przed rozszerzeniem GPO poza pilot wykonaj macierz opisaną w
[GPO-TESTING.md](GPO-TESTING.md). Nie uruchamiaj harnessu destrukcyjnego przez Startup Script
ani na komputerach użytkowników.

Wazuh opisuje błędy kluczy, nazw i hasła w
[troubleshooting enrollmentu](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/troubleshooting.html).
Nie rozwiązuj konfliktu przez kopiowanie klucza z innego komputera.
