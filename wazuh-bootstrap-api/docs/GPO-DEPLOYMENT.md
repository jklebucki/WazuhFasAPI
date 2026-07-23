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
& { Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; $ShareName = 'WazuhDeployment$'; $DefaultRoot = 'E:\WazuhDeploymentSecrets'; $ExistingShare = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue; $SecretRoot = if ($null -ne $ExistingShare) { $ExistingShare.Path } else { $DefaultRoot }; $DomainSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid; if ($null -eq $DomainSid) { throw 'Uruchom podniesiony PowerShell jako konto domenowe.' }; $DeploymentGroup = ([System.Security.Principal.SecurityIdentifier]::new("$($DomainSid.Value)-515")).Translate([System.Security.Principal.NTAccount]).Value; $DomainUsersName = ([System.Security.Principal.SecurityIdentifier]::new("$($DomainSid.Value)-513")).Translate([System.Security.Principal.NTAccount]).Value; $AdminsName = ([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate([System.Security.Principal.NTAccount]).Value; $EveryoneName = ([System.Security.Principal.SecurityIdentifier]'S-1-1-0').Translate([System.Security.Principal.NTAccount]).Value; $AuthenticatedUsersName = ([System.Security.Principal.SecurityIdentifier]'S-1-5-11').Translate([System.Security.Principal.NTAccount]).Value; New-Item -ItemType Directory -Path $SecretRoot -Force | Out-Null; icacls.exe $SecretRoot /inheritance:r | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'Nie udało się wyłączyć dziedziczenia NTFS.' }; icacls.exe $SecretRoot /remove:g '*S-1-1-0' '*S-1-5-11' "*$($DomainSid.Value)-513" | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'Nie udało się usunąć szerokich uprawnień NTFS.' }; icacls.exe $SecretRoot /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$($DomainSid.Value)-515:(OI)(CI)RX" | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'Nie udało się ustawić docelowych uprawnień NTFS.' }; if ($null -eq $ExistingShare) { New-SmbShare -Name $ShareName -Path $SecretRoot -FullAccess $AdminsName -ReadAccess $DeploymentGroup -EncryptData $true | Out-Null } else { Set-SmbShare -Name $ShareName -EncryptData $true -Force | Out-Null }; @($EveryoneName, $AuthenticatedUsersName, $DomainUsersName) | ForEach-Object { Unblock-SmbShareAccess -Name $ShareName -AccountName $_ -Force -ErrorAction SilentlyContinue | Out-Null; Revoke-SmbShareAccess -Name $ShareName -AccountName $_ -Force -ErrorAction SilentlyContinue | Out-Null }; @($DeploymentGroup, $AdminsName) | ForEach-Object { Unblock-SmbShareAccess -Name $ShareName -AccountName $_ -Force -ErrorAction SilentlyContinue | Out-Null; Revoke-SmbShareAccess -Name $ShareName -AccountName $_ -Force -ErrorAction SilentlyContinue | Out-Null }; Grant-SmbShareAccess -Name $ShareName -AccountName $AdminsName -AccessRight Full -Force | Out-Null; Grant-SmbShareAccess -Name $ShareName -AccountName $DeploymentGroup -AccessRight Read -Force | Out-Null; [pscustomobject]@{ Share = $ShareName; Path = $SecretRoot; DeploymentGroup = $DeploymentGroup; Encryption = (Get-SmbShare -Name $ShareName).EncryptData } }
```

Ustaw dokładny ACL NTFS, usuwając również wcześniejsze indywidualne wpisy administratorów:

```powershell
& { $Path = (Get-SmbShare -Name 'WazuhDeployment$').Path; $DomainSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid; if ($null -eq $DomainSid) { throw 'Uruchom podniesiony PowerShell jako konto domenowe.' }; $SystemSid = [System.Security.Principal.SecurityIdentifier]'S-1-5-18'; $AdminsSid = [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544'; $ComputersSid = [System.Security.Principal.SecurityIdentifier]::new("$($DomainSid.Value)-515"); $Inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit; $Propagation = [System.Security.AccessControl.PropagationFlags]::None; $Allow = [System.Security.AccessControl.AccessControlType]::Allow; $Acl = Get-Acl -LiteralPath $Path; $Acl.SetAccessRuleProtection($true, $false); foreach ($Rule in @($Acl.Access)) { $null = $Acl.RemoveAccessRuleSpecific($Rule) }; $Acl.SetOwner($AdminsSid); $Acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($SystemSid, [System.Security.AccessControl.FileSystemRights]::FullControl, $Inheritance, $Propagation, $Allow)); $Acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($AdminsSid, [System.Security.AccessControl.FileSystemRights]::FullControl, $Inheritance, $Propagation, $Allow)); $Acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($ComputersSid, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $Inheritance, $Propagation, $Allow)); Set-Acl -LiteralPath $Path -AclObject $Acl }
```

Zweryfikuj wynik drugim, niezależnym poleceniem:

```powershell
Write-Host "`n=== UDZIAŁ ==="; Get-SmbShare -Name 'WazuhDeployment$' | Select-Object Name, Path, EncryptData | Format-Table -AutoSize | Out-Host; Write-Host "`n=== UPRAWNIENIA SMB ==="; Get-SmbShareAccess -Name 'WazuhDeployment$' | Select-Object AccountName, AccessControlType, AccessRight | Format-Table -AutoSize | Out-Host; Write-Host "`n=== UPRAWNIENIA NTFS ==="; Get-Acl (Get-SmbShare -Name 'WazuhDeployment$').Path | Select-Object Owner, AccessToString | Format-List | Out-Host
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

### Kontrola gotowości przed wdrożeniem

Na serwerze plików skopiuj lub uruchom bezpośrednio z checkoutu
`deploy/gpo/Test-WazuhGpoReadiness.ps1`. Otwórz Windows PowerShell 5.1 jako administrator
domenowy. Po przygotowaniu opisanego poniżej dostępu SSH wykonaj:

```powershell
.\deploy\gpo\Test-WazuhGpoReadiness.ps1 -WazuhSshIdentityFile "$env:USERPROFILE\.ssh\wazuh-readiness-ed25519"
```

Skrypt nie wyświetla sekretów. Sprawdza:

* istnienie ukrytego udziału i włączone szyfrowanie SMB;
* dokładne uprawnienia udziału dla `BUILTIN\Administrators` oraz grupy domenowej o RID `515`;
* właściciela i zasadę najmniejszych uprawnień w ACL NTFS katalogu oraz obu plików;
* brak dodatkowych użytkowników, reguł `Deny`, reparse pointów i dziedziczenia katalogu
  nadrzędnego;
* niepuste UTF-8 bez BOM, końca linii, NUL, białych znaków na brzegach i wartości
  `CHANGE_ME`;
* minimum 32 znaki dla `CLIENT_API_KEY` i minimum 16 znaków dla hasła enrollmentu;
* rozdzielenie obu sekretów;
* przyjęcie klucza klienta przez `GET /api/v1/manifest`, połączenie FastAPI z Wazuh API,
  zgodność managera oraz obecność produkcyjnego SHA-256 paczki MSI;
* zgodność `enrollment-password.txt` z `/var/ossec/etc/authd.pass` przez jednorazowy HMAC,
  a także proces `wazuh-authd`, port enrollmentu i test konfiguracji managera.

Sprawdzenie Wazuh nie wykonuje próbnego enrollmentu i nie tworzy agenta. Windows generuje
losowy challenge, a uruchomiony jako `root` checker managera odpowiada HMAC-em. Hasło nie jest
przesyłane przez SSH, zapisywane w argumentach ani wyświetlane. Zwykły `agent-auth` nie nadaje
się do tej kontroli, ponieważ poprawna próba rejestruje agenta.

Najpierw zaktualizuj aplikację na managerze, aby
`/opt/wazuh-bootstrap-api/scripts/check-wazuh-enrollment.sh` obsługiwał `--challenge`.
Checker Windows używa wyłącznie uwierzytelnienia kluczem SSH i nie prosi o hasło:

```powershell
ssh-keygen.exe -t ed25519 -a 100 -f "$env:USERPROFILE\.ssh\wazuh-readiness-ed25519" -C 'wazuh-gpo-readiness'
```

Ustaw silne hasło klucza. Przed kontrolą załaduj go do Windows OpenSSH Agent:

```powershell
Get-Service ssh-agent | Set-Service -StartupType Manual; Start-Service ssh-agent; ssh-add.exe "$env:USERPROFILE\.ssh\wazuh-readiness-ed25519"
```

```powershell
Get-Content -LiteralPath "$env:USERPROFILE\.ssh\wazuh-readiness-ed25519.pub" | ssh.exe jklebucki@192.168.21.15 "umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys"
```

Na managerze utwórz przez `sudo visudo -f /etc/sudoers.d/wazuh-enrollment-proof` regułę:

```text
Cmnd_Alias WAZUH_ENROLLMENT_PROOF = /opt/wazuh-bootstrap-api/scripts/check-wazuh-enrollment.sh --challenge [A-Fa-f0-9]*
jklebucki ALL=(root) NOPASSWD: WAZUH_ENROLLMENT_PROOF
```

Tryb `--challenge` akceptuje wyłącznie 64 znaki szesnastkowe i odrzuca wszystkie opcje
zmieniające ścieżki. Plik checkera i cały katalog `/opt/wazuh-bootstrap-api` muszą pozostać
własnością `root` i nie mogą być zapisywalne przez `jklebucki`.

Wynik końcowy `READY` i kod procesu `0` są wymagane przed przełączeniem `auditOnly` na
`false`. `NOT READY` zwraca kod `1`. Do samej diagnostyki plików i ACL podczas awarii API
można świadomie pominąć kontrolę sieciową:

```powershell
.\deploy\gpo\Test-WazuhGpoReadiness.ps1 -SkipApiCheck -SkipWazuhCheck
```

Do izolowanej diagnostyki można użyć `-SkipApiCheck` lub `-SkipWazuhCheck`. Każdy z tych
przełączników zwraca ostrzeżenie i nie stanowi pełnego dopuszczenia produkcyjnego. Po zmianie
dowolnego sekretu albo ACL ponownie wykonaj pełną kontrolę bez przełączników pomijających.

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

Poniższą procedurę wykonuj na kontrolerze domeny z podniesionego Windows PowerShell, używając
konta uprawnionego do ręcznego enrollmentu z szablonu `CodeSigning`. Przyjęty katalog roboczy:

```text
C:\Temp\GPO_Script
```

Nie kopiuj klucza prywatnego do SYSVOL ani na stacje robocze. Do komputerów domenowych trafia
wyłącznie publiczny certyfikat wydawcy `WazuhScriptSigner.cer`.

### 6.1. Uruchomienie firmowego urzędu certyfikacji

Serwer `CERTSRV.ad.citronex.pl` jest normalnie wyłączony. Przed enrollmentem włącz maszynę
fizyczną lub wirtualną z konsoli platformy, na której jest utrzymywana. Samo uruchomienie usługi
nie włączy wyłączonego systemu. Po uruchomieniu serwera sprawdź DNS i port RPC:

```powershell
Resolve-DnsName 'CERTSRV.ad.citronex.pl' | Select-Object Name, IPAddress | Format-Table -AutoSize; Test-NetConnection 'CERTSRV.ad.citronex.pl' -Port 135
```

Jeżeli system działa, ale usługa CA jest zatrzymana, uruchom ją na serwerze certyfikatów:

```powershell
Start-Service -Name 'CertSvc'; Get-Service -Name 'CertSvc' | Select-Object Name, Status, StartType | Format-Table -AutoSize
```

Prawidłowym CA dla tej procedury jest:

```text
CERTSRV.ad.citronex.pl\ad-CERTSRV-CA
```

Pozostałe zarejestrowane w AD urzędy mogą mieć wygasłe certyfikaty. Przed użyciem CA potwierdź,
że jego certyfikat jest aktualny:

```powershell
& { $RootDse = [ADSI]'LDAP://RootDSE'; $Base = [ADSI]("LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services," + [string]$RootDse.configurationNamingContext); $Searcher = [System.DirectoryServices.DirectorySearcher]::new($Base); $Searcher.Filter = '(&(objectClass=pKIEnrollmentService)(dNSHostName=CERTSRV.ad.citronex.pl))'; $Searcher.PropertiesToLoad.Add('cACertificate') | Out-Null; $Result = $Searcher.FindOne(); if ($null -eq $Result) { throw 'Nie znaleziono CA CERTSRV.ad.citronex.pl w AD.' }; $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$Result.Properties['cacertificate'][0]); [pscustomobject]@{ Subject = $Certificate.Subject; Issuer = $Certificate.Issuer; NotAfter = $Certificate.NotAfter; Thumbprint = $Certificate.Thumbprint; IsCurrentlyValid = ($Certificate.NotBefore -le (Get-Date) -and $Certificate.NotAfter -gt (Get-Date)) } | Format-List }
```

### 6.2. Publikacja szablonu i enrollment

Opublikuj szablon po osiągnięciu dostępności RPC:

```powershell
certutil.exe -config 'CERTSRV.ad.citronex.pl\ad-CERTSRV-CA' -SetCATemplates +CodeSigning
```

Komunikat `Already present` oznacza, że szablon jest już opublikowany. Komunikat
`Auto-Enroll: Access is denied` nie blokuje ręcznego enrollmentu. Wystaw certyfikat do osobistego
magazynu bieżącego administratora i od razu zweryfikuj rezultat:

```powershell
& { Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; $Enrollment = Get-Certificate -Template 'CodeSigning' -CertStoreLocation 'Cert:\CurrentUser\My'; $Certificate = $Enrollment.Certificate; if ($Enrollment.Status -ne 'Issued' -or $null -eq $Certificate) { throw "Nie wystawiono certyfikatu Code Signing. Status=$($Enrollment.Status); Message=$($Enrollment.StatusMessage)" }; if (-not $Certificate.HasPrivateKey) { throw 'Wystawiony certyfikat nie ma dostępnego klucza prywatnego.' }; [pscustomobject]@{ Status = $Enrollment.Status; Subject = $Certificate.Subject; Thumbprint = $Certificate.Thumbprint; NotBefore = $Certificate.NotBefore; NotAfter = $Certificate.NotAfter; HasPrivateKey = $Certificate.HasPrivateKey; PresentInStore = (Test-Path -LiteralPath "Cert:\CurrentUser\My\$($Certificate.Thumbprint)") } | Format-List }
```

Klucz prywatny może i powinien być nieeksportowalny. Wbudowany, niezależny od języka systemu
filtr pokaże wszystkie dostępne certyfikaty Code Signing:

```powershell
Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert | Select-Object Subject, Thumbprint, NotBefore, NotAfter, HasPrivateKey | Sort-Object NotBefore -Descending | Format-Table -AutoSize
```

### 6.3. Podpisanie i eksport publicznego certyfikatu

Najpierw umieść finalny skrypt w `C:\Temp\GPO_Script\Install-WazuhAgent.ps1`. Polecenie wybiera
najnowszy ważny certyfikat Code Signing, podpisuje skrypt algorytmem SHA-256 i eksportuje
wyłącznie jego część publiczną:

```powershell
& { Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; $ScriptPath = 'C:\Temp\GPO_Script\Install-WazuhAgent.ps1'; $PublicCertificatePath = 'C:\Temp\GPO_Script\WazuhScriptSigner.cer'; $Signer = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.HasPrivateKey -and $_.NotBefore -le (Get-Date) -and $_.NotAfter -gt (Get-Date).AddMonths(1) } | Sort-Object NotBefore -Descending | Select-Object -First 1; if ($null -eq $Signer) { throw 'Brak ważnego przez co najmniej miesiąc certyfikatu Code Signing z kluczem prywatnym.' }; $Signature = Set-AuthenticodeSignature -LiteralPath $ScriptPath -Certificate $Signer -HashAlgorithm SHA256; Export-Certificate -Cert $Signer -FilePath $PublicCertificatePath -Type CERT -Force | Out-Null; [pscustomobject]@{ Status = $Signature.Status; StatusMessage = $Signature.StatusMessage; Script = $ScriptPath; Subject = $Signer.Subject; Thumbprint = $Signer.Thumbprint; CertificateNotAfter = $Signer.NotAfter; PublicCertificate = $PublicCertificatePath } | Format-List; if ($Signature.Status -ne 'Valid') { throw "Podpis nie jest prawidłowy: $($Signature.StatusMessage)" } }
```

Zweryfikuj podpis bez używania `$args[0]` w wyrażeniu formatującym, ponieważ nie wskazuje ono
obiektu potoku i może błędnie wyświetlić puste `Subject` oraz `Thumbprint` mimo ważnego podpisu:

```powershell
& { $Signature = Get-AuthenticodeSignature -LiteralPath 'C:\Temp\GPO_Script\Install-WazuhAgent.ps1'; [pscustomobject]@{ Status = $Signature.Status; StatusMessage = $Signature.StatusMessage; Path = $Signature.Path; Subject = $Signature.SignerCertificate.Subject; Thumbprint = $Signature.SignerCertificate.Thumbprint; NotAfter = $Signature.SignerCertificate.NotAfter } | Format-List; if ($Signature.Status -ne 'Valid') { throw "Podpis nie jest prawidłowy: $($Signature.StatusMessage)" } }
```

Oczekiwanym wynikiem jest `Status: Valid`. Każda zmiana zawartości skryptu, w tym zmiana
zakończeń linii po podpisaniu, unieważnia podpis i wymaga ponownego wykonania tej sekcji.

### 6.4. Zaufanie do wydawcy i publikacja w GPO

Zaimportuj `C:\Temp\GPO_Script\WazuhScriptSigner.cer` do GPO obejmującego komputery docelowe:

```text
Computer Configuration
  Policies
    Windows Settings
      Security Settings
        Public Key Policies
          Trusted Publishers
```

Certyfikat `ad-CERTSRV-CA` umieść w `Trusted Root Certification Authorities`, jeżeli nie jest już
dystrybuowany przez domenę. Do SYSVOL skopiuj podpisany `Install-WazuhAgent.ps1`, a nie jego
wcześniejszą kopię. Na komputerze pilotażowym po `gpupdate.exe /force` sprawdź obecność wydawcy:

```powershell
Get-ChildItem -Path Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Thumbprint -eq '7578F8573173AD9D97AB4AEE4EA683B71405FB84' } | Select-Object Subject, Thumbprint, NotAfter | Format-List
```

Thumbprint w poleceniu pilotażowym jest wartością bieżącego certyfikatu wydanego 23 lipca 2026 r.
Przy odnowieniu zastąp go thumbprintem pokazanym przez procedurę podpisywania.

Włącz `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on Script Execution` jako **Allow only signed scripts** dopiero po potwierdzeniu
dystrybucji zaufania na komputerze pilotażowym. Nie używaj `-ExecutionPolicy Bypass`.

### 6.5. Zakończenie pracy CA i odnowienie

Po wystawieniu certyfikatu można usunąć tymczasową publikację szablonu, jeżeli taki jest przyjęty
model bezpieczeństwa PKI:

```powershell
certutil.exe -config 'CERTSRV.ad.citronex.pl\ad-CERTSRV-CA' -SetCATemplates -CodeSigning
```

Usunięcie szablonu z CA nie unieważnia już wystawionego certyfikatu. Nie wyłączaj serwera, dopóki
nie zakończą się operacje CA i nie zostanie wykonana wymagana w organizacji kopia zapasowa.
Następnie zatrzymaj usługę `CertSvc` i wyłącz system zgodnie z procedurą utrzymania serwera.

Bieżący certyfikat podpisujący wygasa 23 lipca 2027 r. Zaplanuj odnowienie co najmniej 30 dni
wcześniej. Bez zaufanej usługi znakowania czasem podpis nie powinien być uznawany za trwały po
wygaśnięciu certyfikatu. Procedura odnowienia obejmuje uruchomienie CA, ponowne opublikowanie
szablonu, enrollment, podpisanie aktualnej kopii skryptu i wdrożenie nowego publicznego
certyfikatu do `Trusted Publishers` przed zastąpieniem skryptu w SYSVOL.

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
