# Kontrakt przyszłego konsumenta GPO

Bootstrap API informuje wyłącznie, czy rekord o nazwie komputera istnieje w managerze oraz
jaki jest jego publiczny stan. Nie potwierdza, że lokalny `client.keys` odpowiada rekordowi,
nie zwraca klucza i nie dokonuje enrollmentu.

```powershell
$Headers = @{
    'X-API-Key' = $ApiKey
}

$Manifest = Invoke-RestMethod `
    -Uri 'https://wazuh.ad.citronex.pl:8443/api/v1/manifest' `
    -Headers $Headers

$AgentState = Invoke-RestMethod `
    -Uri ("https://wazuh.ad.citronex.pl:8443/api/v1/agents/{0}" -f $env:COMPUTERNAME) `
    -Headers $Headers
```

Klucz należy dostarczyć bezpiecznym mechanizmem domenowym; nie zapisuj go w jawnym logu.
Nie używaj `-SkipCertificateCheck`. Komputer musi ufać firmowemu CA. Obsłuż 401 jako problem
konfiguracji, 409 jako konflikt wymagający administratora, 503 jako stan przejściowy i
`stale=true` zgodnie z polityką ryzyka.

Przyszła logika naprawcza:

- prawidłowy `client.keys`: naprawa/aktualizacja bez ponownego enrollmentu;
- brak `wazuh-agent.exe` lub `WazuhSvc`, ale prawidłowy klucz: bezpieczna kopia `client.keys`
  i `ossec.conf`, MSI repair/update, przywrócenie plików, `wazuh-agent.exe install-service`
  gdy usługa nie istnieje, następnie start;
- brak `client.keys`, ale agent istnieje w managerze: nie zgaduj klucza; wymagany kontrolowany
  re-enrollment zgodnie z polityką administratora;
- brak `client.keys` i brak agenta: instalacja od zera i enrollment.

Przed MSI porównaj SHA-256 z manifestem, jeśli administrator go skonfigurował. Sam status
`active` nie świadczy o właściwej wersji. `duplicateCount > 1` nigdy nie może prowadzić do
automatycznej naprawy.
