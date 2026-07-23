#Requires -Version 5.1

<#
.SYNOPSIS
Validates the protected Wazuh GPO deployment share before rollout.

.DESCRIPTION
Run this script in an elevated Windows PowerShell session on the SMB file server. It validates
the hidden share, SMB encryption and ACLs, NTFS ACLs, secret-file encoding and length, and the
Bootstrap API client key. Secret values are held only in memory and are never printed.

.PARAMETER ShareName
Name of the local SMB share that stores the deployment secrets.

.PARAMETER BootstrapApiUrl
HTTPS base URL of the Wazuh Bootstrap API.

.PARAMETER SkipApiCheck
Skips the authenticated manifest request. Intended only for isolated ACL/format diagnostics.

.PARAMETER SkipWazuhCheck
Skips the manager-side enrollment-password proof. Intended only for isolated diagnostics.

.OUTPUTS
Human-readable PASS, WARN, and FAIL records followed by a summary.

.NOTES
Exit code 0 means ready. Exit code 1 means one or more required checks failed.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ShareName = 'WazuhDeployment$',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[^\\/:*?"<>|]+$')]
    [string]$ApiKeyFileName = 'client-api-key.txt',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[^\\/:*?"<>|]+$')]
    [string]$EnrollmentPasswordFileName = 'enrollment-password.txt',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BootstrapApiUrl = 'https://wazuh.ad.citronex.pl:8443',

    [Parameter()]
    [ValidateRange(32, 4096)]
    [int]$MinimumApiKeyLength = 32,

    [Parameter()]
    [ValidateRange(1, 4096)]
    [int]$MinimumEnrollmentPasswordLength = 16,

    [Parameter()]
    [switch]$SkipApiCheck,

    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$')]
    [string]$WazuhSshHost = '192.168.21.15',

    [Parameter()]
    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_.-]{0,63}$')]
    [string]$WazuhSshUser = 'jklebucki',

    [Parameter()]
    [ValidatePattern('^/[A-Za-z0-9._/-]+$')]
    [string]$WazuhEnrollmentCheckerPath =
        '/opt/wazuh-bootstrap-api/scripts/check-wazuh-enrollment.sh',

    [Parameter()]
    [string]$WazuhSshIdentityFile = '',

    [Parameter()]
    [switch]$SkipWazuhCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:ReadinessResults = [System.Collections.Generic.List[object]]::new()

function Add-ReadinessResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('PASS', 'WARN', 'FAIL')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Check,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $result = [pscustomobject]@{
        Status = $Status
        Check = $Check
        Message = $Message
    }
    $script:ReadinessResults.Add($result)

    $color = switch ($Status) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
    }
    Write-Host ('[{0}] {1}: {2}' -f $Status, $Check, $Message) -ForegroundColor $color
}

function ConvertTo-SidValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Identity)

    if ($Identity -is [System.Security.Principal.SecurityIdentifier]) {
        return $Identity.Value
    }
    return ([System.Security.Principal.NTAccount][string]$Identity).Translate(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
}

function Read-ValidatedSecretFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][int]$MinimumLength
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "$Description file does not exist."
    }
    $item = Get-Item -LiteralPath $LiteralPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description file must not be a reparse point."
    }

    $bytes = [IO.File]::ReadAllBytes($item.FullName)
    if ($bytes.Length -eq 0) {
        throw "$Description file is empty."
    }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and
        $bytes[2] -eq 0xBF) {
        throw "$Description file contains a UTF-8 BOM."
    }

    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    try {
        $value = $utf8.GetString($bytes)
    }
    catch {
        throw "$Description file is not valid UTF-8."
    }
    if ($value.Contains("`r") -or $value.Contains("`n") -or $value.Contains([char]0)) {
        throw "$Description must contain exactly one line without NUL characters."
    }
    if ($value.Length -lt $MinimumLength) {
        throw "$Description must contain at least $MinimumLength characters."
    }
    if ($value -ne $value.Trim()) {
        throw "$Description must not contain leading or trailing whitespace."
    }
    if ($value -eq 'CHANGE_ME') {
        throw "$Description still contains the placeholder value."
    }
    return $value
}

function Test-RequiredFileSystemRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Security.AccessControl.FileSystemSecurity]$Acl,
        [Parameter(Mandatory)][string]$Sid,
        [Parameter(Mandatory)][System.Security.AccessControl.FileSystemRights]$RequiredRights
    )

    foreach ($rule in $Acl.Access) {
        try {
            $ruleSid = ConvertTo-SidValue -Identity $rule.IdentityReference
        }
        catch {
            continue
        }
        if ($ruleSid -eq $Sid -and
            $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            ($rule.FileSystemRights -band $RequiredRights) -eq $RequiredRights) {
            return $true
        }
    }
    return $false
}

function Test-NtfsAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string[]]$AllowedSids,
        [Parameter(Mandatory)][string]$SystemSid,
        [Parameter(Mandatory)][string]$AdministratorsSid,
        [Parameter(Mandatory)][string]$DomainComputersSid,
        [Parameter()][switch]$Directory
    )

    try {
        $acl = Get-Acl -LiteralPath $LiteralPath
        $unexpected = [System.Collections.Generic.List[string]]::new()
        $denyRules = [System.Collections.Generic.List[string]]::new()
        foreach ($rule in $acl.Access) {
            try {
                $ruleSid = ConvertTo-SidValue -Identity $rule.IdentityReference
            }
            catch {
                $unexpected.Add([string]$rule.IdentityReference)
                continue
            }
            if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                $denyRules.Add(('{0} ({1})' -f $rule.IdentityReference, $ruleSid))
            }
            if ($ruleSid -notin $AllowedSids) {
                $unexpected.Add(('{0} ({1})' -f $rule.IdentityReference, $ruleSid))
            }
        }

        $failures = [System.Collections.Generic.List[string]]::new()
        if (-not (Test-RequiredFileSystemRule -Acl $acl -Sid $SystemSid `
                -RequiredRights ([System.Security.AccessControl.FileSystemRights]::FullControl))) {
            $failures.Add('SYSTEM does not have FullControl')
        }
        if (-not (Test-RequiredFileSystemRule -Acl $acl -Sid $AdministratorsSid `
                -RequiredRights ([System.Security.AccessControl.FileSystemRights]::FullControl))) {
            $failures.Add('BUILTIN\Administrators does not have FullControl')
        }
        if (-not (Test-RequiredFileSystemRule -Acl $acl -Sid $DomainComputersSid `
                -RequiredRights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute))) {
            $failures.Add('Domain Computers does not have ReadAndExecute')
        }
        if ($denyRules.Count -gt 0) {
            $failures.Add('one or more Deny rules are present')
        }
        if ($unexpected.Count -gt 0) {
            $failures.Add('unexpected principals: ' + (($unexpected | Sort-Object -Unique) -join ', '))
        }
        if ($Directory -and -not $acl.AreAccessRulesProtected) {
            $failures.Add('the root DACL still inherits from its parent')
        }
        if ((ConvertTo-SidValue -Identity $acl.Owner) -ne $AdministratorsSid) {
            $failures.Add('BUILTIN\Administrators is not the owner')
        }

        if ($failures.Count -gt 0) {
            Add-ReadinessResult -Status FAIL -Check $Label -Message ($failures -join '; ')
            return
        }
        Add-ReadinessResult -Status PASS -Check $Label `
            -Message 'NTFS owner and least-privilege ACL are correct.'
    }
    catch {
        Add-ReadinessResult -Status FAIL -Check $Label `
            -Message ('Unable to validate NTFS ACL ({0}).' -f $_.Exception.GetType().Name)
    }
}

function Test-BootstrapApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BaseUrl,
        [Parameter(Mandatory)][string]$ApiKey
    )

    try {
        $uri = [Uri]$BaseUrl
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or
            -not [string]::IsNullOrEmpty($uri.UserInfo) -or
            -not [string]::IsNullOrEmpty($uri.Query) -or
            -not [string]::IsNullOrEmpty($uri.Fragment)) {
            throw 'BootstrapApiUrl must be an absolute HTTPS base URL.'
        }
        $manifestUri = [Uri]($uri.AbsoluteUri.TrimEnd('/') + '/api/v1/manifest')
        $manifest = Invoke-RestMethod -Method Get -Uri $manifestUri `
            -Headers @{ 'X-API-Key' = $ApiKey } -TimeoutSec 30
        if ($null -eq $manifest.targetAgent -or
            [string]$manifest.targetAgent.sha256 -notmatch '^[A-Fa-f0-9]{64}$') {
            throw 'Manifest does not contain a production SHA-256 value.'
        }
        if ($null -eq $manifest.manager -or $manifest.manager.compatible -ne $true) {
            throw 'Manifest reports an incompatible or unavailable manager.'
        }
        Add-ReadinessResult -Status PASS -Check 'Bootstrap API' `
            -Message 'Client key was accepted and the production manifest is usable.'
    }
    catch {
        $statusCode = $null
        $responseProperty = $_.Exception.PSObject.Properties['Response']
        if ($null -ne $responseProperty -and $null -ne $responseProperty.Value) {
            try {
                $statusCode = [int]$responseProperty.Value.StatusCode
            }
            catch {
                $statusCode = $null
            }
        }
        $detail = if ($null -ne $statusCode) { "HTTP $statusCode" } else {
            $_.Exception.GetType().Name
        }
        Add-ReadinessResult -Status FAIL -Check 'Bootstrap API' `
            -Message "Authenticated manifest check failed ($detail)."
    }
}

function Get-HmacSha256Bytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][byte[]]$Message
    )

    $hmac = [Security.Cryptography.HMACSHA256]::new($Key)
    try {
        return $hmac.ComputeHash($Message)
    }
    finally {
        $hmac.Dispose()
    }
}

function Test-WazuhEnrollmentProof {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SshHost,
        [Parameter(Mandatory)][string]$SshUser,
        [Parameter(Mandatory)][string]$RemoteCheckerPath,
        [Parameter()][string]$SshIdentityFile = '',
        [Parameter(Mandatory)][string]$EnrollmentPassword
    )

    $ssh = Get-Command 'ssh.exe' -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $ssh) {
        Add-ReadinessResult -Status FAIL -Check 'Wazuh enrollment password' `
            -Message 'The Windows OpenSSH client (ssh.exe) is not installed.'
        return
    }

    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    $challengeBytes = [byte[]]::new(32)
    $passwordBytes = $null
    $expectedProof = $null
    try {
        $random.GetBytes($challengeBytes)
        $challenge = -join ($challengeBytes | ForEach-Object { $_.ToString('x2') })

        $passwordBytes = [Text.Encoding]::UTF8.GetBytes($EnrollmentPassword)
        [byte[]]$expectedProof = @(Get-HmacSha256Bytes -Key $passwordBytes `
            -Message $challengeBytes)

        $sshArguments = @(
            '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout=15'
        )
        if (-not [string]::IsNullOrWhiteSpace($SshIdentityFile)) {
            if (-not (Test-Path -LiteralPath $SshIdentityFile -PathType Leaf)) {
                throw 'The configured SSH identity file does not exist.'
            }
            $identityItem = Get-Item -LiteralPath $SshIdentityFile -Force
            if (($identityItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'The SSH identity file must not be a reparse point.'
            }
            $sshArguments += @('-i', $identityItem.FullName)
        }
        $target = '{0}@{1}' -f $SshUser, $SshHost
        $remoteCommand = 'sudo -n -- {0} --challenge {1}' -f $RemoteCheckerPath, $challenge
        $remoteOutput = @(& $ssh.Source @sshArguments $target $remoteCommand 2>&1)
        $sshExitCode = $LASTEXITCODE
        if ($sshExitCode -ne 0) {
            Add-ReadinessResult -Status FAIL -Check 'Wazuh enrollment password' `
                -Message "Manager verification over SSH failed (exit code $sshExitCode)."
            return
        }

        $proofMatch = [regex]::Match(
            ($remoteOutput -join "`n"),
            '(?im)^ENROLLMENT_PROOF:([a-f0-9]{64})\s*$'
        )
        if (-not $proofMatch.Success) {
            Add-ReadinessResult -Status FAIL -Check 'Wazuh enrollment password' `
                -Message 'The manager did not return a valid one-time enrollment proof.'
            return
        }
        $proofHex = $proofMatch.Groups[1].Value
        [byte[]]$actualProof = for ($offset = 0; $offset -lt $proofHex.Length; $offset += 2) {
            [Convert]::ToByte($proofHex.Substring($offset, 2), 16)
        }
        $difference = 0
        for ($index = 0; $index -lt $expectedProof.Length; $index++) {
            $difference = $difference -bor ($expectedProof[$index] -bxor $actualProof[$index])
        }
        if ($difference -ne 0) {
            Add-ReadinessResult -Status FAIL -Check 'Wazuh enrollment password' `
                -Message 'enrollment-password.txt does not match manager authd.pass.'
            return
        }
        Add-ReadinessResult -Status PASS -Check 'Wazuh enrollment password' `
            -Message 'The secret matches authd.pass and the manager enrollment checks passed.'
    }
    catch {
        Add-ReadinessResult -Status FAIL -Check 'Wazuh enrollment password' `
            -Message ('Manager verification failed ({0}).' -f $_.Exception.GetType().Name)
    }
    finally {
        $random.Dispose()
        if ($null -ne $challengeBytes) {
            [Array]::Clear($challengeBytes, 0, $challengeBytes.Length)
        }
        if ($null -ne $passwordBytes) {
            [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
        }
        if ($null -ne $expectedProof) {
            [Array]::Clear($expectedProof, 0, $expectedProof.Length)
        }
    }
}

function Invoke-WazuhGpoReadinessCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SmbShareName,
        [Parameter(Mandatory)][string]$ClientKeyFileName,
        [Parameter(Mandatory)][string]$EnrollmentFileName,
        [Parameter(Mandatory)][string]$ApiUrl,
        [Parameter(Mandatory)][int]$ClientKeyMinimumLength,
        [Parameter(Mandatory)][int]$EnrollmentMinimumLength,
        [Parameter()][switch]$DoNotCheckApi,
        [Parameter(Mandatory)][string]$ManagerSshHost,
        [Parameter(Mandatory)][string]$ManagerSshUser,
        [Parameter(Mandatory)][string]$ManagerCheckerPath,
        [Parameter()][string]$ManagerSshIdentityFile,
        [Parameter()][switch]$DoNotCheckWazuh
    )

    $script:ReadinessResults.Clear()

    if ($env:OS -ne 'Windows_NT') {
        Add-ReadinessResult -Status FAIL -Check 'Platform' `
            -Message 'This check must run on the Windows SMB file server.'
        return 1
    }

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole(
                [System.Security.Principal.WindowsBuiltInRole]::Administrator
            )) {
            Add-ReadinessResult -Status FAIL -Check 'Privileges' `
                -Message 'Run Windows PowerShell as administrator on the SMB file server.'
            return 1
        }
        Add-ReadinessResult -Status PASS -Check 'Privileges' `
            -Message 'The check is running in an elevated administrator session.'
    }
    catch {
        Add-ReadinessResult -Status FAIL -Check 'Privileges' `
            -Message 'Unable to confirm an elevated Windows identity.'
        return 1
    }

    $domainSid = $identity.User.AccountDomainSid
    if ($null -eq $domainSid) {
        Add-ReadinessResult -Status FAIL -Check 'Domain identity' `
            -Message 'Run the check as a domain account.'
        return 1
    }

    $systemSid = 'S-1-5-18'
    $administratorsSid = 'S-1-5-32-544'
    $domainComputersSid = "$($domainSid.Value)-515"
    $allowedSids = @($systemSid, $administratorsSid, $domainComputersSid)

    try {
        $share = Get-SmbShare -Name $SmbShareName -ErrorAction Stop
        if (-not $SmbShareName.EndsWith('$')) {
            Add-ReadinessResult -Status FAIL -Check 'SMB share' `
                -Message 'The deployment share is not hidden (its name must end with $).'
        }
        elseif (-not $share.EncryptData) {
            Add-ReadinessResult -Status FAIL -Check 'SMB share' `
                -Message 'SMB encryption is disabled.'
        }
        elseif (-not (Test-Path -LiteralPath $share.Path -PathType Container)) {
            Add-ReadinessResult -Status FAIL -Check 'SMB share' `
                -Message 'The local share path does not exist.'
        }
        elseif (((Get-Item -LiteralPath $share.Path -Force).Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Add-ReadinessResult -Status FAIL -Check 'SMB share' `
                -Message 'The local share path must not be a reparse point.'
        }
        else {
            Add-ReadinessResult -Status PASS -Check 'SMB share' `
                -Message 'The hidden share exists and requires SMB encryption.'
        }
    }
    catch {
        Add-ReadinessResult -Status FAIL -Check 'SMB share' `
            -Message 'The configured SMB share does not exist or cannot be queried.'
        return 1
    }

    try {
        $shareRules = @(Get-SmbShareAccess -Name $SmbShareName -ErrorAction Stop)
        $ruleFailures = [System.Collections.Generic.List[string]]::new()
        foreach ($rule in $shareRules) {
            try {
                $sid = ConvertTo-SidValue -Identity $rule.AccountName
            }
            catch {
                $ruleFailures.Add("unresolved principal $($rule.AccountName)")
                continue
            }
            if ([string]$rule.AccessControlType -ne 'Allow') {
                $ruleFailures.Add("Deny rule for $sid")
            }
            if ($sid -notin @($administratorsSid, $domainComputersSid)) {
                $ruleFailures.Add("unexpected principal $sid")
            }
        }
        $adminRule = $shareRules | Where-Object {
            (ConvertTo-SidValue -Identity $_.AccountName) -eq $administratorsSid -and
            [string]$_.AccessControlType -eq 'Allow' -and [string]$_.AccessRight -eq 'Full'
        }
        $computerRule = $shareRules | Where-Object {
            (ConvertTo-SidValue -Identity $_.AccountName) -eq $domainComputersSid -and
            [string]$_.AccessControlType -eq 'Allow' -and [string]$_.AccessRight -eq 'Read'
        }
        if ($null -eq $adminRule) {
            $ruleFailures.Add('BUILTIN\Administrators Full rule is missing')
        }
        if ($null -eq $computerRule) {
            $ruleFailures.Add('Domain Computers Read rule is missing')
        }
        if ($ruleFailures.Count -gt 0) {
            Add-ReadinessResult -Status FAIL -Check 'SMB ACL' `
                -Message (($ruleFailures | Sort-Object -Unique) -join '; ')
        }
        else {
            Add-ReadinessResult -Status PASS -Check 'SMB ACL' `
                -Message 'Only administrators and Domain Computers have share access.'
        }
    }
    catch {
        Add-ReadinessResult -Status FAIL -Check 'SMB ACL' `
            -Message 'Unable to validate SMB access rules.'
    }

    $apiKeyPath = Join-Path $share.Path $ClientKeyFileName
    $enrollmentPath = Join-Path $share.Path $EnrollmentFileName
    $apiKey = $null
    $enrollmentPassword = $null
    try {
        $apiKey = Read-ValidatedSecretFile -LiteralPath $apiKeyPath `
            -Description 'Bootstrap API client key' -MinimumLength $ClientKeyMinimumLength
        Add-ReadinessResult -Status PASS -Check 'Client API key file' `
            -Message 'The file is non-empty UTF-8 without BOM or line breaks.'
    }
    catch {
        Add-ReadinessResult -Status FAIL -Check 'Client API key file' `
            -Message $_.Exception.Message
    }
    try {
        $enrollmentPassword = Read-ValidatedSecretFile -LiteralPath $enrollmentPath `
            -Description 'Enrollment password' -MinimumLength $EnrollmentMinimumLength
        Add-ReadinessResult -Status PASS -Check 'Enrollment password file' `
            -Message 'The file is non-empty UTF-8 without BOM or line breaks.'
    }
    catch {
        Add-ReadinessResult -Status FAIL -Check 'Enrollment password file' `
            -Message $_.Exception.Message
    }
    if ($null -ne $apiKey -and $null -ne $enrollmentPassword -and
        $apiKey -ceq $enrollmentPassword) {
        Add-ReadinessResult -Status FAIL -Check 'Secret separation' `
            -Message 'The API key and enrollment password must be different.'
    }
    elseif ($null -ne $apiKey -and $null -ne $enrollmentPassword) {
        Add-ReadinessResult -Status PASS -Check 'Secret separation' `
            -Message 'The two deployment secrets are different.'
    }

    Test-NtfsAcl -LiteralPath $share.Path -Label 'Secret directory ACL' `
        -AllowedSids $allowedSids -SystemSid $systemSid `
        -AdministratorsSid $administratorsSid -DomainComputersSid $domainComputersSid -Directory
    if (Test-Path -LiteralPath $apiKeyPath -PathType Leaf) {
        Test-NtfsAcl -LiteralPath $apiKeyPath -Label 'Client API key ACL' `
            -AllowedSids $allowedSids -SystemSid $systemSid `
            -AdministratorsSid $administratorsSid -DomainComputersSid $domainComputersSid
    }
    if (Test-Path -LiteralPath $enrollmentPath -PathType Leaf) {
        Test-NtfsAcl -LiteralPath $enrollmentPath -Label 'Enrollment password ACL' `
            -AllowedSids $allowedSids -SystemSid $systemSid `
            -AdministratorsSid $administratorsSid -DomainComputersSid $domainComputersSid
    }

    if ($DoNotCheckApi) {
        Add-ReadinessResult -Status WARN -Check 'Bootstrap API' `
            -Message 'Authenticated API validation was explicitly skipped.'
    }
    elseif ($null -ne $apiKey) {
        Test-BootstrapApi -BaseUrl $ApiUrl -ApiKey $apiKey
    }
    else {
        Add-ReadinessResult -Status FAIL -Check 'Bootstrap API' `
            -Message 'API validation cannot run because the client key file is invalid.'
    }

    if ($DoNotCheckWazuh) {
        Add-ReadinessResult -Status WARN -Check 'Wazuh enrollment password' `
            -Message 'Manager-side enrollment-password validation was explicitly skipped.'
    }
    elseif ($null -ne $enrollmentPassword) {
        Test-WazuhEnrollmentProof -SshHost $ManagerSshHost -SshUser $ManagerSshUser `
            -RemoteCheckerPath $ManagerCheckerPath `
            -SshIdentityFile $ManagerSshIdentityFile `
            -EnrollmentPassword $enrollmentPassword
    }
    else {
        Add-ReadinessResult -Status FAIL -Check 'Wazuh enrollment password' `
            -Message 'Manager validation cannot run because the enrollment file is invalid.'
    }

    $apiKey = $null
    $enrollmentPassword = $null
    $failed = @($script:ReadinessResults | Where-Object Status -eq 'FAIL').Count
    $warnings = @($script:ReadinessResults | Where-Object Status -eq 'WARN').Count
    $passed = @($script:ReadinessResults | Where-Object Status -eq 'PASS').Count
    Write-Host ''
    Write-Host ('Summary: {0} passed, {1} warnings, {2} failed.' -f
        $passed, $warnings, $failed)
    if ($failed -gt 0) {
        Write-Host 'NOT READY: do not activate the production GPO.' -ForegroundColor Red
        return 1
    }
    Write-Host 'READY: protected deployment files passed all required checks.' `
        -ForegroundColor Green
    return 0
}

if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-WazuhGpoReadinessCheck -SmbShareName $ShareName `
        -ClientKeyFileName $ApiKeyFileName `
        -EnrollmentFileName $EnrollmentPasswordFileName `
        -ApiUrl $BootstrapApiUrl `
        -ClientKeyMinimumLength $MinimumApiKeyLength `
        -EnrollmentMinimumLength $MinimumEnrollmentPasswordLength `
        -DoNotCheckApi:$SkipApiCheck `
        -ManagerSshHost $WazuhSshHost `
        -ManagerSshUser $WazuhSshUser `
        -ManagerCheckerPath $WazuhEnrollmentCheckerPath `
        -ManagerSshIdentityFile $WazuhSshIdentityFile `
        -DoNotCheckWazuh:$SkipWazuhCheck)
}
