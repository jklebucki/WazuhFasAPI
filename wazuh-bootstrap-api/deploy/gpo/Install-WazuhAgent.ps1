#Requires -Version 5.1

<#
.SYNOPSIS
Idempotent Wazuh agent installation, repair, and upgrade for an AD computer startup GPO.

.DESCRIPTION
Uses the read-only Wazuh Bootstrap API as the source of the target version and manager
configuration. It never retrieves or guesses client.keys. Enrollment is allowed when the
manager has no record for the computer or when one unambiguous record satisfies the embedded
stale-agent policy and the manager's authd force policy. A separately protected enrollment
password file is required. Secrets are never written to this script, logs, or the msiexec
command line. A local agent identity that does not match the current computer name triggers
a controlled full reinstall and re-enrollment without restoring the previous identity files.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Net.Http

# Deployment configuration. Keep secrets in the protected files referenced below.
$script:BootstrapApiUrl = 'https://wazuh.ad.citronex.pl:8443'
$script:ApiKeyFile = '\\fssrv.ad.citronex.pl\WazuhDeployment$\client-api-key.txt'
$script:EnrollmentPasswordFile = '\\fssrv.ad.citronex.pl\WazuhDeployment$\enrollment-password.txt'
$script:AllowedDownloadHosts = @('packages.wazuh.com')
$script:AuditOnly = $false
$script:ForceRepair = $false
$script:ApiRetryCount = 6
$script:ApiRetryDelaySeconds = 10
$script:EnrollmentTimeoutSeconds = 120
$script:AllowStaleAgentReenrollment = $true
$script:StaleAgentReenrollmentMinutes = 60
$script:LogDirectory = 'C:\ProgramData\Citronex\WazuhBootstrap\Logs'

$script:LogFile = $null
$script:RebootRequired = $false
$script:CurrentFailureExitCode = 70
$script:ExitCodes = @{
    Success       = 0
    Configuration = 10
    BootstrapApi  = 20
    ManualAction  = 30
    Package       = 40
    Installer     = 50
    Agent         = 60
    Unexpected    = 70
}

function Protect-LocalPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath,

        [Parameter()]
        [switch]$Directory
    )

    if ($Directory -and -not (Test-Path -LiteralPath $LiteralPath -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $LiteralPath -Force
    }
    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        return
    }

    $arguments = @('/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F',
        '*S-1-5-32-544:(OI)(CI)F')
    if (-not $Directory) {
        $arguments = @('/inheritance:r', '/grant:r', '*S-1-5-18:F', '*S-1-5-32-544:F')
    }
    & (Join-Path $env:SystemRoot 'System32\icacls.exe') $LiteralPath @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to secure local path: $LiteralPath"
    }
}

function Initialize-DeploymentLog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Directory)

    Protect-LocalPath -LiteralPath $Directory -Directory
    $script:LogFile = Join-Path $Directory ('WazuhAgentGpo-{0:yyyyMMdd}.jsonl' -f (Get-Date))
    if (-not (Test-Path -LiteralPath $script:LogFile)) {
        $null = New-Item -ItemType File -Path $script:LogFile -Force
    }
    Protect-LocalPath -LiteralPath $script:LogFile
}

function Write-DeploymentLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [hashtable]$Data = @{}
    )

    $record = [ordered]@{
        timestamp = [DateTime]::UtcNow.ToString('o')
        level = $Level
        message = $Message
        computer = $env:COMPUTERNAME
        data = $Data
    }
    $line = $record | ConvertTo-Json -Compress -Depth 6
    if ($script:LogFile) {
        Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
    }
    if ($Level -in @('WARN', 'ERROR')) {
        Write-Warning $Message
    }
    else {
        Write-Verbose $Message
    }
}

function Get-GpoConfiguration {
    [CmdletBinding()]
    param()

    return [pscustomobject]@{
        BootstrapApiUrl = $script:BootstrapApiUrl
        ApiKeyFile = $script:ApiKeyFile
        EnrollmentPasswordFile = $script:EnrollmentPasswordFile
        AllowedDownloadHosts = @($script:AllowedDownloadHosts)
        AuditOnly = $script:AuditOnly
        ForceRepair = $script:ForceRepair
        ApiRetryCount = $script:ApiRetryCount
        ApiRetryDelaySeconds = $script:ApiRetryDelaySeconds
        EnrollmentTimeoutSeconds = $script:EnrollmentTimeoutSeconds
        AllowStaleAgentReenrollment = $script:AllowStaleAgentReenrollment
        StaleAgentReenrollmentMinutes = $script:StaleAgentReenrollmentMinutes
        LogDirectory = $script:LogDirectory
    }
}

function ConvertTo-GpoConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Configuration)

    foreach ($name in @('BootstrapApiUrl', 'ApiKeyFile', 'AllowedDownloadHosts',
            'AuditOnly', 'ForceRepair', 'ApiRetryCount', 'ApiRetryDelaySeconds',
            'EnrollmentTimeoutSeconds', 'AllowStaleAgentReenrollment',
            'StaleAgentReenrollmentMinutes', 'LogDirectory')) {
        if ($null -eq $Configuration.PSObject.Properties[$name]) {
            throw "Missing required configuration property: $name"
        }
    }

    $apiUri = [Uri][string]$Configuration.BootstrapApiUrl
    if (-not $apiUri.IsAbsoluteUri -or $apiUri.Scheme -ne 'https') {
        throw 'BootstrapApiUrl must be an absolute HTTPS URL.'
    }

    if ([string]::IsNullOrWhiteSpace([string]$Configuration.ApiKeyFile)) {
        throw 'ApiKeyFile must not be empty.'
    }
    if ([string]::IsNullOrWhiteSpace([string]$Configuration.LogDirectory)) {
        throw 'LogDirectory must not be empty.'
    }
    $staleAgentReenrollmentMinutes = [int]$Configuration.StaleAgentReenrollmentMinutes
    if ($staleAgentReenrollmentMinutes -lt 1 -or
        $staleAgentReenrollmentMinutes -gt 525600) {
        throw 'StaleAgentReenrollmentMinutes must be between 1 and 525600.'
    }

    $allowedHosts = @($Configuration.AllowedDownloadHosts)
    if ($allowedHosts.Count -eq 0) {
        throw 'AllowedDownloadHosts must contain at least one DNS name.'
    }
    foreach ($hostName in $allowedHosts) {
        if ([string]$hostName -notmatch '^[A-Za-z0-9.-]+$') {
            throw "Invalid allowed download host: $hostName"
        }
    }

    return [pscustomobject]@{
        BootstrapApiUrl = $apiUri.AbsoluteUri.TrimEnd('/')
        ApiKeyFile = [string]$Configuration.ApiKeyFile
        EnrollmentPasswordFile = if ($null -eq
            $Configuration.PSObject.Properties['EnrollmentPasswordFile']) {
            ''
        }
        else {
            [string]$Configuration.EnrollmentPasswordFile
        }
        AllowedDownloadHosts = @($allowedHosts | ForEach-Object { ([string]$_).ToLowerInvariant() })
        AuditOnly = [bool]$Configuration.AuditOnly
        ForceRepair = [bool]$Configuration.ForceRepair
        ApiRetryCount = [int]$Configuration.ApiRetryCount
        ApiRetryDelaySeconds = [int]$Configuration.ApiRetryDelaySeconds
        EnrollmentTimeoutSeconds = [int]$Configuration.EnrollmentTimeoutSeconds
        AllowStaleAgentReenrollment = [bool]$Configuration.AllowStaleAgentReenrollment
        StaleAgentReenrollmentMinutes = $staleAgentReenrollmentMinutes
        LogDirectory = [string]$Configuration.LogDirectory
    }
}

function ConvertTo-UtcTimestamp {
    [CmdletBinding()]
    param([Parameter()][AllowNull()][object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }
    if ($Value -is [DateTimeOffset]) {
        return ([DateTimeOffset]$Value).ToUniversalTime()
    }
    if ($Value -is [DateTime]) {
        $dateTime = [DateTime]$Value
        if ($dateTime.Kind -eq [DateTimeKind]::Unspecified) {
            $dateTime = [DateTime]::SpecifyKind($dateTime, [DateTimeKind]::Utc)
        }
        return ([DateTimeOffset]$dateTime).ToUniversalTime()
    }

    $parsed = [DateTimeOffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor
        [Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTimeOffset]::TryParse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            $styles,
            [ref]$parsed)) {
        return $null
    }
    return $parsed.ToUniversalTime()
}

function Get-StaleAgentReenrollmentDecision {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Agent,
        [Parameter(Mandatory)][object]$DataAsOf,
        [Parameter(Mandatory)][ValidateRange(1, 525600)][int]$MinimumAgeMinutes
    )

    $status = ([string]$Agent.status).ToLowerInvariant()
    if ($status -notin @('disconnected', 'never_connected')) {
        return [pscustomobject]@{
            Eligible = $false
            Reason = 'agent_status_is_not_replaceable'
            Status = $status
            AgeMinutes = $null
            DisconnectedMinutes = $null
        }
    }

    $dataTimestamp = ConvertTo-UtcTimestamp -Value $DataAsOf
    $dateAdded = ConvertTo-UtcTimestamp -Value $Agent.dateAdded
    if ($null -eq $dataTimestamp -or $null -eq $dateAdded -or
        $dateAdded -gt $dataTimestamp) {
        return [pscustomobject]@{
            Eligible = $false
            Reason = 'registration_timestamp_is_missing_or_invalid'
            Status = $status
            AgeMinutes = $null
            DisconnectedMinutes = $null
        }
    }

    $ageMinutes = [math]::Floor(($dataTimestamp - $dateAdded).TotalMinutes)
    if ($ageMinutes -lt $MinimumAgeMinutes) {
        return [pscustomobject]@{
            Eligible = $false
            Reason = 'agent_record_is_too_recent'
            Status = $status
            AgeMinutes = $ageMinutes
            DisconnectedMinutes = $null
        }
    }

    if ($status -eq 'never_connected') {
        return [pscustomobject]@{
            Eligible = $true
            Reason = 'never_connected_record_is_stale'
            Status = $status
            AgeMinutes = $ageMinutes
            DisconnectedMinutes = $null
        }
    }

    $lastKeepAlive = ConvertTo-UtcTimestamp -Value $Agent.lastKeepAlive
    if ($null -eq $lastKeepAlive -or $lastKeepAlive -gt $dataTimestamp) {
        return [pscustomobject]@{
            Eligible = $false
            Reason = 'last_keep_alive_is_missing_or_invalid'
            Status = $status
            AgeMinutes = $ageMinutes
            DisconnectedMinutes = $null
        }
    }

    $disconnectedMinutes = [math]::Floor(
        ($dataTimestamp - $lastKeepAlive).TotalMinutes)
    if ($disconnectedMinutes -lt $MinimumAgeMinutes) {
        return [pscustomobject]@{
            Eligible = $false
            Reason = 'agent_was_disconnected_too_recently'
            Status = $status
            AgeMinutes = $ageMinutes
            DisconnectedMinutes = $disconnectedMinutes
        }
    }

    return [pscustomobject]@{
        Eligible = $true
        Reason = 'disconnected_record_is_stale'
        Status = $status
        AgeMinutes = $ageMinutes
        DisconnectedMinutes = $disconnectedMinutes
    }
}

function Read-ProtectedValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$Description,
        [Parameter()][int]$RetryCount = 6,
        [Parameter()][int]$RetryDelaySeconds = 10,
        [Parameter()][int]$MinimumLength = 1
    )

    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        try {
            $value = (Get-Content -LiteralPath $LiteralPath -Raw -Encoding UTF8).Trim()
            if ($value.Length -lt $MinimumLength -or $value.Contains("`r") -or
                $value.Contains("`n")) {
                throw "$Description has an invalid format."
            }
            return $value
        }
        catch {
            if ($attempt -eq $RetryCount) {
                throw "Unable to read $Description from its protected file."
            }
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
    throw "Unable to read $Description."
}

function New-HttpException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [Parameter()][int]$StatusCode = 0
    )

    $exception = New-Object System.Exception($Message)
    $exception.Data['StatusCode'] = $StatusCode
    return $exception
}

function Invoke-BootstrapApiGet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Uri]$Uri,
        [Parameter(Mandatory)][string]$ApiKey,
        [Parameter()][int]$RetryCount = 6,
        [Parameter()][int]$RetryDelaySeconds = 10
    )

    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(20)
        $client.DefaultRequestHeaders.Add('X-API-Key', $ApiKey)
        $response = $null
        try {
            $response = $client.GetAsync($Uri).GetAwaiter().GetResult()
            $statusCode = [int]$response.StatusCode
            $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ($statusCode -eq 200) {
                return ($content | ConvertFrom-Json)
            }
            if ($statusCode -in @(301, 302, 303, 307, 308)) {
                throw (New-HttpException -Message 'Bootstrap API redirects are not allowed.' `
                    -StatusCode $statusCode)
            }
            if ($statusCode -in @(401, 400, 409)) {
                throw (New-HttpException -Message "Bootstrap API rejected the request ($statusCode)." `
                    -StatusCode $statusCode)
            }
            if ($statusCode -notin @(429, 502, 503, 504)) {
                throw (New-HttpException -Message "Unexpected Bootstrap API status ($statusCode)." `
                    -StatusCode $statusCode)
            }
            if ($attempt -eq $RetryCount) {
                throw (New-HttpException -Message `
                    "Bootstrap API remained unavailable ($statusCode)." -StatusCode $statusCode)
            }
        }
        catch {
            $status = 0
            if ($_.Exception.Data.Contains('StatusCode')) {
                $status = [int]$_.Exception.Data['StatusCode']
            }
            if ($status -in @(400, 401, 409) -or $attempt -eq $RetryCount) {
                throw
            }
        }
        finally {
            if ($null -ne $response) { $response.Dispose() }
            $client.Dispose()
            $handler.Dispose()
        }
        Start-Sleep -Seconds $RetryDelaySeconds
    }
    throw 'Bootstrap API request failed.'
}

function ConvertTo-AgentVersion {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)

    $match = [regex]::Match($Value, '(?<!\d)(\d+\.\d+\.\d+)(?!\d)')
    if (-not $match.Success) {
        throw "Invalid agent version format: $Value"
    }
    return [version]$match.Groups[1].Value
}

function Get-InstalledAgentVersion {
    [CmdletBinding()]
    param()

    $versions = @()
    foreach ($view in @(
            [Microsoft.Win32.RegistryView]::Registry64,
            [Microsoft.Win32.RegistryView]::Registry32)) {
        $baseKey = $null
        $uninstallKey = $null
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $uninstallKey = $baseKey.OpenSubKey(
                'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($null -eq $uninstallKey) { continue }
            foreach ($subKeyName in $uninstallKey.GetSubKeyNames()) {
                $productKey = $null
                try {
                    $productKey = $uninstallKey.OpenSubKey($subKeyName)
                    if ($null -eq $productKey) { continue }
                    $displayName = [string]$productKey.GetValue('DisplayName', '')
                    $displayVersion = [string]$productKey.GetValue('DisplayVersion', '')
                    if ($displayName -match '(?i)^Wazuh Agent' -and
                        -not [string]::IsNullOrWhiteSpace($displayVersion)) {
                        try { $versions += ConvertTo-AgentVersion -Value $displayVersion }
                        catch {
                            Write-DeploymentLog -Level WARN `
                                -Message 'Ignored an invalid Wazuh registry version.'
                        }
                    }
                }
                finally {
                    if ($null -ne $productKey) { $productKey.Dispose() }
                }
            }
        }
        finally {
            if ($null -ne $uninstallKey) { $uninstallKey.Dispose() }
            if ($null -ne $baseKey) { $baseKey.Dispose() }
        }
    }
    $sortedVersions = @($versions | Sort-Object -Descending)
    if ($sortedVersions.Count -eq 0) { return $null }
    return $sortedVersions[0]
}

function Get-InstalledAgentProductCode {
    [CmdletBinding()]
    param()

    $productCodes = @()
    foreach ($view in @(
            [Microsoft.Win32.RegistryView]::Registry64,
            [Microsoft.Win32.RegistryView]::Registry32
        )) {
        $baseKey = $null
        $uninstallKey = $null
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $uninstallKey = $baseKey.OpenSubKey(
                'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($null -eq $uninstallKey) { continue }
            foreach ($subKeyName in $uninstallKey.GetSubKeyNames()) {
                $productKey = $null
                try {
                    $productKey = $uninstallKey.OpenSubKey($subKeyName)
                    if ($null -eq $productKey) { continue }
                    $displayName = [string]$productKey.GetValue('DisplayName', '')
                    if ($displayName -match '(?i)^Wazuh Agent' -and
                        $subKeyName -match '^\{[0-9A-Fa-f-]{36}\}$') {
                        $productCodes += $subKeyName.ToUpperInvariant()
                    }
                }
                finally {
                    if ($null -ne $productKey) { $productKey.Dispose() }
                }
            }
        }
        finally {
            if ($null -ne $uninstallKey) { $uninstallKey.Dispose() }
            if ($null -ne $baseKey) { $baseKey.Dispose() }
        }
    }
    $productCodes = @($productCodes | Sort-Object -Unique)
    if ($productCodes.Count -ne 1) {
        throw "Expected exactly one installed Wazuh MSI product, found $($productCodes.Count)."
    }
    return $productCodes[0]
}

function Get-AgentInstallDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Manifest)

    $allowedDirectories = @()
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
        $allowedDirectories += Join-Path $programFilesX86 'ossec-agent'
    }
    $allowedDirectories += Join-Path $env:ProgramFiles 'ossec-agent'
    $allowedDirectories = @($allowedDirectories | Select-Object -Unique)

    foreach ($directory in $allowedDirectories) {
        if (Test-Path -LiteralPath $directory -PathType Container) {
            return $directory
        }
    }
    return $allowedDirectories[0]
}

function Get-LocalClientKeyState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$ComputerName
    )

    $state = [ordered]@{
        Exists = $false
        IsValid = $false
        AgentId = $null
        AgentName = $null
        MatchesComputerName = $false
    }
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        return [pscustomobject]$state
    }
    $state.Exists = $true
    try {
        $file = Get-Item -LiteralPath $LiteralPath
        if ($file.Length -lt 20 -or $file.Length -gt 8192) {
            return [pscustomobject]$state
        }
        $lines = @((Get-Content -LiteralPath $LiteralPath -Encoding ASCII) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($lines.Count -ne 1) { return [pscustomobject]$state }
        $match = [regex]::Match($lines[0], `
            '^\s*(?<id>\d{3,8})\s+(?<name>[A-Za-z0-9_.-]{1,128})\s+\S+\s+\S{16,}\s*$')
        if (-not $match.Success -or $match.Groups['id'].Value -eq '000') {
            return [pscustomobject]$state
        }
        $state.IsValid = $true
        $state.AgentId = $match.Groups['id'].Value
        $state.AgentName = $match.Groups['name'].Value
        $state.MatchesComputerName = $state.AgentName.Equals(
            $ComputerName, [StringComparison]::OrdinalIgnoreCase)
    }
    catch { }
    return [pscustomobject]$state
}

function Test-LocalClientKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$ComputerName
    )

    return [bool](Get-LocalClientKeyState -LiteralPath $LiteralPath `
        -ComputerName $ComputerName).MatchesComputerName
}

function Get-LocalAgentConfigurationState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter()][AllowEmptyString()][string]$ComputerName = '',
        [Parameter()][AllowEmptyString()][string]$ManagerAddress = '',
        [Parameter()][int]$ManagerPort = 0,
        [Parameter()][AllowEmptyString()][string]$RegistrationAddress = '',
        [Parameter()][int]$RegistrationPort = 0
    )

    $state = [ordered]@{
        Exists = $false
        IsParseable = $false
        HasValidManager = $false
        ManagerMatchesExpected = $false
        EnrollmentMatchesExpected = $false
        AgentNameStatus = 'Absent'
        AgentName = $null
        EnrollmentCount = 0
    }
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        return [pscustomobject]$state
    }
    $state.Exists = $true
    try {
        $item = Get-Item -LiteralPath $LiteralPath
        if ($item.Length -lt 32 -or $item.Length -gt 10MB) {
            return [pscustomobject]$state
        }
        [xml]$document = Get-Content -LiteralPath $LiteralPath -Raw -Encoding UTF8
        $root = $document.SelectSingleNode('/ossec_config')
        if ($null -eq $root) { return [pscustomobject]$state }
        $client = $root.SelectSingleNode('client')
        if ($null -eq $client) { return [pscustomobject]$state }
        $state.IsParseable = $true

        $servers = @($client.SelectNodes('server'))
        $validServers = @($servers | Where-Object {
                $addressNode = $_.SelectSingleNode('address')
                $value = if ($null -eq $addressNode) { '' } else { $addressNode.InnerText.Trim() }
                $value -match '^[A-Za-z0-9.-]+$' -and
                $value -notin @('0.0.0.0', 'MANAGER_IP')
            })
        $state.HasValidManager = $validServers.Count -gt 0
        if (-not [string]::IsNullOrWhiteSpace($ManagerAddress) -and
            $ManagerPort -gt 0 -and $servers.Count -eq 1) {
            $addressNode = $servers[0].SelectSingleNode('address')
            $portNode = $servers[0].SelectSingleNode('port')
            $protocolNode = $servers[0].SelectSingleNode('protocol')
            $addressMatches = $null -ne $addressNode -and
                $addressNode.InnerText.Trim().Equals(
                    $ManagerAddress, [StringComparison]::OrdinalIgnoreCase)
            $portMatches = $null -ne $portNode -and
                $portNode.InnerText.Trim() -eq [string]$ManagerPort
            $protocolMatches = $null -ne $protocolNode -and
                $protocolNode.InnerText.Trim().Equals(
                    'tcp', [StringComparison]::OrdinalIgnoreCase)
            $state.ManagerMatchesExpected = $addressMatches -and
                $portMatches -and $protocolMatches
        }

        $enrollments = @($client.SelectNodes('enrollment'))
        $state.EnrollmentCount = $enrollments.Count
        $agentNameNodes = @($client.SelectNodes('enrollment/agent_name'))
        if ($agentNameNodes.Count -eq 1) {
            $agentName = $agentNameNodes[0].InnerText.Trim()
            $state.AgentName = $agentName
            if ($agentName -notmatch '^[A-Za-z0-9_.-]{1,128}$') {
                $state.AgentNameStatus = 'Invalid'
            }
            elseif ([string]::IsNullOrWhiteSpace($ComputerName)) {
                $state.AgentNameStatus = 'Present'
            }
            elseif ($agentName.Equals($ComputerName,
                    [StringComparison]::OrdinalIgnoreCase)) {
                $state.AgentNameStatus = 'Match'
            }
            else {
                $state.AgentNameStatus = 'Mismatch'
            }
        }
        elseif ($agentNameNodes.Count -gt 1) {
            $state.AgentNameStatus = 'Ambiguous'
            $state.AgentName = (@($agentNameNodes | ForEach-Object {
                        $_.InnerText.Trim()
                    }) -join ',')
        }

        if (-not [string]::IsNullOrWhiteSpace($RegistrationAddress) -and
            $RegistrationPort -gt 0 -and
            -not [string]::IsNullOrWhiteSpace($ComputerName) -and
            $enrollments.Count -eq 1) {
            $enrollment = $enrollments[0]
            $enabledNode = $enrollment.SelectSingleNode('enabled')
            $addressNode = $enrollment.SelectSingleNode('manager_address')
            $portNode = $enrollment.SelectSingleNode('port')
            $passwordPathNode = $enrollment.SelectSingleNode('authorization_pass_path')
            $state.EnrollmentMatchesExpected =
                $state.AgentNameStatus -eq 'Match' -and
                $null -ne $enabledNode -and
                $enabledNode.InnerText.Trim().Equals(
                    'yes', [StringComparison]::OrdinalIgnoreCase) -and
                $null -ne $addressNode -and
                $addressNode.InnerText.Trim().Equals(
                    $RegistrationAddress, [StringComparison]::OrdinalIgnoreCase) -and
                $null -ne $portNode -and
                $portNode.InnerText.Trim() -eq [string]$RegistrationPort -and
                ($null -eq $passwordPathNode -or
                    $passwordPathNode.InnerText.Trim().Equals(
                        'authd.pass', [StringComparison]::OrdinalIgnoreCase))
        }
    }
    catch { }
    return [pscustomobject]$state
}

function Test-LocalAgentConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter()][AllowEmptyString()][string]$ManagerAddress = '',
        [Parameter()][int]$ManagerPort = 0
    )

    $state = Get-LocalAgentConfigurationState -LiteralPath $LiteralPath `
        -ManagerAddress $ManagerAddress -ManagerPort $ManagerPort
    if (-not $state.IsParseable -or -not $state.HasValidManager) { return $false }
    if (-not [string]::IsNullOrWhiteSpace($ManagerAddress) -and $ManagerPort -gt 0) {
        return [bool]$state.ManagerMatchesExpected
    }
    return $true
}

function Test-InstalledAgentExecutable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$AllowedSignerSubjectRegex
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) { return $false }
    try {
        $signature = Get-AuthenticodeSignature -FilePath $LiteralPath
        return $signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid -and
            $null -ne $signature.SignerCertificate -and
            $signature.SignerCertificate.Subject -match $AllowedSignerSubjectRegex
    }
    catch { return $false }
}

function Test-AllowedHttpsUri {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Uri]$Uri,
        [Parameter(Mandatory)][string[]]$AllowedHosts
    )

    if (-not $Uri.IsAbsoluteUri -or $Uri.Scheme -ne 'https' -or
        $AllowedHosts -notcontains $Uri.DnsSafeHost.ToLowerInvariant()) {
        throw "Download URI is not an allowed HTTPS location: $($Uri.GetLeftPart('Authority'))"
    }
}

function Invoke-SecureDownload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Uri]$Uri,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string[]]$AllowedHosts
    )

    $currentUri = $Uri
    for ($redirect = 0; $redirect -le 5; $redirect++) {
        Test-AllowedHttpsUri -Uri $currentUri -AllowedHosts $AllowedHosts
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromMinutes(5)
        $response = $null
        try {
            $response = $client.GetAsync(
                $currentUri,
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
            ).GetAwaiter().GetResult()
            $statusCode = [int]$response.StatusCode
            if ($statusCode -in @(301, 302, 303, 307, 308)) {
                $location = $response.Headers.Location
                if ($null -eq $location) { throw 'MSI redirect has no Location header.' }
                $currentUri = if ($location.IsAbsoluteUri) {
                    $location
                }
                else {
                    New-Object Uri($currentUri, $location)
                }
                continue
            }
            if (-not $response.IsSuccessStatusCode) {
                throw "MSI download failed with HTTP status $statusCode."
            }
            $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            try {
                $outputStream = New-Object System.IO.FileStream(
                    $Destination,
                    [System.IO.FileMode]::CreateNew,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::None
                )
                try { $inputStream.CopyTo($outputStream) }
                finally { $outputStream.Dispose() }
            }
            finally { $inputStream.Dispose() }
            return
        }
        finally {
            if ($null -ne $response) { $response.Dispose() }
            $client.Dispose()
            $handler.Dispose()
        }
    }
    throw 'MSI download exceeded the redirect limit.'
}

function Test-AgentPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter()][AllowEmptyString()][string]$ExpectedSha256,
        [Parameter(Mandatory)][bool]$RequireSha256,
        [Parameter(Mandatory)][string]$AllowedSignerSubjectRegex
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        if ($RequireSha256) {
            throw 'Manifest has no MSI SHA-256, but production policy requires it.'
        }
        Write-DeploymentLog -Level WARN -Message 'Manifest SHA-256 is absent; relying on Authenticode.'
    }
    else {
        if ($ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$') {
            throw 'Manifest MSI SHA-256 has an invalid format.'
        }
        $actualHash = (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash
        if (-not $actualHash.Equals($ExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Downloaded MSI SHA-256 does not match the manifest.'
        }
    }

    $signature = Get-AuthenticodeSignature -FilePath $LiteralPath
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch $AllowedSignerSubjectRegex) {
        throw "MSI Authenticode validation failed with status $($signature.Status)."
    }
}

function New-SecureWorkDirectory {
    [CmdletBinding()]
    param()

    $root = Join-Path $env:ProgramData 'Citronex\WazuhBootstrap\Work'
    Protect-LocalPath -LiteralPath $root -Directory
    $directory = Join-Path $root ([Guid]::NewGuid().ToString('N'))
    Protect-LocalPath -LiteralPath $directory -Directory
    return $directory
}

function Backup-AgentIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InstallDirectory,
        [Parameter(Mandatory)][string]$WorkDirectory,
        [Parameter()][ValidateNotNullOrEmpty()][string]$ComputerName = $env:COMPUTERNAME
    )

    $files = @()
    $clientKeyPath = Join-Path $InstallDirectory 'client.keys'
    if (Test-LocalClientKey -LiteralPath $clientKeyPath -ComputerName $ComputerName) {
        $files += 'client.keys'
    }
    $configurationPath = Join-Path $InstallDirectory 'ossec.conf'
    if (Test-LocalAgentConfiguration -LiteralPath $configurationPath) {
        $files += 'ossec.conf'
    }
    $backedUp = @()
    foreach ($fileName in $files) {
        $source = Join-Path $InstallDirectory $fileName
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            Copy-Item -LiteralPath $source -Destination (Join-Path $WorkDirectory $fileName) -Force
            $backedUp += $fileName
        }
    }
    return $backedUp
}

function Restore-AgentIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InstallDirectory,
        [Parameter(Mandatory)][string]$WorkDirectory,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Files
    )

    if ($Files.Count -eq 0) { return }

    foreach ($fileName in $Files) {
        $source = Join-Path $WorkDirectory $fileName
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            Copy-Item -LiteralPath $source -Destination (Join-Path $InstallDirectory $fileName) `
                -Force
        }
    }
}

function ConvertTo-MsiProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )

    if ($Name -notmatch '^[A-Z_]+$' -or $Value -match '["\r\n]') {
        throw "Unsafe MSI property value for $Name."
    }
    return ('{0}="{1}"' -f $Name, $Value)
}

function Invoke-WazuhMsi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$MsiPath,
        [Parameter(Mandatory)][ValidateSet('Install', 'Repair')][string]$Mode,
        [Parameter()][hashtable]$Properties = @{},
        [Parameter(Mandatory)][string]$LogPath
    )

    if ($Mode -eq 'Repair') {
        # Windows Installer can return 1706 during /f when the original source list
        # no longer exists, even when a verified package is supplied. A controlled
        # uninstall/install is deterministic. The caller decides whether an existing
        # identity may be restored or must be intentionally replaced.
        $productCode = Get-InstalledAgentProductCode
        $uninstallLogPath = Join-Path (Split-Path $LogPath -Parent) 'msiexec-uninstall.log'
        $uninstallArguments = @('/x', $productCode, '/qn', '/norestart',
            '/l*v', ('"{0}"' -f $uninstallLogPath))
        $uninstallProcess = Start-Process `
            -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') `
            -ArgumentList ($uninstallArguments -join ' ') -Wait -PassThru `
            -WindowStyle Hidden
        if ($uninstallProcess.ExitCode -notin @(0, 1605, 1641, 3010)) {
            throw "Wazuh MSI uninstall failed with exit code $($uninstallProcess.ExitCode). Protected log: $uninstallLogPath"
        }
        if ($uninstallProcess.ExitCode -in @(1641, 3010)) {
            $script:RebootRequired = $true
        }
    }
    $arguments = @('/i', ('"{0}"' -f $MsiPath), '/qn', '/norestart')
    foreach ($name in ($Properties.Keys | Sort-Object)) {
        $arguments += ConvertTo-MsiProperty -Name ([string]$name) -Value ([string]$Properties[$name])
    }
    $arguments += @('/l*v', ('"{0}"' -f $LogPath))

    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') `
        -ArgumentList ($arguments -join ' ') -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -notin @(0, 1641, 3010)) {
        throw "Wazuh MSI failed with exit code $($process.ExitCode). Protected log: $LogPath"
    }
    if ($process.ExitCode -in @(1641, 3010)) {
        $script:RebootRequired = $true
    }
}

function Stop-AgentService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$ExecutablePath,
        [Parameter()][int]$TimeoutSeconds = 90,
        [Parameter()][int]$ProcessTimeoutSeconds = 30
    )

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status -ne 'Stopped') {
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        }
        catch {
            # WazuhSvc can report that it cannot be stopped while it has already entered
            # StopPending. Inspect the real state and keep waiting instead of failing early.
            $service.Refresh()
            if ($service.Status -notin @('StopPending', 'Stopped')) { throw }
            Write-DeploymentLog -Level WARN `
                -Message 'Wazuh service reported a stop error after entering StopPending; waiting for completion.'
        }
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($TimeoutSeconds))
        $service.Refresh()
        if ($service.Status -ne 'Stopped') {
            throw "Wazuh service did not stop within ${TimeoutSeconds}s."
        }
    }

    $processDeadline = [DateTime]::UtcNow.AddSeconds($ProcessTimeoutSeconds)
    do {
        $processes = @(Get-CimInstance -ClassName Win32_Process `
                -Filter "Name='wazuh-agent.exe'" -ErrorAction Stop)
        if ($processes.Count -eq 0) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $processDeadline)

    $expectedPath = [IO.Path]::GetFullPath($ExecutablePath)
    $forceDeadline = [DateTime]::UtcNow.AddSeconds(15)
    $emptyChecks = 0
    do {
        $processes = @(Get-CimInstance -ClassName Win32_Process `
                -Filter "Name='wazuh-agent.exe'" -ErrorAction Stop)
        if ($processes.Count -eq 0) {
            $emptyChecks++
            if ($emptyChecks -ge 2) { return }
        }
        else {
            $emptyChecks = 0
            foreach ($process in $processes) {
                $actualPath = [string]$process.ExecutablePath
                if ([string]::IsNullOrWhiteSpace($actualPath) -or
                    -not ([IO.Path]::GetFullPath($actualPath)).Equals(
                        $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Refused to stop a residual wazuh-agent.exe process with an unexpected path.'
                }
                Stop-Process -Id ([int]$process.ProcessId) -Force `
                    -ErrorAction SilentlyContinue
            }
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $forceDeadline)
    if ($emptyChecks -lt 2) {
        throw 'Residual wazuh-agent.exe processes kept respawning after forced termination.'
    }
}

function Repair-AgentConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$ManagerAddress,
        [Parameter(Mandatory)][int]$ManagerPort,
        [Parameter()][AllowEmptyString()][string]$RegistrationAddress = '',
        [Parameter()][int]$RegistrationPort = 0,
        [Parameter()][AllowEmptyString()][string]$AgentName = '',
        [Parameter()][switch]$ConfigureEnrollment
    )

    try { [xml]$document = Get-Content -LiteralPath $LiteralPath -Raw -Encoding UTF8 }
    catch { throw 'MSI did not provide a parseable ossec.conf for controlled repair.' }
    $root = $document.SelectSingleNode('/ossec_config')
    if ($null -eq $root) { throw 'MSI ossec.conf has no ossec_config root.' }
    $client = $root.SelectSingleNode('client')
    if ($null -eq $client) {
        $client = $document.CreateElement('client')
        $null = $root.PrependChild($client)
    }
    foreach ($existingServer in @($client.SelectNodes('server'))) {
        $null = $client.RemoveChild($existingServer)
    }
    $server = $document.CreateElement('server')
    $null = $client.PrependChild($server)
    foreach ($setting in ([ordered]@{
            address = $ManagerAddress
            port = [string]$ManagerPort
            protocol = 'tcp'
        }).GetEnumerator()) {
        $node = $server.SelectSingleNode([string]$setting.Key)
        if ($null -eq $node) {
            $node = $document.CreateElement([string]$setting.Key)
            $null = $server.AppendChild($node)
        }
        $node.InnerText = [string]$setting.Value
    }

    if ($ConfigureEnrollment) {
        if ([string]::IsNullOrWhiteSpace($RegistrationAddress) -or
            $RegistrationPort -lt 1 -or $RegistrationPort -gt 65535 -or
            $AgentName -notmatch '^[A-Za-z0-9_.-]{1,128}$') {
            throw 'Controlled enrollment configuration parameters are invalid.'
        }
        foreach ($existingEnrollment in @($client.SelectNodes('enrollment'))) {
            $null = $client.RemoveChild($existingEnrollment)
        }
        $enrollment = $document.CreateElement('enrollment')
        foreach ($setting in ([ordered]@{
                enabled = 'yes'
                manager_address = $RegistrationAddress
                port = [string]$RegistrationPort
                agent_name = $AgentName
                authorization_pass_path = 'authd.pass'
            }).GetEnumerator()) {
            $node = $document.CreateElement([string]$setting.Key)
            $node.InnerText = [string]$setting.Value
            $null = $enrollment.AppendChild($node)
        }
        $null = $client.AppendChild($enrollment)
    }
    $writerSettings = New-Object System.Xml.XmlWriterSettings
    $writerSettings.Encoding = New-Object Text.UTF8Encoding($false)
    $writerSettings.Indent = $true
    # ossec.conf is an XML-like Wazuh configuration fragment. The Wazuh parser
    # does not accept an XML declaration before ossec_config.
    $writerSettings.OmitXmlDeclaration = $true
    $writer = [Xml.XmlWriter]::Create($LiteralPath, $writerSettings)
    try { $document.Save($writer) }
    finally { $writer.Dispose() }
    $configurationState = Get-LocalAgentConfigurationState `
        -LiteralPath $LiteralPath -ComputerName $AgentName `
        -ManagerAddress $ManagerAddress -ManagerPort $ManagerPort `
        -RegistrationAddress $RegistrationAddress `
        -RegistrationPort $RegistrationPort
    if (-not $configurationState.ManagerMatchesExpected -or
        ($ConfigureEnrollment -and
            -not $configurationState.EnrollmentMatchesExpected)) {
        throw 'Controlled ossec.conf repair did not produce a valid manager configuration.'
    }
}

function Invoke-AgentExecutableCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExecutablePath,
        [Parameter(Mandatory)][string]$Arguments
    )

    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $ExecutablePath
    $startInfo.Arguments = $Arguments
    $startInfo.WorkingDirectory = Split-Path $ExecutablePath -Parent
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw 'Failed to start the Wazuh agent command.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout.GetAwaiter().GetResult() | Out-Null
        $stderr.GetAwaiter().GetResult() | Out-Null
        return $process.ExitCode
    }
    finally { $process.Dispose() }
}

function Ensure-AgentService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$ExecutablePath
    )

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        $serviceInfo = Get-CimInstance -ClassName Win32_Service `
            -Filter "Name='$ServiceName'" -ErrorAction Stop
        $actualPath = [Environment]::ExpandEnvironmentVariables(
            [string]$serviceInfo.PathName).Trim().Trim('"')
        $expectedPath = [IO.Path]::GetFullPath($ExecutablePath)
        if (-not $actualPath.Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase) -or
            $serviceInfo.StartName -ne 'LocalSystem') {
            Write-DeploymentLog -Level WARN `
                -Message 'Wazuh service registration is invalid and will be recreated.'
            Stop-AgentService -ServiceName $ServiceName -ExecutablePath $ExecutablePath
            $service.Dispose()
            $service = $null
            & (Join-Path $env:SystemRoot 'System32\sc.exe') delete $ServiceName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Failed to delete invalid Wazuh service.' }
            $deadline = [DateTime]::UtcNow.AddSeconds(60)
            do {
                if ($null -eq (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
                    break
                }
                Start-Sleep -Milliseconds 500
            } while ([DateTime]::UtcNow -lt $deadline)
            if ($null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
                throw 'Invalid Wazuh service remained marked for deletion.'
            }
        }
    }
    if ($null -eq $service) {
        if (-not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
            throw 'Wazuh executable is missing after MSI installation.'
        }
        # A service entry may have been removed while its agent process was still
        # winding down. install-service fails in that state, so finish the
        # path-validated process shutdown before creating the service again.
        Stop-AgentService -ServiceName $ServiceName -ExecutablePath $ExecutablePath
        $installExitCode = -1
        Start-Sleep -Seconds 2
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            $installExitCode = Invoke-AgentExecutableCommand `
                -ExecutablePath $ExecutablePath -Arguments 'install-service'
            if ($installExitCode -eq 0 -and
                $null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
                break
            }
            Start-Sleep -Seconds 5
        }
        if ($null -eq (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
            Write-DeploymentLog -Level WARN `
                -Message "wazuh-agent.exe install-service returned $installExitCode; using a controlled SCM fallback."
            $quotedExecutablePath = '"{0}"' -f $ExecutablePath
            & (Join-Path $env:SystemRoot 'System32\sc.exe') create $ServiceName `
                binPath= $quotedExecutablePath type= own start= auto error= normal `
                DisplayName= 'Wazuh' | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to create Wazuh service through SCM: $LASTEXITCODE."
            }
            & (Join-Path $env:SystemRoot 'System32\sc.exe') description $ServiceName `
                'Wazuh Windows Agent' | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to set Wazuh service description: $LASTEXITCODE."
            }
        }
        if ($null -eq (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
            throw "Wazuh service is still absent after registration; install-service exit code was $installExitCode."
        }
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
    }
    Set-Service -Name $ServiceName -StartupType Automatic
    if ($service.Status -ne 'Running') {
        & (Join-Path $env:SystemRoot 'System32\sc.exe') start $ServiceName | Out-Null
        if ($LASTEXITCODE -notin @(0, 1056)) {
            throw "Failed to start Wazuh service with exit code $LASTEXITCODE."
        }
    }
    (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
    Start-Sleep -Seconds 3
    if ((Get-Service -Name $ServiceName).Status -ne 'Running') {
        throw 'Wazuh service exited immediately after startup.'
    }
}

function Write-EnrollmentPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InstallDirectory,
        [Parameter(Mandatory)][string]$Password
    )

    $path = Join-Path $InstallDirectory 'authd.pass'
    try {
        [IO.File]::WriteAllText($path, $Password + [Environment]::NewLine, `
            (New-Object Text.UTF8Encoding($false)))
        Protect-LocalPath -LiteralPath $path
        return $path
    }
    catch {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Wait-ForEnrollment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClientKeyPath,
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-LocalClientKey -LiteralPath $ClientKeyPath -ComputerName $ComputerName) {
            return
        }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Enrollment did not create a valid client.keys within ${TimeoutSeconds}s."
}

function Test-DomainComputerContext {
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The script must run elevated, normally as LocalSystem from a computer GPO.'
    }
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    if (-not $computerSystem.PartOfDomain) {
        throw 'The computer is not joined to an Active Directory domain.'
    }
}

function Invoke-WazuhAgentDeployment {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Configuration)

    $script:CurrentFailureExitCode = $script:ExitCodes.Configuration
    $configuration = ConvertTo-GpoConfiguration -Configuration $Configuration
    Initialize-DeploymentLog -Directory $configuration.LogDirectory
    Write-DeploymentLog -Level INFO -Message 'Wazuh GPO deployment started.'
    Test-DomainComputerContext

    if ($configuration.ApiRetryCount -lt 1 -or $configuration.ApiRetryDelaySeconds -lt 1 -or
        $configuration.EnrollmentTimeoutSeconds -lt 10) {
        throw 'Retry and timeout configuration values are invalid.'
    }

    $apiKey = Read-ProtectedValue -LiteralPath $configuration.ApiKeyFile `
        -Description 'Bootstrap API client key' -MinimumLength 32 `
        -RetryCount $configuration.ApiRetryCount `
        -RetryDelaySeconds $configuration.ApiRetryDelaySeconds

    $script:CurrentFailureExitCode = $script:ExitCodes.BootstrapApi
    $manifestUri = [Uri]($configuration.BootstrapApiUrl + '/api/v1/manifest')
    $agentUri = [Uri]($configuration.BootstrapApiUrl + '/api/v1/agents/' +
        [Uri]::EscapeDataString($env:COMPUTERNAME))
    $manifest = Invoke-BootstrapApiGet -Uri $manifestUri -ApiKey $apiKey `
        -RetryCount $configuration.ApiRetryCount `
        -RetryDelaySeconds $configuration.ApiRetryDelaySeconds
    try {
        $agentState = Invoke-BootstrapApiGet -Uri $agentUri -ApiKey $apiKey `
            -RetryCount $configuration.ApiRetryCount `
            -RetryDelaySeconds $configuration.ApiRetryDelaySeconds
    }
    catch {
        if ($_.Exception.Data.Contains('StatusCode') -and
            [int]$_.Exception.Data['StatusCode'] -eq 409) {
            throw (New-HttpException -Message `
                'Duplicate Wazuh agent records require administrator action.' -StatusCode 409)
        }
        throw
    }
    $apiKey = $null

    if ([int]$manifest.schemaVersion -ne 1 -or -not [bool]$manifest.manager.compatible) {
        throw 'Manifest schema or manager compatibility check failed.'
    }
    if ([bool]$manifest.stale -or [bool]$agentState.stale) {
        throw 'Bootstrap API returned stale data; endpoint mutation was refused.'
    }
    if ([int]$agentState.duplicateCount -gt 1) {
        throw (New-HttpException -Message `
            'Duplicate Wazuh agent records require administrator action.' -StatusCode 409)
    }

    $managerAddress = [string]$manifest.manager.address
    $registrationAddress = [string]$manifest.manager.registrationAddress
    $communicationPort = [int]$manifest.manager.communicationPort
    $registrationPort = [int]$manifest.manager.registrationPort
    if ($managerAddress -notmatch '^[A-Za-z0-9.-]+$' -or
        $registrationAddress -notmatch '^[A-Za-z0-9.-]+$' -or
        $communicationPort -lt 1 -or $communicationPort -gt 65535 -or
        $registrationPort -lt 1 -or $registrationPort -gt 65535) {
        throw 'Manifest contains an invalid manager address or port.'
    }

    $serviceName = [string]$manifest.windows.serviceName
    $executableName = [string]$manifest.windows.executableName
    $keyFileName = [string]$manifest.windows.keyFileName
    $configFileName = [string]$manifest.windows.configFileName
    $msiFileName = [string]$manifest.targetAgent.msiFileName
    if ($serviceName -ne 'WazuhSvc' -or $executableName -ne 'wazuh-agent.exe' -or
        $keyFileName -ne 'client.keys' -or $configFileName -ne 'ossec.conf') {
        throw 'Manifest contains unsupported Windows file or service names.'
    }
    if ([IO.Path]::GetFileName($msiFileName) -ne $msiFileName -or
        $msiFileName -notmatch '^wazuh-agent-\d+\.\d+\.\d+-[A-Za-z0-9.-]+\.msi$') {
        throw 'Manifest contains an unsafe MSI file name.'
    }
    $targetVersion = ConvertTo-AgentVersion -Value ([string]$manifest.targetAgent.version)
    $installDirectory = Get-AgentInstallDirectory -Manifest $manifest
    $script:CurrentFailureExitCode = $script:ExitCodes.Agent
    $clientKeyPath = Join-Path $installDirectory $keyFileName
    $configFilePath = Join-Path $installDirectory $configFileName
    $executablePath = Join-Path $installDirectory $executableName
    $staleEnrollmentPasswordPath = Join-Path $installDirectory 'authd.pass'
    if (-not $configuration.AuditOnly -and
        (Test-Path -LiteralPath $staleEnrollmentPasswordPath -PathType Leaf)) {
        Remove-Item -LiteralPath $staleEnrollmentPasswordPath -Force
        Write-DeploymentLog -Level WARN `
            -Message 'Removed a stale enrollment password file left by an interrupted run.'
    }
    $localKeyState = Get-LocalClientKeyState -LiteralPath $clientKeyPath `
        -ComputerName $env:COMPUTERNAME
    $localConfigurationState = Get-LocalAgentConfigurationState `
        -LiteralPath $configFilePath -ComputerName $env:COMPUTERNAME `
        -ManagerAddress $managerAddress -ManagerPort $communicationPort `
        -RegistrationAddress $registrationAddress `
        -RegistrationPort $registrationPort
    $hasValidKey = [bool]$localKeyState.MatchesComputerName
    $configurationNameConflict = $localConfigurationState.AgentNameStatus `
        -in @('Mismatch', 'Ambiguous', 'Invalid')
    $keyNameConflict = $localKeyState.IsValid -and
        -not $localKeyState.MatchesComputerName
    $computerRenameDetected = $configurationNameConflict -or $keyNameConflict
    $enrollmentRequired = -not $hasValidKey -or $computerRenameDetected
    if ($computerRenameDetected) {
        Write-DeploymentLog -Level WARN `
            -Message 'A local Wazuh identity does not match the current computer name.' `
            -Data @{
                configuredAgentName = $localConfigurationState.AgentName
                configurationNameStatus = $localConfigurationState.AgentNameStatus
                keyAgentId = $localKeyState.AgentId
                keyAgentName = $localKeyState.AgentName
                currentComputerName = $env:COMPUTERNAME
            }
    }
    $managerHasAgent = [bool]$agentState.registered
    $replacementEnrollment = $false
    $reenrollmentDecision = $null

    if ($enrollmentRequired -and $managerHasAgent) {
        if (-not $configuration.AllowStaleAgentReenrollment) {
            throw (New-HttpException -Message `
                'Manager has this agent name but the endpoint requires enrollment. Stale-agent re-enrollment is disabled.' `
                -StatusCode 409)
        }
        if ($null -eq $agentState.agent) {
            throw (New-HttpException -Message `
                'Manager reported an agent record without unambiguous agent details.' `
                -StatusCode 409)
        }
        $reenrollmentDecision = Get-StaleAgentReenrollmentDecision `
            -Agent $agentState.agent `
            -DataAsOf $agentState.dataAsOf `
            -MinimumAgeMinutes $configuration.StaleAgentReenrollmentMinutes
        if (-not $reenrollmentDecision.Eligible) {
            throw (New-HttpException -Message `
                "Manager has this agent name but controlled re-enrollment is not allowed: $($reenrollmentDecision.Reason)." `
                -StatusCode 409)
        }
        $replacementEnrollment = $true
        Write-DeploymentLog -Level WARN `
            -Message 'A stale, unambiguous manager record is eligible for controlled re-enrollment.' `
            -Data @{
                agentId = [string]$agentState.agent.id
                status = [string]$reenrollmentDecision.Status
                reason = [string]$reenrollmentDecision.Reason
                ageMinutes = $reenrollmentDecision.AgeMinutes
                disconnectedMinutes = $reenrollmentDecision.DisconnectedMinutes
                minimumAgeMinutes = $configuration.StaleAgentReenrollmentMinutes
            }
    }

    $freshEnrollment = ($enrollmentRequired -and
        (-not $managerHasAgent -or $replacementEnrollment))
    $resetLocalIdentity = $freshEnrollment
    if ($hasValidKey -and -not $managerHasAgent) {
        Write-DeploymentLog -Level WARN `
            -Message 'A local client.keys exists but the manager has no matching name; identity is preserved and enrollment is not repeated.'
    }
    $installedVersion = Get-InstalledAgentVersion
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $executableHealthy = Test-InstalledAgentExecutable -LiteralPath $executablePath `
        -AllowedSignerSubjectRegex '(?i)\bWazuh\b'
    $configurationHealthy = Test-LocalAgentConfiguration `
        -LiteralPath $configFilePath -ManagerAddress $managerAddress `
        -ManagerPort $communicationPort
    $installationFilesHealthy = $executableHealthy -and $configurationHealthy
    $operation = 'None'
    if ($null -eq $installedVersion) {
        $operation = 'Install'
    }
    elseif ($resetLocalIdentity -and $installedVersion -gt $targetVersion) {
        throw (New-HttpException -Message `
            'Local identity reset requires a full reinstall, but the installed Wazuh agent is newer than the target. Automatic downgrade was refused.' `
            -StatusCode 409)
    }
    elseif ($resetLocalIdentity) {
        # Repair is implemented as a deterministic uninstall followed by install.
        $operation = 'Repair'
    }
    elseif ($installedVersion -lt $targetVersion) {
        $operation = 'Install'
    }
    elseif ($installedVersion -eq $targetVersion -and
        (-not $installationFilesHealthy -or $configuration.ForceRepair)) {
        $operation = 'Repair'
    }
    elseif ($installedVersion -gt $targetVersion) {
        Write-DeploymentLog -Level WARN `
            -Message 'Installed agent is newer than the target; downgrade was refused.' `
            -Data @{ installed = $installedVersion.ToString(); target = $targetVersion.ToString() }
    }
    if ($configuration.AuditOnly) {
        Write-DeploymentLog -Level INFO -Message 'Audit-only evaluation completed; no changes made.' `
            -Data @{
                operation = $operation
                installedVersion = if ($null -eq $installedVersion) { $null } `
                    else { $installedVersion.ToString() }
                targetVersion = $targetVersion.ToString()
                validLocalKey = $hasValidKey
                managerHasAgent = $managerHasAgent
                freshEnrollment = $freshEnrollment
                replacementEnrollment = $replacementEnrollment
                computerRenameDetected = $computerRenameDetected
                resetLocalIdentity = $resetLocalIdentity
                configuredAgentName = $localConfigurationState.AgentName
                keyAgentName = $localKeyState.AgentName
            }
        return $script:ExitCodes.Success
    }

    $enrollmentPassword = $null
    if ($freshEnrollment) {
        if ([string]::IsNullOrWhiteSpace($configuration.EnrollmentPasswordFile)) {
            throw (New-HttpException -Message `
                'Fresh enrollment requires a separately protected enrollment password file.' `
                -StatusCode 409)
        }
        $script:CurrentFailureExitCode = $script:ExitCodes.Configuration
        $enrollmentPassword = Read-ProtectedValue `
            -LiteralPath $configuration.EnrollmentPasswordFile `
            -Description 'Wazuh enrollment password' -MinimumLength 1 `
            -RetryCount $configuration.ApiRetryCount `
            -RetryDelaySeconds $configuration.ApiRetryDelaySeconds
    }

    $workDirectory = $null
    $authPasswordPath = $null
    $deploymentCompleted = $false
    try {
        if ($operation -ne 'None') {
            $script:CurrentFailureExitCode = $script:ExitCodes.Package
            $workDirectory = New-SecureWorkDirectory
            $msiPath = Join-Path $workDirectory $msiFileName
            $msiLog = Join-Path $workDirectory 'msiexec.log'
            Write-DeploymentLog -Level INFO -Message "Downloading verified Wazuh MSI for $operation."
            Invoke-SecureDownload -Uri ([Uri]$manifest.targetAgent.downloadUrl) `
                -Destination $msiPath -AllowedHosts $configuration.AllowedDownloadHosts
            Test-AgentPackage -LiteralPath $msiPath `
                -ExpectedSha256 ([string]$manifest.targetAgent.sha256) `
                -RequireSha256 $true `
                -AllowedSignerSubjectRegex '(?i)\bWazuh\b'

            $backupFiles = @()
            if (Test-Path -LiteralPath $installDirectory -PathType Container) {
                if ($resetLocalIdentity) {
                    foreach ($identityFile in @($keyFileName, $configFileName)) {
                        $identityPath = Join-Path $installDirectory $identityFile
                        if (Test-Path -LiteralPath $identityPath -PathType Leaf) {
                            Copy-Item -LiteralPath $identityPath `
                                -Destination (Join-Path $workDirectory `
                                    ('previous-' + $identityFile)) -Force
                        }
                    }
                }
                else {
                    $backupFiles = @(Backup-AgentIdentity `
                        -InstallDirectory $installDirectory `
                        -WorkDirectory $workDirectory)
                }
            }
            Stop-AgentService -ServiceName $serviceName -ExecutablePath $executablePath

            if ($resetLocalIdentity) {
                foreach ($identityPath in @(
                        $clientKeyPath,
                        $configFilePath,
                        $staleEnrollmentPasswordPath
                    )) {
                    if (Test-Path -LiteralPath $identityPath -PathType Leaf) {
                        Remove-Item -LiteralPath $identityPath -Force
                    }
                }
                Write-DeploymentLog -Level WARN `
                    -Message 'Removed the previous local Wazuh identity before full reinstall.' `
                    -Data @{
                        previousConfiguredName = $localConfigurationState.AgentName
                        previousKeyAgentId = $localKeyState.AgentId
                        previousKeyAgentName = $localKeyState.AgentName
                        currentComputerName = $env:COMPUTERNAME
                    }
            }
            elseif (-not $configurationHealthy -and
                (Test-Path -LiteralPath $configFilePath -PathType Leaf)) {
                Copy-Item -LiteralPath $configFilePath `
                    -Destination (Join-Path $workDirectory 'ossec.conf.invalid') -Force
                Remove-Item -LiteralPath $configFilePath -Force
            }

            $properties = @{}
            if ($freshEnrollment -or -not (Test-Path -LiteralPath $configFilePath)) {
                $properties['WAZUH_MANAGER'] = $managerAddress
                $properties['WAZUH_MANAGER_PORT'] = [string]$communicationPort
                $properties['WAZUH_PROTOCOL'] = 'TCP'
            }
            if ($freshEnrollment) {
                $properties['WAZUH_REGISTRATION_SERVER'] = `
                    $registrationAddress
                $properties['WAZUH_REGISTRATION_PORT'] = `
                    [string]$registrationPort
                $properties['WAZUH_AGENT_NAME'] = $env:COMPUTERNAME
            }

            try {
                $script:CurrentFailureExitCode = $script:ExitCodes.Installer
                Invoke-WazuhMsi -MsiPath $msiPath -Mode $operation `
                    -Properties $properties -LogPath $msiLog
                $installDirectory = Get-AgentInstallDirectory -Manifest $manifest
                $clientKeyPath = Join-Path $installDirectory $keyFileName
                $configFilePath = Join-Path $installDirectory $configFileName
                $executablePath = Join-Path $installDirectory $executableName
                Stop-AgentService -ServiceName $serviceName -ExecutablePath $executablePath
                if (-not $resetLocalIdentity -and $backupFiles.Count -gt 0) {
                    Restore-AgentIdentity -InstallDirectory $installDirectory `
                        -WorkDirectory $workDirectory -Files $backupFiles
                }
                if ($resetLocalIdentity) {
                    if (Test-Path -LiteralPath $clientKeyPath -PathType Leaf) {
                        Remove-Item -LiteralPath $clientKeyPath -Force
                    }
                    Repair-AgentConfiguration -LiteralPath $configFilePath `
                        -ManagerAddress $managerAddress `
                        -ManagerPort $communicationPort `
                        -RegistrationAddress $registrationAddress `
                        -RegistrationPort $registrationPort `
                        -AgentName $env:COMPUTERNAME -ConfigureEnrollment
                    Copy-Item -LiteralPath $configFilePath `
                        -Destination (Join-Path $workDirectory `
                            'ossec.conf.identity-reset') -Force
                }
                elseif (-not $configurationHealthy) {
                    Repair-AgentConfiguration `
                        -LiteralPath $configFilePath `
                        -ManagerAddress $managerAddress -ManagerPort $communicationPort
                    Copy-Item -LiteralPath $configFilePath `
                        -Destination (Join-Path $workDirectory 'ossec.conf.repaired') -Force
                }
            }
            catch {
                if (-not $resetLocalIdentity -and $backupFiles.Count -gt 0 -and
                    (Test-Path -LiteralPath $installDirectory -PathType Container)) {
                    Restore-AgentIdentity -InstallDirectory $installDirectory `
                        -WorkDirectory $workDirectory -Files $backupFiles
                }
                if ($resetLocalIdentity) {
                    Write-DeploymentLog -Level ERROR `
                        -Message 'Identity reset failed; the previous identity was not restored or restarted.'
                }
                else {
                    $existingService = Get-Service -Name $serviceName `
                        -ErrorAction SilentlyContinue
                    if ($null -ne $existingService -and
                        $existingService.Status -ne 'Running') {
                        try { Start-Service -Name $serviceName }
                        catch {
                            Write-DeploymentLog -Level ERROR `
                                -Message 'Failed to restart the previous Wazuh service after MSI failure.'
                        }
                    }
                }
                throw
            }
        }

        $installDirectory = Get-AgentInstallDirectory -Manifest $manifest
        $clientKeyPath = Join-Path $installDirectory $keyFileName
        $configFilePath = Join-Path $installDirectory $configFileName
        $executablePath = Join-Path $installDirectory $executableName
        $script:CurrentFailureExitCode = $script:ExitCodes.Agent
        if ($freshEnrollment) {
            # MSI may start WazuhSvc immediately. Stop it before creating authd.pass so the
            # intentional enrollment attempt observes the protected password file.
            Stop-AgentService -ServiceName $serviceName -ExecutablePath $executablePath
            if (Test-Path -LiteralPath $clientKeyPath -PathType Leaf) {
                Remove-Item -LiteralPath $clientKeyPath -Force
            }
            $preEnrollmentConfiguration = Get-LocalAgentConfigurationState `
                -LiteralPath $configFilePath -ComputerName $env:COMPUTERNAME `
                -ManagerAddress $managerAddress -ManagerPort $communicationPort `
                -RegistrationAddress $registrationAddress `
                -RegistrationPort $registrationPort
            if (-not $preEnrollmentConfiguration.ManagerMatchesExpected -or
                -not $preEnrollmentConfiguration.EnrollmentMatchesExpected) {
                throw 'Wazuh configuration does not contain the expected identity immediately before enrollment.'
            }
            $authPasswordPath = Write-EnrollmentPassword -InstallDirectory $installDirectory `
                -Password $enrollmentPassword
        }
        $enrollmentPassword = $null

        Ensure-AgentService -ServiceName $serviceName -ExecutablePath $executablePath
        if ($freshEnrollment) {
            Wait-ForEnrollment -ClientKeyPath $clientKeyPath -ComputerName $env:COMPUTERNAME `
                -TimeoutSeconds $configuration.EnrollmentTimeoutSeconds
            Write-DeploymentLog -Level INFO -Message 'Fresh Wazuh enrollment completed.'
        }
        elseif (-not (Test-LocalClientKey -LiteralPath $clientKeyPath `
                -ComputerName $env:COMPUTERNAME)) {
            throw 'Agent service is installed, but client.keys is missing or invalid.'
        }

        $finalConfigurationState = Get-LocalAgentConfigurationState `
            -LiteralPath $configFilePath -ComputerName $env:COMPUTERNAME `
            -ManagerAddress $managerAddress -ManagerPort $communicationPort `
            -RegistrationAddress $registrationAddress `
            -RegistrationPort $registrationPort
        if (-not $finalConfigurationState.ManagerMatchesExpected) {
            throw 'The final Wazuh manager configuration does not match the deployment manifest.'
        }
        if ($freshEnrollment -and
            -not $finalConfigurationState.EnrollmentMatchesExpected) {
            throw 'The final Wazuh enrollment identity does not match the computer name.'
        }

        $finalService = Get-Service -Name $serviceName -ErrorAction Stop
        if ($finalService.Status -ne 'Running') {
            throw 'Wazuh service is not running after deployment.'
        }
        Write-DeploymentLog -Level INFO -Message 'Wazuh GPO deployment completed.' `
            -Data @{
                operation = $operation
                targetVersion = $targetVersion.ToString()
                rebootRequired = $script:RebootRequired
                computerRenameDetected = $computerRenameDetected
                freshEnrollment = $freshEnrollment
            }
        $deploymentCompleted = $true
        return $script:ExitCodes.Success
    }
    finally {
        $enrollmentPassword = $null
        if ($authPasswordPath -and (Test-Path -LiteralPath $authPasswordPath)) {
            Remove-Item -LiteralPath $authPasswordPath -Force
        }
        if ($workDirectory -and (Test-Path -LiteralPath $workDirectory)) {
            if ($deploymentCompleted) {
                Remove-Item -LiteralPath $workDirectory -Recurse -Force
            }
            else {
                Write-DeploymentLog -Level WARN `
                    -Message 'Protected work directory retained for failure diagnostics.' `
                    -Data @{ path = $workDirectory }
            }
        }
    }
}

function Invoke-Main {
    [CmdletBinding()]
    param([Parameter()][AllowNull()][psobject]$Configuration = $null)

    $mutex = New-Object Threading.Mutex($false, 'Global\Citronex.WazuhAgent.Gpo')
    $hasMutex = $false
    try {
        $hasMutex = $mutex.WaitOne([TimeSpan]::FromSeconds(5))
        if (-not $hasMutex) {
            return $script:ExitCodes.Success
        }
        if ($null -eq $Configuration) {
            $Configuration = Get-GpoConfiguration
        }
        return Invoke-WazuhAgentDeployment -Configuration $Configuration
    }
    catch {
        $statusCode = 0
        if ($_.Exception.Data.Contains('StatusCode')) {
            $statusCode = [int]$_.Exception.Data['StatusCode']
        }
        try {
            Write-DeploymentLog -Level ERROR -Message $_.Exception.Message `
                -Data @{ statusCode = $statusCode; exceptionType = $_.Exception.GetType().FullName }
        }
        catch {
            Write-Error 'Wazuh deployment failed and its protected log could not be written.'
        }
        if ($statusCode -eq 409) { return $script:ExitCodes.ManualAction }
        if ($statusCode -ne 0) { return $script:ExitCodes.BootstrapApi }
        return $script:CurrentFailureExitCode
    }
    finally {
        if ($hasMutex) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-Main)
}
