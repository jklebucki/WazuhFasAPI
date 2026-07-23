#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Runs controlled destructive end-to-end tests of the Wazuh GPO deployment script.

.DESCRIPTION
This test is intentionally invasive. It backs up the complete Wazuh agent directory,
uninstall registry key, service metadata, and a verified MSI before changing anything.
Every scenario starts and ends with a baseline restore. The final restore also runs from
the outer finally block.

Never deploy this file through GPO. Run it interactively on one designated pilot endpoint.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$DeploymentScript,

    [Parameter(Mandatory)]
    [string]$ApiEnvironmentFile,

    [Parameter(Mandatory)]
    [switch]$IUnderstandThisWillModifyWazuh,

    [Parameter()]
    [string]$ReportDirectory = '',

    [Parameter()]
    [string[]]$Scenario = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ServiceName = 'WazuhSvc'
$ExpectedExecutableName = 'wazuh-agent.exe'
$ExpectedKeyName = 'client.keys'
$ExpectedConfigName = 'ossec.conf'
$TestRoot = Join-Path $env:ProgramData 'Citronex\WazuhBootstrap\DestructiveTests'
$RunId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$RunRoot = Join-Path $TestRoot $RunId
$BackupRoot = Join-Path $RunRoot 'baseline'
$ResultFile = Join-Path $RunRoot 'results.jsonl'
$SummaryFile = Join-Path $RunRoot 'summary.json'
$script:Baseline = $null
$script:Results = New-Object System.Collections.Generic.List[object]

function Assert-SafeTestPath {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $full = [IO.Path]::GetFullPath($LiteralPath).TrimEnd('\')
    $allowed = [IO.Path]::GetFullPath($TestRoot).TrimEnd('\')
    if (-not $full.StartsWith($allowed + '\', [StringComparison]::OrdinalIgnoreCase) -and
        -not $full.Equals($allowed, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe test path refused: $full"
    }
}

function Protect-TestPath {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [switch]$Directory
    )

    Assert-SafeTestPath -LiteralPath $LiteralPath
    if ($Directory -and -not (Test-Path -LiteralPath $LiteralPath -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $LiteralPath -Force
    }
    $arguments = if ($Directory) {
        @('/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F',
            '*S-1-5-32-544:(OI)(CI)F')
    }
    else {
        @('/inheritance:r', '/grant:r', '*S-1-5-18:F', '*S-1-5-32-544:F')
    }
    & (Join-Path $env:SystemRoot 'System32\icacls.exe') $LiteralPath @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to protect test path: $LiteralPath" }
}

function Write-TestEvent {
    param(
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string]$Message,
        [hashtable]$Data = @{}
    )

    $record = [ordered]@{
        timestamp = [DateTime]::UtcNow.ToString('o')
        level = $Level
        message = $Message
        data = $Data
    }
    $line = $record | ConvertTo-Json -Compress -Depth 6
    Add-Content -LiteralPath $ResultFile -Value $line -Encoding UTF8
    Write-Host "[$Level] $Message"
}

function Read-DotEnv {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $values = @{}
    foreach ($line in Get-Content -LiteralPath $LiteralPath -Encoding UTF8) {
        if ($line -notmatch '^(?<name>[A-Z][A-Z0-9_]*)=(?<value>.*)$') { continue }
        $value = $Matches.value.Trim()
        if ($value.Length -ge 2 -and
            (($value[0] -eq '"' -and $value[$value.Length - 1] -eq '"') -or
                ($value[0] -eq "'" -and $value[$value.Length - 1] -eq "'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $values[$Matches.name] = $value
    }
    return $values
}

function Get-TestAgentInstallDirectory {
    $directories = @()
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if ($programFilesX86) { $directories += Join-Path $programFilesX86 'ossec-agent' }
    $directories += Join-Path $env:ProgramFiles 'ossec-agent'
    $existing = @($directories | Select-Object -Unique | Where-Object {
            Test-Path -LiteralPath $_ -PathType Container
        })
    if ($existing.Count -ne 1) {
        throw "Expected exactly one Wazuh installation directory; found $($existing.Count)."
    }
    return [IO.Path]::GetFullPath($existing[0]).TrimEnd('\')
}

function Get-WazuhProduct {
    param([switch]$AllowMissing)

    $products = @()
    foreach ($view in @(
            [Microsoft.Win32.RegistryView]::Registry64,
            [Microsoft.Win32.RegistryView]::Registry32)) {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try {
            $uninstall = $baseKey.OpenSubKey(
                'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($null -eq $uninstall) { continue }
            try {
                foreach ($subKeyName in $uninstall.GetSubKeyNames()) {
                    $productKey = $uninstall.OpenSubKey($subKeyName, $true)
                    if ($null -eq $productKey) { continue }
                    try {
                        if ([string]$productKey.GetValue('DisplayName', '') -match '^Wazuh Agent') {
                            $products += [pscustomobject]@{
                                View = $view.ToString()
                                ProductCode = $subKeyName
                                Version = [string]$productKey.GetValue('DisplayVersion', '')
                                RegistryPath = if ($view -eq
                                    [Microsoft.Win32.RegistryView]::Registry32) {
                                    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$subKeyName"
                                }
                                else {
                                    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$subKeyName"
                                }
                            }
                        }
                    }
                    finally { $productKey.Dispose() }
                }
            }
            finally { $uninstall.Dispose() }
        }
        finally { $baseKey.Dispose() }
    }
    if ($products.Count -eq 0 -and $AllowMissing) { return $null }
    if ($products.Count -ne 1) {
        throw "Expected exactly one Wazuh MSI registration; found $($products.Count)."
    }
    return $products[0]
}

function Set-WazuhDisplayVersion {
    param([Parameter(Mandatory)][string]$Value)

    $product = Get-WazuhProduct
    $view = if ($product.View -eq 'Registry32') {
        [Microsoft.Win32.RegistryView]::Registry32
    }
    else {
        [Microsoft.Win32.RegistryView]::Registry64
    }
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, $view)
    try {
        $relative = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' +
            $product.ProductCode
        $key = $baseKey.OpenSubKey($relative, $true)
        if ($null -eq $key) { throw 'Wazuh uninstall registry key disappeared.' }
        try { $key.SetValue('DisplayVersion', $Value, [Microsoft.Win32.RegistryValueKind]::String) }
        finally { $key.Dispose() }
    }
    finally { $baseKey.Dispose() }
}

function Invoke-RobocopyChecked {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [switch]$Mirror
    )

    $arguments = @($Source, $Destination)
    $arguments += if ($Mirror) { '/MIR' } else { '/E' }
    $arguments += @('/COPYALL', '/DCOPY:DAT', '/XJ', '/R:2', '/W:1',
        '/NFL', '/NDL', '/NJH', '/NJS', '/NP')
    & (Join-Path $env:SystemRoot 'System32\robocopy.exe') @arguments | Out-Null
    $code = $LASTEXITCODE
    if ($code -gt 7) { throw "Robocopy failed with exit code $code." }
}

function Get-CriticalHashes {
    param([Parameter(Mandatory)][string]$Directory)

    $hashes = [ordered]@{}
    foreach ($name in @($ExpectedKeyName, $ExpectedConfigName, $ExpectedExecutableName)) {
        $path = Join-Path $Directory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Critical baseline file is missing: $name"
        }
        $hashes[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
    return $hashes
}

function Wait-ServiceAbsent {
    param([int]$TimeoutSeconds = 30)

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($null -eq (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "$ServiceName was not deleted within ${TimeoutSeconds}s."
}

function Stop-AgentIfPresent {
    $installDirectory = if ($null -ne $script:Baseline) {
        [string]$script:Baseline.installDirectory
    }
    else { Get-TestAgentInstallDirectory }
    Stop-AgentService -ServiceName $ServiceName `
        -ExecutablePath (Join-Path $installDirectory $ExpectedExecutableName) `
        -ProcessTimeoutSeconds 30
}

function Ensure-BaselineService {
    param([Parameter(Mandatory)][string]$InstallDirectory)

    $expectedExecutable = Join-Path $InstallDirectory $ExpectedExecutableName
    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    $pathIsCorrect = $null -ne $service -and
        ([string]$service.PathName).Trim('"').Equals(
            $expectedExecutable, [StringComparison]::OrdinalIgnoreCase)
    $accountIsCorrect = $null -ne $service -and $service.StartName -eq 'LocalSystem'
    if ($null -ne $service -and (-not $pathIsCorrect -or -not $accountIsCorrect)) {
        & (Join-Path $env:SystemRoot 'System32\sc.exe') delete $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Unable to delete the damaged Wazuh service.' }
        Wait-ServiceAbsent
        $service = $null
    }
    if ($null -eq $service) {
        $installed = $false
        Start-Sleep -Seconds 2
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            $installExitCode = Invoke-AgentExecutableCommand `
                -ExecutablePath $expectedExecutable -Arguments 'install-service'
            if ($installExitCode -eq 0 -and
                $null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
                $installed = $true
                break
            }
            Start-Sleep -Seconds 5
        }
        if (-not $installed) { throw 'Unable to restore the Wazuh service.' }
    }
    Set-Service -Name $ServiceName -StartupType Automatic
    $windowsService = Get-Service -Name $ServiceName
    if ($windowsService.Status -ne 'Running') {
        & (Join-Path $env:SystemRoot 'System32\sc.exe') start $ServiceName | Out-Null
        if ($LASTEXITCODE -notin @(0, 1056)) {
            throw "Unable to start the restored Wazuh service: $LASTEXITCODE"
        }
    }
    (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
    Start-Sleep -Seconds 3
    if ((Get-Service -Name $ServiceName).Status -ne 'Running') {
        throw 'Restored Wazuh service exited immediately after startup.'
    }
}

function New-TestConfiguration {
    param(
        [Parameter(Mandatory)][string]$ApiKeyFile,
        [Parameter(Mandatory)][bool]$AuditOnly,
        [bool]$ForceRepair = $false,
        [string]$Name = 'active'
    )

    $path = Join-Path $RunRoot "$Name.config.json"
    $configuration = [ordered]@{
        bootstrapApiUrl = 'https://wazuh.ad.citronex.pl:8443'
        apiKeyFile = $ApiKeyFile
        enrollmentPasswordFile = ''
        agentGroup = ''
        allowedDownloadHosts = @('packages.wazuh.com')
        allowedSignerSubjectRegex = '(?i)\bWazuh\b'
        requireManifestSha256 = $true
        auditOnly = $AuditOnly
        forceRepair = $ForceRepair
        apiRetryCount = 2
        apiRetryDelaySeconds = 1
        enrollmentTimeoutSeconds = 30
        logDirectory = (Join-Path $RunRoot 'deployment-logs')
    }
    $configuration | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $path -Encoding UTF8
    Protect-TestPath -LiteralPath $path
    return $path
}

function Invoke-Deployment {
    param(
        [Parameter(Mandatory)][string]$Configuration,
        [Parameter(Mandatory)][string]$Scenario
    )

    $outputPath = Join-Path $RunRoot "$Scenario.console.log"
    $errorPath = Join-Path $RunRoot "$Scenario.console.err.log"
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File',
        ('"{0}"' -f $DeploymentScript), '-ConfigPath', ('"{0}"' -f $Configuration))
    $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') `
        -ArgumentList ($arguments -join ' ') -Wait -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $outputPath -RedirectStandardError $errorPath
    $exitCode = $process.ExitCode
    Protect-TestPath -LiteralPath $outputPath
    Protect-TestPath -LiteralPath $errorPath
    return $exitCode
}

function Assert-Equal {
    param(
        [Parameter(Mandatory)]$Actual,
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)][string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message Expected '$Expected', got '$Actual'."
    }
}

function Assert-AgentHealthy {
    param(
        [Parameter(Mandatory)][hashtable]$ExpectedHashes,
        [switch]$AllowRebuiltConfiguration
    )

    $directory = Get-TestAgentInstallDirectory
    $actual = Get-CriticalHashes -Directory $directory
    Assert-Equal $actual[$ExpectedKeyName] $ExpectedHashes[$ExpectedKeyName] `
        'client.keys identity hash changed.'
    if ($AllowRebuiltConfiguration) {
        Assert-Equal (Test-LocalAgentConfiguration `
                -LiteralPath (Join-Path $directory $ExpectedConfigName)) $true `
            'Rebuilt ossec.conf is not structurally valid.'
    }
    else {
        Assert-Equal $actual[$ExpectedConfigName] $ExpectedHashes[$ExpectedConfigName] `
            'ossec.conf hash changed.'
    }
    $signature = Get-AuthenticodeSignature -FilePath (Join-Path $directory $ExpectedExecutableName)
    Assert-Equal $signature.Status 'Valid' 'Wazuh executable signature is not valid.'
    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    Assert-Equal $service.State 'Running' 'Wazuh service is not running.'
    Assert-Equal $service.StartMode 'Auto' 'Wazuh service is not automatic.'
}

function New-BaselineBackup {
    param(
        [Parameter(Mandatory)][string]$ApiKeyFile
    )

    $installDirectory = Get-TestAgentInstallDirectory
    $product = Get-WazuhProduct
    $wasRunning = (Get-Service -Name $ServiceName).Status -eq 'Running'
    try {
        Stop-AgentIfPresent
        $agentBackup = Join-Path $BackupRoot 'ossec-agent'
        Protect-TestPath -LiteralPath $BackupRoot -Directory
        Protect-TestPath -LiteralPath $agentBackup -Directory
        Invoke-RobocopyChecked -Source $installDirectory -Destination $agentBackup
        $hashes = Get-CriticalHashes -Directory $installDirectory
        $backupHashes = Get-CriticalHashes -Directory $agentBackup
        foreach ($name in $hashes.Keys) {
            Assert-Equal $backupHashes[$name] $hashes[$name] "Backup hash mismatch for $name."
        }

        $registryFile = Join-Path $BackupRoot 'wazuh-uninstall.reg'
        & (Join-Path $env:SystemRoot 'System32\reg.exe') export `
            $product.RegistryPath $registryFile /y | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Unable to export Wazuh registry key.' }
        Protect-TestPath -LiteralPath $registryFile

        $apiKey = Read-ProtectedValue -LiteralPath $ApiKeyFile `
            -Description 'destructive test API key' -MinimumLength 32 `
            -RetryCount 1 -RetryDelaySeconds 1
        $manifest = Invoke-BootstrapApiGet `
            -Uri ([Uri]'https://wazuh.ad.citronex.pl:8443/api/v1/manifest') `
            -ApiKey $apiKey -RetryCount 2 -RetryDelaySeconds 1
        $msiPath = Join-Path $BackupRoot ([string]$manifest.targetAgent.msiFileName)
        Invoke-SecureDownload -Uri ([Uri]$manifest.targetAgent.downloadUrl) `
            -Destination $msiPath -AllowedHosts @('packages.wazuh.com')
        Test-AgentPackage -LiteralPath $msiPath `
            -ExpectedSha256 ([string]$manifest.targetAgent.sha256) `
            -RequireSha256 $true -AllowedSignerSubjectRegex '(?i)\bWazuh\b'
        Protect-TestPath -LiteralPath $msiPath

        $previousVersion = '4.13.1'
        $previousMsiPath = Join-Path $BackupRoot 'wazuh-agent-4.13.1-1.msi'
        Invoke-SecureDownload `
            -Uri ([Uri]'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.13.1-1.msi') `
            -Destination $previousMsiPath -AllowedHosts @('packages.wazuh.com')
        Test-AgentPackage -LiteralPath $previousMsiPath -ExpectedSha256 '' `
            -RequireSha256 $false -AllowedSignerSubjectRegex '(?i)\bWazuh\b'
        Protect-TestPath -LiteralPath $previousMsiPath

        $metadata = [ordered]@{
            createdAt = [DateTime]::UtcNow.ToString('o')
            computer = $env:COMPUTERNAME
            installDirectory = $installDirectory
            productCode = $product.ProductCode
            productVersion = $product.Version
            registryFile = $registryFile
            msiPath = $msiPath
            targetVersion = [string]$manifest.targetAgent.version
            previousVersion = $previousVersion
            previousMsiPath = $previousMsiPath
            previousMsiSha256 = (Get-FileHash -LiteralPath $previousMsiPath `
                -Algorithm SHA256).Hash
            criticalHashes = $hashes
            serviceWasRunning = $wasRunning
        }
        $metadataPath = Join-Path $BackupRoot 'metadata.json'
        $metadata | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
        Protect-TestPath -LiteralPath $metadataPath
        return [pscustomobject]$metadata
    }
    finally {
        if ($wasRunning) { Ensure-BaselineService -InstallDirectory $installDirectory }
    }
}

function Restore-Baseline {
    if ($null -eq $script:Baseline) { return }
    $installDirectory = [string]$script:Baseline.installDirectory
    $allowedDirectories = @(
        (Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'ossec-agent'),
        (Join-Path $env:ProgramFiles 'ossec-agent')
    ) | Where-Object { $_ }
    if ($allowedDirectories -notcontains $installDirectory) {
        throw "Unsafe Wazuh restore destination refused: $installDirectory"
    }

    Stop-AgentIfPresent
    $product = @(Get-WazuhProduct -AllowMissing)
    if ($product.Count -eq 1 -and
        $product[0].ProductCode -ne [string]$script:Baseline.productCode) {
        $removeArguments = @('/x', [string]$product[0].ProductCode, '/qn', '/norestart')
        $removeProcess = Start-Process `
            -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') `
            -ArgumentList ($removeArguments -join ' ') -Wait -PassThru -WindowStyle Hidden
        if ($removeProcess.ExitCode -notin @(0, 1605, 1641, 3010)) {
            throw "Unable to remove a non-baseline Wazuh product: $($removeProcess.ExitCode)."
        }
        $product = @()
    }
    if ($product.Count -eq 0) {
        $arguments = @('/i', ('"{0}"' -f [string]$script:Baseline.msiPath),
            '/qn', '/norestart', '/l*v', ('"{0}"' -f (Join-Path $RunRoot 'recovery-msi.log')))
        $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') `
            -ArgumentList ($arguments -join ' ') -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -notin @(0, 1641, 3010)) {
            throw "Emergency MSI recovery failed with exit code $($process.ExitCode)."
        }
        Stop-AgentIfPresent
    }

    if (-not (Test-Path -LiteralPath $installDirectory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $installDirectory -Force
    }
    Invoke-RobocopyChecked -Source (Join-Path $BackupRoot 'ossec-agent') `
        -Destination $installDirectory -Mirror
    & (Join-Path $env:SystemRoot 'System32\reg.exe') import `
        ([string]$script:Baseline.registryFile) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to restore Wazuh registry metadata.' }
    Ensure-BaselineService -InstallDirectory $installDirectory
    Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes
    )
}

function Invoke-TestScenario {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Test
    )

    if ($Scenario.Count -gt 0 -and $Scenario -notcontains $Name) {
        return
    }
    Write-TestEvent -Level INFO -Message "Starting scenario: $Name"
    Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes)
    $started = [DateTime]::UtcNow
    $passed = $false
    $errorMessage = $null
    try {
        & $Test
        $passed = $true
    }
    catch {
        $errorMessage = $_.Exception.Message
        $agentLog = Join-Path ([string]$script:Baseline.installDirectory) 'ossec.log'
        if (Test-Path -LiteralPath $agentLog -PathType Leaf) {
            Get-Content -LiteralPath $agentLog -Tail 200 |
                Set-Content -LiteralPath (Join-Path $RunRoot "$Name.agent.log") `
                    -Encoding UTF8
        }
        Write-TestEvent -Level ERROR -Message "Scenario failed: $Name" `
            -Data @{ error = $errorMessage }
    }
    finally {
        try { Restore-Baseline }
        catch {
            Write-TestEvent -Level CRITICAL -Message 'Baseline restore failed; aborting tests.' `
                -Data @{ error = $_.Exception.Message; scenario = $Name }
            throw
        }
    }
    $result = [pscustomobject]@{
        name = $Name
        passed = $passed
        durationSeconds = [Math]::Round(
            ([DateTime]::UtcNow - $started).TotalSeconds, 3)
        error = $errorMessage
    }
    $script:Results.Add($result)
    Write-TestEvent -Level $(if ($passed) { 'PASS' } else { 'FAIL' }) `
        -Message "Completed scenario: $Name"
}

if (-not $IUnderstandThisWillModifyWazuh) {
    throw 'Explicit destructive-test confirmation switch is required.'
}
if (-not (Test-Path -LiteralPath $DeploymentScript -PathType Leaf)) {
    throw 'Deployment script does not exist.'
}
if (-not (Test-Path -LiteralPath $ApiEnvironmentFile -PathType Leaf)) {
    throw 'API environment file does not exist.'
}

$DeploymentScript = (Resolve-Path -LiteralPath $DeploymentScript).Path
$ApiEnvironmentFile = (Resolve-Path -LiteralPath $ApiEnvironmentFile).Path
. $DeploymentScript

Protect-TestPath -LiteralPath $TestRoot -Directory
Protect-TestPath -LiteralPath $RunRoot -Directory
$null = New-Item -ItemType File -Path $ResultFile -Force
Protect-TestPath -LiteralPath $ResultFile

$environmentValues = Read-DotEnv -LiteralPath $ApiEnvironmentFile
$apiKey = [string]$environmentValues.CLIENT_API_KEY
if ($apiKey.Length -lt 32) { throw 'CLIENT_API_KEY is unavailable or invalid.' }
$apiKeyFile = Join-Path $RunRoot 'client-api-key.txt'
[IO.File]::WriteAllText($apiKeyFile, $apiKey + [Environment]::NewLine,
    (New-Object Text.UTF8Encoding($false)))
Protect-TestPath -LiteralPath $apiKeyFile
$environmentValues.CLIENT_API_KEY = $null
$apiKey = $null

$activeConfiguration = New-TestConfiguration -ApiKeyFile $apiKeyFile -AuditOnly $false
$auditConfiguration = New-TestConfiguration -ApiKeyFile $apiKeyFile -AuditOnly $true `
    -Name 'audit'
$forceRepairConfiguration = New-TestConfiguration -ApiKeyFile $apiKeyFile -AuditOnly $false `
    -ForceRepair $true -Name 'force-repair'
$badApiKeyFile = Join-Path $RunRoot 'invalid-api-key.txt'
[IO.File]::WriteAllText($badApiKeyFile, ('x' * 48) + [Environment]::NewLine,
    (New-Object Text.UTF8Encoding($false)))
Protect-TestPath -LiteralPath $badApiKeyFile
$badApiConfiguration = New-TestConfiguration -ApiKeyFile $badApiKeyFile -AuditOnly $true `
    -Name 'invalid-api-key'

$exitCode = 1
try {
    Write-TestEvent -Level INFO -Message 'Creating verified baseline backup.'
    $script:Baseline = New-BaselineBackup -ApiKeyFile $apiKeyFile
    Write-TestEvent -Level PASS -Message 'Baseline backup and recovery MSI verified.' `
        -Data @{ backup = $BackupRoot; version = $script:Baseline.productVersion }

    Invoke-TestScenario -Name 'healthy-audit-only' -Test {
        Assert-Equal (Invoke-Deployment $auditConfiguration 'healthy-audit-only') 0 `
            'Healthy audit returned the wrong code.'
        Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes)
    }

    Invoke-TestScenario -Name 'healthy-active-idempotency' -Test {
        Assert-Equal (Invoke-Deployment $activeConfiguration 'healthy-active-idempotency') 0 `
            'Healthy active run returned the wrong code.'
        Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes)
    }

    Invoke-TestScenario -Name 'invalid-api-key' -Test {
        Assert-Equal (Invoke-Deployment $badApiConfiguration 'invalid-api-key') 20 `
            'Invalid API key did not map to code 20.'
    }

    Invoke-TestScenario -Name 'audit-does-not-start-stopped-service' -Test {
        Stop-AgentIfPresent
        Assert-Equal (Invoke-Deployment $auditConfiguration 'audit-stopped') 0 `
            'Stopped-service audit returned the wrong code.'
        Assert-Equal (Get-Service $ServiceName).Status 'Stopped' `
            'Audit-only mode changed service state.'
    }

    Invoke-TestScenario -Name 'active-starts-stopped-service' -Test {
        Stop-AgentIfPresent
        Assert-Equal (Invoke-Deployment $activeConfiguration 'active-stopped') 0 `
            'Stopped-service recovery returned the wrong code.'
        Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes)
    }

    Invoke-TestScenario -Name 'active-removes-stale-authd-pass' -Test {
        $authPath = Join-Path ([string]$script:Baseline.installDirectory) 'authd.pass'
        [IO.File]::WriteAllText($authPath, 'synthetic-destructive-test-value')
        Assert-Equal (Invoke-Deployment $activeConfiguration 'stale-authd') 0 `
            'Stale authd.pass cleanup returned the wrong code.'
        Assert-Equal (Test-Path -LiteralPath $authPath) $false `
            'Stale authd.pass was not removed.'
    }

    foreach ($invalidKey in @(
            @{ Name = 'invalid-client-key-manager-id'; Value = '000 TEST any invalid-key-material' },
            @{ Name = 'invalid-client-key-wrong-host'; Value = '123 OTHER-PC any abcdef0123456789abcdef0123456789' },
            @{ Name = 'invalid-client-key-multiple-lines'; Value = "123 $env:COMPUTERNAME any abcdef0123456789abcdef0123456789`r`n124 $env:COMPUTERNAME any abcdef0123456789abcdef0123456789" }
        )) {
        Invoke-TestScenario -Name $invalidKey.Name -Test {
            Stop-AgentIfPresent
            $keyPath = Join-Path ([string]$script:Baseline.installDirectory) $ExpectedKeyName
            [IO.File]::WriteAllText($keyPath, [string]$invalidKey.Value)
            Assert-Equal (Invoke-Deployment $activeConfiguration $invalidKey.Name) 30 `
                'Invalid local identity did not fail closed with code 30.'
        }
    }

    Invoke-TestScenario -Name 'missing-ossec-conf' -Test {
        Stop-AgentIfPresent
        $configPath = Join-Path ([string]$script:Baseline.installDirectory) $ExpectedConfigName
        Move-Item -LiteralPath $configPath -Destination ($configPath + '.damage-test') -Force
        Assert-Equal (Invoke-Deployment $activeConfiguration 'missing-ossec-conf') 0 `
            'Missing configuration repair returned the wrong code.'
        Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes) `
            -AllowRebuiltConfiguration
    }

    Invoke-TestScenario -Name 'empty-ossec-conf' -Test {
        Stop-AgentIfPresent
        $configPath = Join-Path ([string]$script:Baseline.installDirectory) $ExpectedConfigName
        [IO.File]::WriteAllBytes($configPath, [byte[]]@())
        Assert-Equal (Invoke-Deployment $activeConfiguration 'empty-ossec-conf') 0 `
            'Empty configuration repair returned the wrong code.'
        Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes) `
            -AllowRebuiltConfiguration
    }

    Invoke-TestScenario -Name 'missing-agent-executable' -Test {
        Stop-AgentIfPresent
        $exePath = Join-Path ([string]$script:Baseline.installDirectory) $ExpectedExecutableName
        Move-Item -LiteralPath $exePath -Destination ($exePath + '.damage-test') -Force
        Assert-Equal (Invoke-Deployment $activeConfiguration 'missing-executable') 0 `
            'Missing executable repair returned the wrong code.'
        Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes)
    }

    Invoke-TestScenario -Name 'corrupt-agent-executable' -Test {
        Stop-AgentIfPresent
        $exePath = Join-Path ([string]$script:Baseline.installDirectory) $ExpectedExecutableName
        [IO.File]::WriteAllBytes($exePath, [byte[]](1, 2, 3, 4))
        Assert-Equal (Invoke-Deployment $activeConfiguration 'corrupt-executable') 0 `
            'Corrupt executable repair returned the wrong code.'
        Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes)
    }

    Invoke-TestScenario -Name 'missing-service' -Test {
        Stop-AgentIfPresent
        & (Join-Path $env:SystemRoot 'System32\sc.exe') delete $ServiceName | Out-Null
        Assert-Equal $LASTEXITCODE 0 'Service deletion failed.'
        Wait-ServiceAbsent
        Assert-Equal (Invoke-Deployment $activeConfiguration 'missing-service') 0 `
            'Missing service repair returned the wrong code.'
        Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes)
    }

    Invoke-TestScenario -Name 'disabled-service' -Test {
        Stop-AgentIfPresent
        Set-Service -Name $ServiceName -StartupType Disabled
        Assert-Equal (Invoke-Deployment $activeConfiguration 'disabled-service') 0 `
            'Disabled service repair returned the wrong code.'
        Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes)
    }

    Invoke-TestScenario -Name 'wrong-service-binary-path' -Test {
        Stop-AgentIfPresent
        & (Join-Path $env:SystemRoot 'System32\sc.exe') config $ServiceName `
            binPath= 'C:\Windows\System32\cmd.exe /c exit 1' | Out-Null
        Assert-Equal $LASTEXITCODE 0 'Service path corruption failed.'
        Assert-Equal (Invoke-Deployment $activeConfiguration 'wrong-service-path') 0 `
            'Wrong service path repair returned the wrong code.'
        Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes)
    }

    Invoke-TestScenario -Name 'forced-repair' -Test {
        Assert-Equal (Invoke-Deployment $forceRepairConfiguration 'forced-repair') 0 `
            'Forced repair returned the wrong code.'
        Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes)
    }

    Invoke-TestScenario -Name 'tampered-version-metadata-remains-safe' -Test {
        Set-WazuhDisplayVersion -Value '4.13.0'
        Assert-Equal (Invoke-Deployment $activeConfiguration 'tampered-version') 0 `
            'Inconsistent MSI display metadata disrupted deployment.'
        Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes)
    }

    Invoke-TestScenario -Name 'real-older-version-upgrade' -Test {
        Stop-AgentIfPresent
        $currentProduct = Get-WazuhProduct
        $uninstallArguments = @('/x', [string]$currentProduct.ProductCode,
            '/qn', '/norestart')
        $uninstall = Start-Process `
            -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') `
            -ArgumentList ($uninstallArguments -join ' ') -Wait -PassThru -WindowStyle Hidden
        if ($uninstall.ExitCode -notin @(0, 1641, 3010)) {
            throw "Current-version uninstall failed: $($uninstall.ExitCode)."
        }
        $installDirectory = [string]$script:Baseline.installDirectory
        if (-not (Test-Path -LiteralPath $installDirectory -PathType Container)) {
            $null = New-Item -ItemType Directory -Path $installDirectory -Force
        }
        foreach ($name in @($ExpectedKeyName, $ExpectedConfigName)) {
            Copy-Item -LiteralPath (Join-Path $BackupRoot "ossec-agent\$name") `
                -Destination (Join-Path $installDirectory $name) -Force
        }
        $previousArguments = @('/i', ('"{0}"' -f [string]$script:Baseline.previousMsiPath),
            '/qn', '/norestart', 'WAZUH_MANAGER="192.168.21.15"',
            'WAZUH_MANAGER_PORT="1514"', 'WAZUH_PROTOCOL="TCP"')
        $previousInstall = Start-Process `
            -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') `
            -ArgumentList ($previousArguments -join ' ') -Wait -PassThru -WindowStyle Hidden
        if ($previousInstall.ExitCode -notin @(0, 1641, 3010)) {
            throw "Previous-version install failed: $($previousInstall.ExitCode)."
        }
        Stop-AgentIfPresent
        foreach ($name in @($ExpectedKeyName, $ExpectedConfigName)) {
            Copy-Item -LiteralPath (Join-Path $BackupRoot "ossec-agent\$name") `
                -Destination (Join-Path $installDirectory $name) -Force
        }
        Ensure-BaselineService -InstallDirectory $installDirectory
        Assert-Equal (Get-WazuhProduct).Version ([string]$script:Baseline.previousVersion) `
            'Previous Wazuh version was not installed.'
        Assert-Equal (Invoke-Deployment $activeConfiguration 'real-version-upgrade') 0 `
            'Real version upgrade returned the wrong code.'
        Assert-Equal (Get-WazuhProduct).Version ([string]$script:Baseline.targetVersion) `
            'Real version upgrade did not reach the target.'
        Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes)
    }

    Invoke-TestScenario -Name 'newer-version-no-downgrade' -Test {
        Set-WazuhDisplayVersion -Value '99.0.0'
        Assert-Equal (Invoke-Deployment $activeConfiguration 'newer-version') 0 `
            'Newer version handling returned the wrong code.'
        Assert-Equal (Get-WazuhProduct).Version '99.0.0' 'A downgrade was attempted.'
    }

    Invoke-TestScenario -Name 'full-msi-reinstall-with-preserved-identity' -Test {
        Stop-AgentIfPresent
        $arguments = @('/x', [string]$script:Baseline.productCode, '/qn', '/norestart',
            '/l*v', ('"{0}"' -f (Join-Path $RunRoot 'uninstall-test.log')))
        $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') `
            -ArgumentList ($arguments -join ' ') -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -notin @(0, 1641, 3010)) {
            throw "Test uninstall failed with exit code $($process.ExitCode)."
        }
        $installDirectory = [string]$script:Baseline.installDirectory
        if (-not (Test-Path -LiteralPath $installDirectory -PathType Container)) {
            $null = New-Item -ItemType Directory -Path $installDirectory -Force
        }
        foreach ($name in @($ExpectedKeyName, $ExpectedConfigName)) {
            Copy-Item -LiteralPath (Join-Path $BackupRoot "ossec-agent\$name") `
                -Destination (Join-Path $installDirectory $name) -Force
        }
        Assert-Equal (Invoke-Deployment $activeConfiguration 'full-reinstall') 0 `
            'Full reinstall returned the wrong code.'
        Assert-AgentHealthy -ExpectedHashes ([hashtable]$script:Baseline.criticalHashes)
    }

    $failed = @($script:Results | Where-Object { -not $_.passed })
    $summary = [ordered]@{
        runId = $RunId
        computer = $env:COMPUTERNAME
        backup = $BackupRoot
        total = $script:Results.Count
        passed = $script:Results.Count - $failed.Count
        failed = $failed.Count
        results = $script:Results
    }
    $summary | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $SummaryFile -Encoding UTF8
    Protect-TestPath -LiteralPath $SummaryFile
    $exitCode = if ($failed.Count -eq 0) { 0 } else { 1 }
}
catch {
    $infrastructureError = $_.Exception.Message
    Write-TestEvent -Level CRITICAL -Message 'Destructive test infrastructure failed.' `
        -Data @{ error = $infrastructureError }
    $failed = @($script:Results | Where-Object { -not $_.passed })
    $summary = [ordered]@{
        runId = $RunId
        computer = $env:COMPUTERNAME
        backup = if ($null -eq $script:Baseline) { $null } else { $BackupRoot }
        total = $script:Results.Count
        passed = $script:Results.Count - $failed.Count
        failed = $failed.Count
        infrastructureError = $infrastructureError
        results = $script:Results
    }
    $summary | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $SummaryFile -Encoding UTF8
    Protect-TestPath -LiteralPath $SummaryFile
    $exitCode = 2
}
finally {
    if ($null -ne $script:Baseline) {
        Restore-Baseline
        Write-TestEvent -Level PASS -Message 'Final baseline restore completed.'
    }
    if (Test-Path -LiteralPath $apiKeyFile) {
        Remove-Item -LiteralPath $apiKeyFile -Force
    }
    if (Test-Path -LiteralPath $badApiKeyFile) {
        Remove-Item -LiteralPath $badApiKeyFile -Force
    }
    if (-not [string]::IsNullOrWhiteSpace($ReportDirectory)) {
        if (-not [IO.Path]::IsPathRooted($ReportDirectory)) {
            throw 'ReportDirectory must be an absolute path.'
        }
        $reportRunDirectory = Join-Path ([IO.Path]::GetFullPath($ReportDirectory)) $RunId
        $null = New-Item -ItemType Directory -Path $reportRunDirectory -Force
        if (Test-Path -LiteralPath $SummaryFile) {
            Copy-Item -LiteralPath $SummaryFile -Destination $reportRunDirectory -Force
        }
        Copy-Item -LiteralPath $ResultFile -Destination $reportRunDirectory -Force
        Get-ChildItem -LiteralPath $RunRoot -Filter '*.console*.log' -File `
            -ErrorAction SilentlyContinue |
            Copy-Item -Destination $reportRunDirectory -Force
        if (Test-Path -LiteralPath (Join-Path $RunRoot 'deployment-logs')) {
            Get-ChildItem -LiteralPath (Join-Path $RunRoot 'deployment-logs') -File |
                Copy-Item -Destination $reportRunDirectory -Force
        }
    }
}

Write-Host "Summary: $SummaryFile"
exit $exitCode
