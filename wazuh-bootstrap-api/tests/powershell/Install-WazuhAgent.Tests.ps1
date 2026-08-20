$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$scriptPath = Join-Path $projectRoot 'deploy\gpo\Install-WazuhAgent.ps1'
. $scriptPath

function Assert-Throws {
    param([Parameter(Mandatory)][scriptblock]$ScriptBlock)

    $threw = $false
    try { & $ScriptBlock }
    catch { $threw = $true }
    $threw | Should Be $true
}

Describe 'Install-WazuhAgent version handling' {
    It 'normalizes supported Wazuh version strings' {
        (ConvertTo-AgentVersion -Value 'Wazuh v4.14.6').ToString() | Should Be '4.14.6'
        (ConvertTo-AgentVersion -Value '4.14.6-1').ToString() | Should Be '4.14.6'
    }

    It 'rejects an invalid version' {
        Assert-Throws { ConvertTo-AgentVersion -Value 'latest' }
    }
}

Describe 'Install-WazuhAgent client key validation' {
    It 'accepts one structurally valid key for the current computer' {
        $path = Join-Path $TestDrive 'client.keys'
        Set-Content -LiteralPath $path `
            -Value '123 LAP006 any abcdef0123456789abcdef0123456789' -Encoding ASCII
        Test-LocalClientKey -LiteralPath $path -ComputerName 'lap006' | Should Be $true
    }

    It 'rejects a key copied from another computer' {
        $path = Join-Path $TestDrive 'client.keys'
        Set-Content -LiteralPath $path `
            -Value '123 OTHER-PC any abcdef0123456789abcdef0123456789' -Encoding ASCII
        Test-LocalClientKey -LiteralPath $path -ComputerName 'LAP006' | Should Be $false
    }

    It 'rejects manager ID 000 and multiple records' {
        $manager = Join-Path $TestDrive 'manager.keys'
        Set-Content -LiteralPath $manager `
            -Value '000 LAP006 any abcdef0123456789abcdef0123456789' -Encoding ASCII
        Test-LocalClientKey -LiteralPath $manager -ComputerName 'LAP006' | Should Be $false

        $multiple = Join-Path $TestDrive 'multiple.keys'
        Set-Content -LiteralPath $multiple -Value @(
            '123 LAP006 any abcdef0123456789abcdef0123456789',
            '124 LAP006 any abcdef0123456789abcdef0123456789'
        ) -Encoding ASCII
        Test-LocalClientKey -LiteralPath $multiple -ComputerName 'LAP006' | Should Be $false
    }
}

Describe 'Install-WazuhAgent controlled re-enrollment policy' {
    It 'allows an old disconnected record' {
        $agent = [pscustomobject]@{
            status = 'disconnected'
            dateAdded = '2025-09-25T06:46:37Z'
            lastKeepAlive = '2026-07-13T13:20:54Z'
        }

        $decision = Get-StaleAgentReenrollmentDecision -Agent $agent `
            -DataAsOf '2026-07-28T12:10:58Z' -MinimumAgeMinutes 60

        $decision.Eligible | Should Be $true
        $decision.Reason | Should Be 'disconnected_record_is_stale'
        ($decision.DisconnectedMinutes -gt 60) | Should Be $true
    }

    It 'allows an old record which never connected' {
        $agent = [pscustomobject]@{
            status = 'never_connected'
            dateAdded = '2026-07-20T12:00:00Z'
            lastKeepAlive = $null
        }

        $decision = Get-StaleAgentReenrollmentDecision -Agent $agent `
            -DataAsOf '2026-07-28T12:10:58Z' -MinimumAgeMinutes 60

        $decision.Eligible | Should Be $true
        $decision.Reason | Should Be 'never_connected_record_is_stale'
    }

    It 'blocks active and recently disconnected records' {
        $active = [pscustomobject]@{
            status = 'active'
            dateAdded = '2025-01-01T00:00:00Z'
            lastKeepAlive = '2026-07-28T12:10:00Z'
        }
        $recent = [pscustomobject]@{
            status = 'disconnected'
            dateAdded = '2025-01-01T00:00:00Z'
            lastKeepAlive = '2026-07-28T11:40:58Z'
        }

        $activeDecision = Get-StaleAgentReenrollmentDecision -Agent $active `
            -DataAsOf '2026-07-28T12:10:58Z' -MinimumAgeMinutes 60
        $recentDecision = Get-StaleAgentReenrollmentDecision -Agent $recent `
            -DataAsOf '2026-07-28T12:10:58Z' -MinimumAgeMinutes 60

        $activeDecision.Eligible | Should Be $false
        $activeDecision.Reason | Should Be 'agent_status_is_not_replaceable'
        $recentDecision.Eligible | Should Be $false
        $recentDecision.Reason | Should Be 'agent_was_disconnected_too_recently'
    }

    It 'fails closed when timestamps are missing, invalid, or in the future' {
        $missingKeepAlive = [pscustomobject]@{
            status = 'disconnected'
            dateAdded = '2025-01-01T00:00:00Z'
            lastKeepAlive = $null
        }
        $futureRegistration = [pscustomobject]@{
            status = 'never_connected'
            dateAdded = '2026-07-29T00:00:00Z'
            lastKeepAlive = $null
        }

        $missingDecision = Get-StaleAgentReenrollmentDecision -Agent $missingKeepAlive `
            -DataAsOf '2026-07-28T12:10:58Z' -MinimumAgeMinutes 60
        $futureDecision = Get-StaleAgentReenrollmentDecision -Agent $futureRegistration `
            -DataAsOf '2026-07-28T12:10:58Z' -MinimumAgeMinutes 60

        $missingDecision.Eligible | Should Be $false
        $missingDecision.Reason | Should Be 'last_keep_alive_is_missing_or_invalid'
        $futureDecision.Eligible | Should Be $false
        $futureDecision.Reason | Should Be 'registration_timestamp_is_missing_or_invalid'
    }
}

Describe 'Install-WazuhAgent local file health' {
    It 'accepts a non-empty Wazuh configuration and rejects an empty one' {
        $valid = Join-Path $TestDrive 'valid-ossec.conf'
        Set-Content -LiteralPath $valid `
            -Value '<ossec_config><client><server><address>192.0.2.1</address></server></client></ossec_config>' `
            -Encoding UTF8
        Test-LocalAgentConfiguration -LiteralPath $valid | Should Be $true

        $empty = Join-Path $TestDrive 'empty-ossec.conf'
        Set-Content -LiteralPath $empty -Value '' -NoNewline
        Test-LocalAgentConfiguration -LiteralPath $empty | Should Be $false
    }

    It 'rejects an unsigned executable as unhealthy' {
        $fakeExecutable = Join-Path $TestDrive 'wazuh-agent.exe'
        Set-Content -LiteralPath $fakeExecutable -Value 'not-an-executable'
        Test-InstalledAgentExecutable -LiteralPath $fakeExecutable `
            -AllowedSignerSubjectRegex '(?i)\bWazuh\b' | Should Be $false
    }
}

Describe 'Install-WazuhAgent identity backup and recovery' {
    It 'allows a clean installation with no identity files to restore' {
        $installDirectory = Join-Path $TestDrive 'clean-install'
        $workDirectory = Join-Path $TestDrive 'clean-work'
        $null = New-Item -ItemType Directory -Path $installDirectory, $workDirectory -Force

        $backupFiles = @(Backup-AgentIdentity -InstallDirectory $installDirectory `
                -WorkDirectory $workDirectory -ComputerName 'LAP006')

        $backupFiles.Count | Should Be 0
        Restore-AgentIdentity -InstallDirectory $installDirectory `
            -WorkDirectory $workDirectory -Files @()
        $true | Should Be $true
    }

    It 'does not preserve an empty client key from a partial installation' {
        $installDirectory = Join-Path $TestDrive 'partial-install'
        $workDirectory = Join-Path $TestDrive 'partial-work'
        $null = New-Item -ItemType Directory -Path $installDirectory, $workDirectory -Force
        [IO.File]::WriteAllBytes((Join-Path $installDirectory 'client.keys'), [byte[]]@())
        Set-Content -LiteralPath (Join-Path $installDirectory 'ossec.conf') `
            -Value '<ossec_config><client><server><address>192.0.2.1</address></server></client></ossec_config>' `
            -Encoding UTF8

        $backupFiles = @(Backup-AgentIdentity -InstallDirectory $installDirectory `
                -WorkDirectory $workDirectory -ComputerName 'LAP006')

        $backupFiles.Count | Should Be 1
        ($backupFiles -contains 'ossec.conf') | Should Be $true
        ($backupFiles -contains 'client.keys') | Should Be $false
        (Test-Path -LiteralPath (Join-Path $workDirectory 'client.keys')) | Should Be $false
    }

    It 'preserves a structurally valid identity for the current computer' {
        $installDirectory = Join-Path $TestDrive 'valid-install'
        $workDirectory = Join-Path $TestDrive 'valid-work'
        $null = New-Item -ItemType Directory -Path $installDirectory, $workDirectory -Force
        Set-Content -LiteralPath (Join-Path $installDirectory 'client.keys') `
            -Value '123 LAP006 any abcdef0123456789abcdef0123456789' -Encoding ASCII

        $backupFiles = @(Backup-AgentIdentity -InstallDirectory $installDirectory `
                -WorkDirectory $workDirectory -ComputerName 'LAP006')

        $backupFiles.Count | Should Be 1
        ($backupFiles -contains 'client.keys') | Should Be $true
        (Test-Path -LiteralPath (Join-Path $workDirectory 'client.keys')) | Should Be $true
    }
}

Describe 'Install-WazuhAgent configuration repair' {
    It 'writes a Wazuh fragment without an XML declaration' {
        $path = Join-Path $TestDrive 'ossec.conf'
        Set-Content -LiteralPath $path -Encoding UTF8 -Value @'
<ossec_config>
  <client>
    <server>
      <address>MANAGER_IP</address>
    </server>
  </client>
</ossec_config>
'@
        Repair-AgentConfiguration -LiteralPath $path `
            -ManagerAddress '192.168.21.15' -ManagerPort 1514
        $content = Get-Content -LiteralPath $path -Raw
        $content.StartsWith('<?xml') | Should Be $false
        $content | Should Match '<address>192\.168\.21\.15</address>'
        $content | Should Match '<port>1514</port>'
        $content | Should Match '<protocol>tcp</protocol>'
    }
}

Describe 'Install-WazuhAgent input hardening' {
    It 'quotes safe MSI properties' {
        ConvertTo-MsiProperty -Name 'WAZUH_MANAGER' -Value '192.168.21.15' |
            Should Be 'WAZUH_MANAGER="192.168.21.15"'
    }

    It 'rejects MSI argument injection characters' {
        Assert-Throws { ConvertTo-MsiProperty -Name 'WAZUH_AGENT_NAME' -Value 'PC" /qn' }
        Assert-Throws { ConvertTo-MsiProperty -Name 'WAZUH_AGENT_NAME' -Value "PC`nOTHER=1" }
    }

    It 'allows only configured HTTPS package hosts' {
        Assert-Throws { Test-AllowedHttpsUri -Uri ([Uri]'http://packages.wazuh.com/a.msi') `
            -AllowedHosts @('packages.wazuh.com') }
        Assert-Throws { Test-AllowedHttpsUri -Uri ([Uri]'https://evil.example/a.msi') `
            -AllowedHosts @('packages.wazuh.com') }
        Test-AllowedHttpsUri -Uri ([Uri]'https://packages.wazuh.com/a.msi') `
            -AllowedHosts @('packages.wazuh.com')
    }
}

Describe 'Install-WazuhAgent configuration' {
    It 'provides valid embedded production settings without secret values' {
        $configuration = ConvertTo-GpoConfiguration -Configuration (Get-GpoConfiguration)
        $configuration.BootstrapApiUrl | Should Be 'https://wazuh.ad.citronex.pl:8443'
        $configuration.AuditOnly | Should Be $false
        $configuration.AllowStaleAgentReenrollment | Should Be $true
        $configuration.StaleAgentReenrollmentMinutes | Should Be 60
        ($configuration.AllowedDownloadHosts -contains 'packages.wazuh.com') | Should Be $true
    }

    It 'rejects invalid embedded settings' {
        $configuration = Get-GpoConfiguration
        $configuration.BootstrapApiUrl = 'http://wazuh.example'
        Assert-Throws { ConvertTo-GpoConfiguration -Configuration $configuration }
    }

    It 'rejects an invalid stale-agent re-enrollment threshold' {
        $configuration = Get-GpoConfiguration
        $configuration.StaleAgentReenrollmentMinutes = 0
        Assert-Throws { ConvertTo-GpoConfiguration -Configuration $configuration }
    }
}

Describe 'Install-WazuhAgent static secret safety' {
    It 'passes the embedded registration password to the MSI for a fresh enrollment' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Match "properties\['WAZUH_REGISTRATION_PASSWORD'\]"
        $source | Should Match '\$script:WazuhRegistrationPassword'
        $source | Should Not Match 'Write-EnrollmentPassword'
    }

    It 'does not bypass TLS, signatures, or PowerShell policy' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Not Match 'SkipCertificateCheck'
        $source | Should Not Match 'Invoke-Expression'
        $source | Should Not Match 'ExecutionPolicy\s+Bypass'
        $source | Should Match 'Get-AuthenticodeSignature'
        $source | Should Match 'Get-FileHash'
        $source | Should Match 'Removed a stale enrollment password file'
        $source | Should Match 'Stop-AgentService -ServiceName'
    }

    It 'does not depend on an external GPO configuration file' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Not Match 'ConfigPath'
        $source | Should Not Match 'WazuhAgentGpo\.config'
    }
}
