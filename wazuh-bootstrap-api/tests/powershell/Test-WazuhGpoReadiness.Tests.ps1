$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$scriptPath = Join-Path $projectRoot 'deploy\gpo\Test-WazuhGpoReadiness.ps1'
. $scriptPath

function Assert-Throws {
    param([Parameter(Mandatory)][scriptblock]$ScriptBlock)

    $threw = $false
    try { & $ScriptBlock }
    catch { $threw = $true }
    $threw | Should Be $true
}

Describe 'Test-WazuhGpoReadiness protected file validation' {
    It 'accepts a non-empty UTF-8 file without BOM or line break' {
        $path = Join-Path $TestDrive 'valid.txt'
        [IO.File]::WriteAllText($path, ('a' * 32), [Text.UTF8Encoding]::new($false))
        (Read-ValidatedSecretFile -LiteralPath $path -Description 'test secret' `
            -MinimumLength 32).Length | Should Be 32
    }

    It 'rejects an empty file' {
        $path = Join-Path $TestDrive 'empty.txt'
        [IO.File]::WriteAllBytes($path, [byte[]]@())
        Assert-Throws {
            Read-ValidatedSecretFile -LiteralPath $path -Description 'test secret' `
                -MinimumLength 1
        }
    }

    It 'rejects UTF-8 BOM, line breaks, and surrounding whitespace' {
        $bom = Join-Path $TestDrive 'bom.txt'
        [IO.File]::WriteAllText($bom, 'secret-value', [Text.UTF8Encoding]::new($true))
        Assert-Throws {
            Read-ValidatedSecretFile -LiteralPath $bom -Description 'test secret' `
                -MinimumLength 1
        }

        $lineBreak = Join-Path $TestDrive 'line-break.txt'
        [IO.File]::WriteAllText($lineBreak, "secret`r`n", [Text.UTF8Encoding]::new($false))
        Assert-Throws {
            Read-ValidatedSecretFile -LiteralPath $lineBreak -Description 'test secret' `
                -MinimumLength 1
        }

        $whitespace = Join-Path $TestDrive 'whitespace.txt'
        [IO.File]::WriteAllText($whitespace, ' secret ', [Text.UTF8Encoding]::new($false))
        Assert-Throws {
            Read-ValidatedSecretFile -LiteralPath $whitespace -Description 'test secret' `
                -MinimumLength 1
        }
    }

    It 'rejects a placeholder and a value below the required length' {
        $placeholder = Join-Path $TestDrive 'placeholder.txt'
        [IO.File]::WriteAllText($placeholder, 'CHANGE_ME', [Text.UTF8Encoding]::new($false))
        Assert-Throws {
            Read-ValidatedSecretFile -LiteralPath $placeholder -Description 'test secret' `
                -MinimumLength 1
        }

        $short = Join-Path $TestDrive 'short.txt'
        [IO.File]::WriteAllText($short, 'short', [Text.UTF8Encoding]::new($false))
        Assert-Throws {
            Read-ValidatedSecretFile -LiteralPath $short -Description 'test secret' `
                -MinimumLength 32
        }
    }
}

Describe 'Test-WazuhGpoReadiness static secret safety' {
    It 'does not print secret values or bypass certificate validation' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $source | Should Not Match 'SkipCertificateCheck'
        $source | Should Not Match 'TrustAllCert'
        $source | Should Not Match 'Write-(Host|Output).*\$(apiKey|enrollmentPassword|value)'
        $source.Contains("'X-API-Key' = `$ApiKey") | Should Be $true
        $source | Should Match 'BatchMode=yes'
        $source | Should Match 'StrictHostKeyChecking=yes'
        $source | Should Match 'sudo -n --'
        $source | Should Match 'HMACSHA256'
    }
}

Describe 'Test-WazuhGpoReadiness enrollment proof' {
    It 'implements the RFC 4231 HMAC-SHA256 test vector' {
        $key = [byte[]]::new(20)
        for ($index = 0; $index -lt $key.Length; $index++) { $key[$index] = 0x0b }
        $message = [Text.Encoding]::ASCII.GetBytes('Hi There')
        [byte[]]$proof = @(Get-HmacSha256Bytes -Key $key -Message $message)
        $hex = -join ($proof | ForEach-Object { $_.ToString('x2') })
        $hex | Should Be 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
    }
}
