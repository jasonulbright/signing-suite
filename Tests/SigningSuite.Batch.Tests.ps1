#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeDiscovery {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module -Name (Join-Path (Split-Path -Parent $PSScriptRoot) 'Module\SigningSuite\SigningSuite.psd1') -Force
    $script:dlibAvailable = [bool](Find-SignTool) -and [bool](Get-TestDigestSignLibrary -Architecture 'x64')
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module -Name (Join-Path $repoRoot 'Module\SigningSuite\SigningSuite.psd1') -Force
    Import-Module -Name Microsoft.PowerShell.Security
    $script:signTool = Find-SignTool
    $script:hostExe = (Get-Process -Id $PID).Path
}

Describe 'Batch signing' {

    BeforeAll {
        $script:batchRoot = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'batch [x]')).FullName
        [System.IO.File]::WriteAllText((Join-Path $batchRoot 'one.ps1'), "Write-Output 1`r`n")
        [System.IO.File]::WriteAllText((Join-Path $batchRoot 'two.vbs'), "WScript.Echo 1`r`n")
        [System.IO.File]::WriteAllText((Join-Path $batchRoot 'notes.txt'), 'x')
        New-TestZip -Path (Join-Path $batchRoot 'app.msix') -Entries @{ 'AppxManifest.xml' = '<Package><Identity Publisher="CN=Signing Suite Test"/></Package>' }
        $pfx = Join-Path $TestDrive 'batch.pfx'
        New-TestPfx -Path $pfx
        $script:batchCertificate = Import-TestSigningCertificate -Path $pfx
    }

    AfterAll {
        Remove-TestKey -Certificate $script:batchCertificate
    }

    It 'lists what would be signed with -WhatIf and changes nothing' {
        $results = @(Invoke-SigningBatch -Path $script:batchRoot -Certificate $script:batchCertificate -Engine PowerShell -WhatIf)
        @($results | Where-Object Status -eq 'WhatIf' | ForEach-Object Name) | Sort-Object | Should -Be @('one.ps1', 'two.vbs')
        (Get-FileSignatureState -LiteralPath (Join-Path $script:batchRoot 'one.ps1')).State | Should -Be 'NotSigned'
    }

    It 'signs what it can and explains the rest' {
        $results = @(Invoke-SigningBatch -Path $script:batchRoot -Certificate $script:batchCertificate)
        $byName = @{}
        foreach ($result in $results) {
            $byName[$result.Name] = $result
        }
        $byName.Keys.Count | Should -Be 3
        $byName['one.ps1'].Status | Should -Be 'Signed'
        $byName['one.ps1'].SignerThumbprint | Should -Be $script:batchCertificate.Thumbprint
        $byName['two.vbs'].Status | Should -Be 'Signed'
        $byName['app.msix'].Status | Should -Be 'Failed'
    }

    It 'leaves validly signed files alone with -SkipValid' -Skip:(-not (Find-SignTool)) {
        $copy = Join-Path $script:batchRoot 'vendor-signed.exe'
        [System.IO.File]::Copy($script:signTool.Path, $copy, $true)
        $before = [System.IO.File]::ReadAllBytes($copy)
        $results = @(Invoke-SigningBatch -Path $copy -Certificate $script:batchCertificate -Engine PowerShell -SkipValid)
        $results[0].Status | Should -Be 'Skipped'
        $results[0].Detail | Should -BeLike 'Already has a valid signature from Microsoft*'
        [System.IO.File]::ReadAllBytes($copy).Length | Should -Be $before.Length
        [System.IO.File]::Delete($copy)
    }

    It 'signs an untrusted signature again with -SkipValid' {
        $results = @(Invoke-SigningBatch -Path (Join-Path $script:batchRoot 'one.ps1') -Certificate $script:batchCertificate -Engine PowerShell -SkipValid)
        $results[0].Status | Should -Be 'Signed'
    }

    It 'refuses an incomplete identity or timestamp' {
        { Invoke-SigningBatch -Path $script:batchRoot } | Should -Throw -ExpectedMessage '*needs a certificate*'
        { Invoke-SigningBatch -Path $script:batchRoot -Source Dlib -DlibPath (Join-Path $TestDrive 'missing.dll') } | Should -Throw
        { Invoke-SigningBatch -Path $script:batchRoot -Certificate $script:batchCertificate -TimestampMode Rfc3161 } | Should -Throw -ExpectedMessage '*server URL*'
    }

    It 'warns about paths it cannot read' {
        $warnings = $null
        $null = Invoke-SigningBatch -Path (Join-Path $TestDrive 'nowhere') -Certificate $script:batchCertificate -WarningVariable warnings -WarningAction SilentlyContinue
        @($warnings).Count | Should -Be 1
    }
}

Describe 'Command-line script' {

    BeforeAll {
        $script:cliRoot = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'cli')).FullName
        $script:cliScript = Join-Path $script:repoRoot 'Invoke-SigningSuite.ps1'
        [System.IO.File]::WriteAllText((Join-Path $cliRoot 'good.ps1'), "Write-Output 1`r`n")
        $script:cliDlib = Get-TestDigestSignLibrary -Architecture 'x64'
        $script:cliIdentity = New-TestDlibIdentity -Folder $script:cliRoot
        $script:failRoot = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'cli-fail')).FullName
        [System.IO.File]::WriteAllText((Join-Path $failRoot 'bad.ps1'), "Write-Output 1`r`n")
        $script:failMetadata = Join-Path $failRoot 'fail.txt'
        [System.IO.File]::WriteAllText($script:failMetadata, 'fail=80090016')
    }

    It 'signs through a digest signing library and exits 0' -Skip:(-not $script:dlibAvailable) {
        $output = & $script:hostExe -NoProfile -ExecutionPolicy Bypass -File $script:cliScript -Path $script:cliRoot -DlibPath $script:cliDlib -DlibMetadata $script:cliIdentity.MetadataPath -CertificateFile $script:cliIdentity.CertificateFile 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output | Out-String)
        (Get-FileSignatureState -LiteralPath (Join-Path $script:cliRoot 'good.ps1')).Thumbprint | Should -Be $script:cliIdentity.Thumbprint
    }

    It 'exits 1 when a file fails to sign' -Skip:(-not $script:dlibAvailable) {
        $output = & $script:hostExe -NoProfile -ExecutionPolicy Bypass -File $script:cliScript -Path $script:failRoot -DlibPath $script:cliDlib -DlibMetadata $script:failMetadata -CertificateFile $script:cliIdentity.CertificateFile 2>&1
        $LASTEXITCODE | Should -Be 1 -Because ($output | Out-String)
    }

    It 'verifies and exits 0 when no signature is invalid' {
        $null = & $script:hostExe -NoProfile -ExecutionPolicy Bypass -File $script:cliScript -Path $script:failRoot -Verify 2>&1
        $LASTEXITCODE | Should -Be 0
    }

    It 'exits 1 when no signable file is found' {
        $empty = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'cli-empty')).FullName
        [System.IO.File]::WriteAllText((Join-Path $empty 'notes.txt'), 'x')
        $null = & $script:hostExe -NoProfile -ExecutionPolicy Bypass -File $script:cliScript -Path $empty -Verify 2>&1
        $LASTEXITCODE | Should -Be 1
    }

    It 'refuses signing options with -Verify' {
        $output = & $script:hostExe -NoProfile -ExecutionPolicy Bypass -File $script:cliScript -Path $script:failRoot -Verify -TimestampMode Rfc3161 2>&1
        $LASTEXITCODE | Should -Be 2
        ($output | Out-String) | Should -BeLike '*-TimestampMode*'
    }

    It 'fails for a thumbprint that is not in the store' {
        $null = & $script:hostExe -NoProfile -ExecutionPolicy Bypass -File $script:cliScript -Path $script:failRoot -CertificateThumbprint '00' 2>&1
        $LASTEXITCODE | Should -Not -Be 0
    }
}
