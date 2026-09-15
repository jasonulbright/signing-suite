#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeDiscovery {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module -Name (Join-Path (Split-Path -Parent $PSScriptRoot) 'Module\SigningSuite\SigningSuite.psd1') -Force
    $discoveredTool = Find-SignTool
    $script:signToolAvailable = [bool]$discoveredTool
    $script:dlibAvailable = $script:signToolAvailable -and [bool](Get-TestDigestSignLibrary -Architecture 'x64')
    $makeAppx = if ($discoveredTool) { Join-Path (Split-Path -Parent $discoveredTool.Path) 'makeappx.exe' } else { '' }
    $script:packagesAvailable = $script:dlibAvailable -and [System.IO.File]::Exists($makeAppx)
    $script:openXmlSipRegistered = Test-SipRegistered -Guid '6e64d5bd-ceb0-4b66-b4a0-15ac71775c48'
    $fixtures = $env:SIGNINGSUITE_OFFICE_FIXTURES
    $script:officeAvailable = [bool]$fixtures -and [System.IO.Directory]::Exists($fixtures) -and $script:openXmlSipRegistered -and
        (Test-SipRegistered -Guid '01f45160-3e3e-11d3-b49a-00104b2cf645')
    $currentSip = Get-OfficeSipStatus | Where-Object { $_.Is64Bit -eq [Environment]::Is64BitProcess } | Select-Object -First 1
    $script:officeClearAvailable = $script:officeAvailable -and $currentSip -and [bool]$currentSip.OffClearSigPath
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:manifest = Join-Path (Split-Path -Parent $PSScriptRoot) 'Module\SigningSuite\SigningSuite.psd1'
    Import-Module -Name $script:manifest -Force
    Import-Module -Name Microsoft.PowerShell.Security
    $script:bits = if ([Environment]::Is64BitProcess) { 'x64' } else { 'x86' }
    $script:signTool = Find-SignTool
}

Describe 'Module manifest' {

    It 'exports every function it lists, and each exported function exists' {
        $data = Import-PowerShellDataFile -LiteralPath $script:manifest
        $exported = @((Get-Module SigningSuite).ExportedFunctions.Keys)
        foreach ($name in $data.FunctionsToExport) {
            $exported | Should -Contain $name
        }
        $exported.Count | Should -Be @($data.FunctionsToExport).Count
    }

    It 'carries the YYYY.MM.DD.#### version and a matching ModuleVersion' {
        $data = Import-PowerShellDataFile -LiteralPath $script:manifest
        $version = $data.PrivateData.SigningSuiteVersion
        $version | Should -Match '^\d{4}\.\d{2}\.\d{2}\.\d{4}$'
        $parts = $version.Split('.') | ForEach-Object { [int]$_ }
        [version]$data.ModuleVersion | Should -Be ([version]::new($parts[0], $parts[1], $parts[2], $parts[3]))
    }
}

Describe 'Format providers' {

    It 'maps <Extension> to <Id>' -ForEach @(
        @{ Extension = '.ps1'; Id = 'PowerShell' }
        @{ Extension = 'PSM1'; Id = 'PowerShell' }
        @{ Extension = '.cdxml'; Id = 'PowerShell' }
        @{ Extension = '.vbs'; Id = 'WindowsScriptHost' }
        @{ Extension = '.wsf'; Id = 'WindowsScriptHost' }
        @{ Extension = '.exe'; Id = 'PortableExecutable' }
        @{ Extension = '.sys'; Id = 'PortableExecutable' }
        @{ Extension = '.msi'; Id = 'WindowsInstaller' }
        @{ Extension = '.cab'; Id = 'Cabinet' }
        @{ Extension = '.cat'; Id = 'Catalog' }
        @{ Extension = '.xlsm'; Id = 'OfficeVba' }
        @{ Extension = '.ppt'; Id = 'OfficeVba' }
        @{ Extension = '.vsdm'; Id = 'OfficeVba' }
        @{ Extension = '.msixbundle'; Id = 'AppPackage' }
    ) {
        (Get-FormatProvider -Extension $Extension).Id | Should -Be $Id
    }

    It 'returns nothing for an unsupported extension' {
        Get-FormatProvider -Extension '.txt' | Should -BeNullOrEmpty
    }

    It 'assigns each extension to exactly one provider' {
        $all = @(Get-SupportedExtension)
        @($all | Select-Object -Unique).Count | Should -Be $all.Count
    }

    It 'allows appended signatures only where signtool supports them' {
        @(Get-FormatProvider | Where-Object SupportsAppend | ForEach-Object Id) | Sort-Object | Should -Be @('Cabinet', 'PortableExecutable')
    }

    It 'limits app packages to the SignTool engine' {
        (Get-FormatProvider -Id AppPackage).Engines | Should -Be @('SignTool')
    }
}

Describe 'SIP lookup' {

    BeforeAll {
        $script:sipRoot = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'sip')).FullName
        [System.IO.File]::WriteAllText((Join-Path $sipRoot 'a.ps1'), 'Write-Output 1')
        [System.IO.File]::WriteAllText((Join-Path $sipRoot 'a.vbs'), 'WScript.Echo 1')
        [System.IO.File]::WriteAllText((Join-Path $sipRoot 'a.txt'), 'text')
        [System.IO.File]::WriteAllText((Join-Path $sipRoot 'fake.exe'), 'not a PE')
        New-TestPortableExecutable -Path (Join-Path $sipRoot 'real.dll')
    }

    It 'resolves <Name> as supported=<Supported>' -ForEach @(
        @{ Name = 'a.ps1'; Supported = $true }
        @{ Name = 'a.vbs'; Supported = $true }
        @{ Name = 'real.dll'; Supported = $true }
        @{ Name = 'a.txt'; Supported = $false }
        @{ Name = 'fake.exe'; Supported = $false }
    ) {
        $subject = Get-SipSubject -LiteralPath (Join-Path $script:sipRoot $Name)
        $subject.Supported | Should -Be $Supported
        Test-FileUnlocked -Path (Join-Path $script:sipRoot $Name) | Should -BeTrue
    }

    It 'names the PowerShell SIP' {
        (Get-SipSubject -LiteralPath (Join-Path $script:sipRoot 'a.ps1')).Name | Should -Be 'PowerShell'
    }
}

Describe 'Folder scan' {

    BeforeAll {
        $script:scanRoot = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'scan')).FullName
        $brackets = [System.IO.Directory]::CreateDirectory((Join-Path $scanRoot 'sub [x]')).FullName
        [System.IO.File]::WriteAllText((Join-Path $scanRoot 'script.ps1'), 'Write-Output 1')
        [System.IO.File]::WriteAllText((Join-Path $brackets "caf$([char]0xE9).psm1"), 'function f {}')
        [System.IO.File]::WriteAllText((Join-Path $scanRoot '~$Owner.xlsm'), 'owner')
        [System.IO.File]::WriteAllText((Join-Path $scanRoot 'notes.txt'), 'x')
        [System.IO.File]::WriteAllBytes((Join-Path $scanRoot 'empty.ps1'), [byte[]]@())
        [System.IO.File]::WriteAllText((Join-Path $scanRoot 'readonly.ps1'), 'Write-Output 1')
        (Get-Item -LiteralPath (Join-Path $scanRoot 'readonly.ps1')).IsReadOnly = $true
        [System.IO.File]::WriteAllText((Join-Path $scanRoot 'fake.exe'), 'not a PE')
        New-TestZip -Path (Join-Path $scanRoot 'WithMacros.xlsm') -Entries @{ '[Content_Types].xml' = '<Types/>'; 'xl/vbaProject.bin' = 'x' }
        New-TestZip -Path (Join-Path $scanRoot 'NoMacros.xlsm') -Entries @{ '[Content_Types].xml' = '<Types/>'; 'xl/workbook.xml' = '<x/>' }
        New-TestZip -Path (Join-Path $scanRoot 'Word.docm') -Entries @{ 'word/vbaProject.bin' = 'x' }
        [System.IO.File]::WriteAllText((Join-Path $scanRoot 'Corrupt.xlsm'), 'not a zip archive')
        $legacy = [byte[]]::new(4096)
        $marker = [System.Text.Encoding]::Unicode.GetBytes('_VBA_PROJECT')
        [Array]::Copy($marker, 0, $legacy, 2047, $marker.Length)
        [System.IO.File]::WriteAllBytes((Join-Path $scanRoot 'Legacy.xls'), $legacy)
        [System.IO.File]::WriteAllBytes((Join-Path $scanRoot 'LegacyNoMacros.doc'), [byte[]]::new(4096))
        [System.IO.File]::WriteAllBytes((Join-Path $scanRoot 'Slides.ppt'), [byte[]]::new(4096))

        $unreadable = 0
        $script:found = @(Find-SignableFile -Path @($scanRoot, (Join-Path $scanRoot 'notes.txt'), (Join-Path $scanRoot 'missing.ps1')) -UnreadableCount ([ref]$unreadable))
        $script:unreadable = $unreadable
        $script:infos = @{}
        foreach ($file in $script:found) {
            $script:infos[[System.IO.Path]::GetFileName($file)] = Get-SignableFileInfo -LiteralPath $file
        }
    }

    AfterAll {
        $readonly = Join-Path $script:scanRoot 'readonly.ps1'
        if ([System.IO.File]::Exists($readonly)) {
            (Get-Item -LiteralPath $readonly).IsReadOnly = $false
        }
    }

    It 'searches recursively, keeps explicitly named files, and counts missing paths' {
        $names = @($script:found | ForEach-Object { [System.IO.Path]::GetFileName($_) })
        $names | Should -Contain "caf$([char]0xE9).psm1"
        $names | Should -Contain 'notes.txt'
        $names | Should -Not -Contain '~$Owner.xlsm'
        $script:unreadable | Should -Be 1
    }

    It 'lists a folder''s unsupported files only when named explicitly' {
        @($script:found | Where-Object { $_ -like '*notes.txt' }).Count | Should -Be 1
    }

    It 'classifies <Name> as <Status>' -ForEach @(
        @{ Name = 'script.ps1'; Status = 'Ready'; Detail = 'Not signed.' }
        @{ Name = 'notes.txt'; Status = 'Skipped'; Detail = 'Not a signable file type.' }
        @{ Name = 'empty.ps1'; Status = 'Skipped'; Detail = 'The file is empty.' }
        @{ Name = 'readonly.ps1'; Status = 'Failed'; Detail = 'The file is read-only.*' }
        @{ Name = 'fake.exe'; Status = 'Failed'; Detail = 'The file is not a valid Windows executable or library.' }
        @{ Name = 'NoMacros.xlsm'; Status = 'Skipped'; Detail = 'No VBA project.' }
        @{ Name = 'Corrupt.xlsm'; Status = 'Skipped'; Detail = 'Could not read the file*' }
        @{ Name = 'LegacyNoMacros.doc'; Status = 'Skipped'; Detail = 'No VBA project.' }
    ) {
        $script:infos[$Name].Status | Should -Be $Status
        $script:infos[$Name].Detail | Should -BeLike $Detail
    }

    It 'detects VBA projects in Open XML and legacy files' {
        Test-OfficeVbaProject -LiteralPath (Join-Path $script:scanRoot 'WithMacros.xlsm') | Should -BeTrue
        Test-OfficeVbaProject -LiteralPath (Join-Path $script:scanRoot 'Word.docm') | Should -BeTrue
        Test-OfficeVbaProject -LiteralPath (Join-Path $script:scanRoot 'Legacy.xls') | Should -BeTrue
        Test-OfficeVbaProject -LiteralPath (Join-Path $script:scanRoot 'LegacyNoMacros.doc') | Should -BeFalse
    }

    It 'finds a marker that straddles the 1 MB read buffer' {
        $big = [byte[]]::new((1 -shl 20) + 64)
        $marker = [System.Text.Encoding]::Unicode.GetBytes('_VBA_PROJECT')
        [Array]::Copy($marker, 0, $big, (1 -shl 20) - 5, $marker.Length)
        $path = Join-Path $TestDrive 'Straddle.xls'
        [System.IO.File]::WriteAllBytes($path, $big)
        Test-OfficeVbaProject -LiteralPath $path | Should -BeTrue
    }

    It 'leaves PowerPoint binary files undecided' {
        Test-OfficeVbaProject -LiteralPath (Join-Path $script:scanRoot 'Slides.ppt') | Should -BeNullOrEmpty
    }

    It 'reports the Office SIP by name when Office files are unsupported' -Skip:($script:openXmlSipRegistered) {
        $script:infos['WithMacros.xlsm'].Status | Should -Be 'Failed'
        $script:infos['WithMacros.xlsm'].Detail | Should -BeLike '*msosipx.dll*'
    }

    It 'marks a macro workbook ready when the Office SIP is registered' -Skip:(-not $script:openXmlSipRegistered) {
        $script:infos['WithMacros.xlsm'].Status | Should -Be 'Ready'
    }
}

Describe 'App package identity' {

    BeforeAll {
        $manifest = '<?xml version="1.0" encoding="utf-8"?><Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Fixture" Publisher="CN=Contoso, O=Contoso Ltd" Version="1.2.3.4"/></Package>'
        $bundle = '<?xml version="1.0" encoding="utf-8"?><Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle"><Identity Name="FixtureBundle" Publisher="CN=Contoso" Version="2.0.0.0"/></Bundle>'
        $script:package = Join-Path $TestDrive 'app.msix'
        $script:bundlePath = Join-Path $TestDrive 'app.msixbundle'
        $script:doctype = Join-Path $TestDrive 'doctype.msix'
        New-TestZip -Path $script:package -Entries @{ 'AppxManifest.xml' = $manifest; 'AppxSignature.p7x' = 'x' }
        New-TestZip -Path $script:bundlePath -Entries @{ 'AppxMetadata/AppxBundleManifest.xml' = $bundle }
        New-TestZip -Path $script:doctype -Entries @{ 'AppxManifest.xml' = '<?xml version="1.0"?><!DOCTYPE Package [<!ENTITY x "y">]><Package><Identity Publisher="&x;"/></Package>' }
    }

    It 'reads a package manifest' {
        $identity = Get-AppPackageIdentity -LiteralPath $script:package
        $identity.Publisher | Should -Be 'CN=Contoso, O=Contoso Ltd'
        $identity.Version | Should -Be '1.2.3.4'
        $identity.IsBundle | Should -BeFalse
        $identity.Signed | Should -BeTrue
    }

    It 'reads a bundle manifest' {
        $identity = Get-AppPackageIdentity -LiteralPath $script:bundlePath
        $identity.Name | Should -Be 'FixtureBundle'
        $identity.IsBundle | Should -BeTrue
        $identity.Signed | Should -BeFalse
    }

    It 'refuses a manifest with a DTD' {
        { Get-AppPackageIdentity -LiteralPath $script:doctype } | Should -Throw
    }

    It 'compares publishers as distinguished names' {
        Test-CertificateMatchesPublisher -Publisher 'CN=Contoso, O=Contoso Ltd' -Subject 'CN=Contoso, O=Contoso Ltd' | Should -BeTrue
        Test-CertificateMatchesPublisher -Publisher 'CN=Contoso,O=Contoso Ltd' -Subject 'CN=Contoso, O=Contoso Ltd' | Should -BeTrue
        Test-CertificateMatchesPublisher -Publisher 'CN=Contoso' -Subject 'CN=Fabrikam' | Should -BeFalse
    }
}

Describe 'Certificates' {

    It 'accepts only certificates with the Code Signing EKU' {
        $withEku = New-TestCertificate -CodeSigning $true
        $withoutEku = New-TestCertificate -CodeSigning $false
        try {
            Test-CodeSigningUsage -Certificate $withEku | Should -BeTrue
            Test-CodeSigningUsage -Certificate $withoutEku | Should -BeFalse
        }
        finally {
            $withEku.Dispose()
            $withoutEku.Dispose()
        }
    }

    It 'labels a certificate with simple names, ISO expiry and store location' {
        $certificate = New-TestCertificate
        try {
            $label = Get-CertificateLabel -Certificate $certificate
            $label.IssuedTo | Should -Be 'Signing Suite Test'
            $label.Expires | Should -Match '^\d{4}-\d{2}-\d{2}$'
            $label.StoreLocation | Should -Be 'CurrentUser'
            $label.Thumbprint | Should -Be $certificate.Thumbprint
        }
        finally {
            $certificate.Dispose()
        }
    }

    It 'offers only currently valid code-signing certificates that have a private key' {
        $now = Get-Date
        foreach ($certificate in @(Get-SigningCertificate -StoreLocation CurrentUser, LocalMachine)) {
            $certificate.HasPrivateKey | Should -BeTrue
            $certificate.NotAfter | Should -BeGreaterThan $now
            Test-CodeSigningUsage -Certificate $certificate | Should -BeTrue
        }
    }

    It 'names the key storage provider without opening the key' {
        $pfx = Join-Path $TestDrive 'provider.pfx'
        New-TestPfx -Path $pfx
        $certificate = Import-TestSigningCertificate -Path $pfx
        try {
            Get-CertificateKeyProvider -Certificate $certificate | Should -Not -BeNullOrEmpty
        }
        finally {
            Remove-TestKey -Certificate $certificate
        }
    }

    It 'rejects a PFX without the Code Signing EKU and leaves the personal store unchanged' {
        $before = @(Get-ChildItem -Path Cert:\CurrentUser\My).Count
        $pfx = Join-Path $TestDrive 'no-eku.pfx'
        New-TestPfx -Path $pfx -CodeSigning $false
        { Import-PfxToUserStore -Path $pfx -Password (ConvertTo-TestSecureString -Value 'test-protection') } |
            Should -Throw -ExpectedMessage '*not valid for code signing*'
        @(Get-ChildItem -Path Cert:\CurrentUser\My).Count | Should -Be $before
    }

    It 'rejects a wrong PFX password and leaves the personal store unchanged' {
        $before = @(Get-ChildItem -Path Cert:\CurrentUser\My).Count
        $pfx = Join-Path $TestDrive 'code-signing.pfx'
        New-TestPfx -Path $pfx
        { Import-PfxToUserStore -Path $pfx -Password (ConvertTo-TestSecureString -Value 'wrong') } | Should -Throw
        @(Get-ChildItem -Path Cert:\CurrentUser\My).Count | Should -Be $before
    }
}

Describe 'SignTool arguments' {

    It 'quotes <Value> so CommandLineToArgvW returns it unchanged' -ForEach @(
        @{ Value = 'plain' }
        @{ Value = 'C:\Program Files\x y\file.ps1' }
        @{ Value = 'C:\trailing slash\' }
        @{ Value = 'say "hi"' }
        @{ Value = 'back\\"quote' }
        @{ Value = '' }
    ) {
        if (-not ('SigningSuiteTests.Argv' -as [type])) {
            Add-Type -Namespace SigningSuiteTests -Name Argv -MemberDefinition @'
[DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern IntPtr CommandLineToArgvW(string lpCmdLine, out int pNumArgs);
[DllImport("kernel32.dll")]
static extern IntPtr LocalFree(IntPtr hMem);
public static string[] Split(string commandLine)
{
    int count;
    IntPtr pointer = CommandLineToArgvW(commandLine, out count);
    try
    {
        string[] result = new string[count];
        for (int i = 0; i < count; i++)
        {
            result[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(pointer, i * IntPtr.Size));
        }
        return result;
    }
    finally
    {
        LocalFree(pointer);
    }
}
'@
        }
        $quoted = ConvertTo-CommandLineArgument -Value $Value
        $parsed = [SigningSuiteTests.Argv]::Split("program.exe $quoted")
        $parsed.Count | Should -Be 2
        $parsed[1] | Should -BeExactly $Value
    }

    It 'builds a store thumbprint pass with an RFC 3161 timestamp' {
        $arguments = New-SignToolSignArgument -LiteralPath 'C:\x\a.exe' -Thumbprint 'ab cd' -TimestampMode Rfc3161 -TimestampServer 'http://ts' -DigestAlgorithm SHA384
        ($arguments -join ' ') | Should -Be 'sign /fd SHA384 /sha1 ABCD /s My /tr http://ts /td SHA384 -- C:\x\a.exe'
    }

    It 'adds /sm for the machine store and /t for Authenticode timestamps' {
        $arguments = New-SignToolSignArgument -LiteralPath 'a.exe' -Thumbprint 'AB' -StoreLocation LocalMachine -TimestampMode Authenticode -TimestampServer 'http://ts'
        $arguments | Should -Contain '/sm'
        ($arguments -join ' ') | Should -BeLike '*/t http://ts*'
        $arguments | Should -Not -Contain '/td'
    }

    It 'builds a digest signing pass without a local certificate' {
        $arguments = New-SignToolSignArgument -LiteralPath 'a.msix' -DlibPath 'C:\d\Azure.CodeSigning.Dlib.dll' -MetadataPath 'C:\d\metadata.json'
        ($arguments -join ' ') | Should -Be 'sign /fd SHA256 /dlib C:\d\Azure.CodeSigning.Dlib.dll /dmdf C:\d\metadata.json -- a.msix'
    }

    It 'places the file after -- and appends options before it' {
        $arguments = New-SignToolSignArgument -LiteralPath '-dash.exe' -CertificateFile 'c.cer' -DlibPath 'd.dll' -AppendSignature -Description 'Tool' -DescriptionUrl 'https://x' -PageHashes On
        $arguments[-2] | Should -Be '--'
        $arguments[-1] | Should -Be '-dash.exe'
        foreach ($expected in '/as', '/ph', '/f', '/d', '/du') {
            $arguments | Should -Contain $expected
        }
    }

    It 'refuses a pass with no signing identity or a timestamp without a server' {
        { New-SignToolSignArgument -LiteralPath 'a.exe' } | Should -Throw
        { New-SignToolSignArgument -LiteralPath 'a.exe' -Thumbprint 'AB' -TimestampMode Rfc3161 } | Should -Throw
    }

    It 'finds signtool.exe from the Windows SDK when installed' -Skip:(-not $script:signToolAvailable) {
        $script:signTool.Path | Should -Match 'signtool\.exe$'
        $script:signTool.Source | Should -BeIn 'WindowsSdk', 'Path'
    }

    It 'prefers a configured signtool path that carries a valid signature' -Skip:(-not $script:signToolAvailable) {
        $copy = Join-Path $TestDrive 'configured\signtool.exe'
        [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $copy))
        [System.IO.File]::Copy($script:signTool.Path, $copy, $true)
        (Find-SignTool -ConfiguredPath $copy).Source | Should -Be 'Configured'
    }

    It 'ignores a configured signtool path without a valid signature' {
        $fake = Join-Path $TestDrive 'unsigned\signtool.exe'
        [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $fake))
        New-TestPortableExecutable -Path $fake
        $found = Find-SignTool -ConfiguredPath $fake -WarningAction SilentlyContinue
        if ($found) {
            $found.Source | Should -Not -Be 'Configured'
        }
    }

    It 'explains a signing service HTTP <Code> failure' -ForEach @(
        @{ Code = '401'; Expected = 'The signing service rejected the sign-in (401)*' }
        @{ Code = '403'; Expected = '*refused the request (403)*Certificate Profile Signer role*SignerSign() failed*' }
        @{ Code = '404'; Expected = '*did not find the account or certificate profile (404)*' }
    ) {
        $output = "Submitting digest for signing...`r`nUnhandled managed exception`r`nAzure.RequestFailedException: Service request failed.`r`nStatus: $Code (Forbidden)`r`n`r`nError information: `"Error: SignerSign() failed.`" (-2147467259/0x80004005)`r`nSignTool Error: An unexpected internal error has occurred.`r`n"
        $run = [pscustomobject]@{ ExitCode = 1; TimedOut = $false; Output = $output; Error = ''; Errors = @('An unexpected internal error has occurred.'); Warnings = @() }
        $message = & (Get-Module SigningSuite) { param($r) Get-SignToolFailureMessage -Run $r } $run
        $message | Should -BeLike $Expected
    }

    It 'joins signtool messages wrapped onto indented lines' {
        $text = "Done Adding Additional Store`r`nSignTool Error: A certificate chain processed, but terminated in a root`r`n`tcertificate which is not trusted by the trust provider.`r`n`r`nSignTool Warning: Signing succeeded, but an error occurred.`r`nSignTool Error: An error occurred while attempting to sign: C:\x.ps1`r`n"
        $messages = ConvertFrom-SignToolOutput -Text $text
        $messages.Errors | Should -Be @('A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider.', 'An error occurred while attempting to sign: C:\x.ps1')
        $messages.Warnings | Should -Be @('Signing succeeded, but an error occurred.')
    }
}

Describe 'CSV export values' {

    It 'neutralizes <Value>' -ForEach @(
        @{ Value = '=cmd|calc!A1.exe'; Expected = "'=cmd|calc!A1.exe" }
        @{ Value = '+1.ps1'; Expected = "'+1.ps1" }
        @{ Value = '-dash.ps1'; Expected = "'-dash.ps1" }
        @{ Value = '@x.vbs'; Expected = "'@x.vbs" }
        @{ Value = 'plain.ps1'; Expected = 'plain.ps1' }
        @{ Value = ''; Expected = '' }
    ) {
        ConvertTo-SafeCsvField -Value $Value | Should -BeExactly $Expected
    }
}

Describe 'External processes' {

    It 'returns output and exit code without deadlocking on large output' {
        $cmd = Join-Path $env:windir 'System32\cmd.exe'
        $run = Invoke-ExternalProcess -FilePath $cmd -ArgumentList @('/d', '/c', '(for /L %i in (1,1,6000) do @echo line %i) & exit /b 3') -TimeoutSeconds 60
        $run.TimedOut | Should -BeFalse
        $run.ExitCode | Should -Be 3
        ($run.Output -split "`n").Count | Should -BeGreaterThan 5000
    }

    It 'returns when a child process keeps the output pipes open' {
        $marker = 'SigningSuiteOrphan' + [guid]::NewGuid().ToString('N')
        $cmd = Join-Path $env:windir 'System32\cmd.exe'
        $powershell = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
        # cmd.exe does not read CommandLineToArgvW escapes, so the start /b line lives in a batch file; start /b children inherit the pipes.
        $batch = Join-Path $TestDrive 'orphan.cmd'
        [System.IO.File]::WriteAllText($batch, "@echo off`r`nstart /b `"`" `"$powershell`" -NoProfile -Command `"Start-Sleep -Seconds 60; '$marker'`"`r`necho started`r`n")
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $run = Invoke-ExternalProcess -FilePath $cmd -ArgumentList @('/d', '/c', $batch) -TimeoutSeconds 30
            $watch.Stop()
            $watch.Elapsed.TotalSeconds | Should -BeLessThan 25
            $run.TimedOut | Should -BeFalse
            $run.StreamsClosed | Should -BeFalse
            $run.Output | Should -BeLike 'started*'
        }
        finally {
            Get-CimInstance -ClassName Win32_Process -Filter "Name = 'powershell.exe'" | Where-Object { $_.CommandLine -like "*$marker*" } |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'kills a process that exceeds the timeout' {
        $powershell = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $run = Invoke-ExternalProcess -FilePath $powershell -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 30') -TimeoutSeconds 2
        $watch.Stop()
        $run.TimedOut | Should -BeTrue
        $run.ExitCode | Should -Be -1
        $watch.Elapsed.TotalSeconds | Should -BeLessThan 20
    }
}

Describe 'Engine selection' {

    BeforeAll {
        $script:powerShellProvider = Get-FormatProvider -Id PowerShell
        $script:packageProvider = Get-FormatProvider -Id AppPackage
    }

    It 'uses SignTool automatically when it is available' {
        (Resolve-SigningEngine -Provider $script:powerShellProvider -SignToolAvailable $true).Engine | Should -Be 'SignTool'
    }

    It 'falls back to PowerShell automatically for store certificates' {
        (Resolve-SigningEngine -Provider $script:powerShellProvider -SignToolAvailable $false).Engine | Should -Be 'PowerShell'
    }

    It 'explains why nothing can sign an app package without signtool' {
        $choice = Resolve-SigningEngine -Provider $script:packageProvider -SignToolAvailable $false
        $choice.Engine | Should -BeNullOrEmpty
        $choice.Reason | Should -BeLike '*App package files*'
    }

    It 'refuses the PowerShell engine for <Case>' -ForEach @(
        @{ Case = 'Artifact Signing'; Source = 'ArtifactSigning'; Timestamp = 'None' }
        @{ Case = 'digest signing libraries'; Source = 'Dlib'; Timestamp = 'None' }
        @{ Case = 'RFC 3161 timestamps'; Source = 'Store'; Timestamp = 'Rfc3161' }
    ) {
        $choice = Resolve-SigningEngine -Provider $script:powerShellProvider -Requested PowerShell -SignToolAvailable $true -Source $Source -TimestampMode $Timestamp
        $choice.Engine | Should -BeNullOrEmpty
        $choice.Reason | Should -BeLike "*$Case*"
    }

    It 'keeps an explicit PowerShell choice for an Authenticode timestamp' {
        (Resolve-SigningEngine -Provider $script:powerShellProvider -Requested PowerShell -SignToolAvailable $true -TimestampMode Authenticode).Engine | Should -Be 'PowerShell'
    }

    It 'skips a valid signature only when it has the timestamp the run asks for: <Case>' -ForEach @(
        @{ Case = 'valid, no timestamp asked'; State = 'Valid'; Timestamped = $false; Mode = 'None'; Expected = $true }
        @{ Case = 'valid and timestamped'; State = 'Valid'; Timestamped = $true; Mode = 'Rfc3161'; Expected = $true }
        @{ Case = 'valid without the asked timestamp'; State = 'Valid'; Timestamped = $false; Mode = 'Authenticode'; Expected = $false }
        @{ Case = 'untrusted'; State = 'Untrusted'; Timestamped = $true; Mode = 'None'; Expected = $false }
        @{ Case = 'not signed'; State = 'NotSigned'; Timestamped = $false; Mode = 'None'; Expected = $false }
    ) {
        Test-SkipValidSignature -SignatureState $State -Timestamped $Timestamped -TimestampMode $Mode | Should -Be $Expected
    }

    It 'shortens signature states for the file list' {
        ConvertTo-SignatureText -State 'Valid' -Signer 'Contoso' | Should -Be 'Valid: Contoso'
        ConvertTo-SignatureText -State 'NotSigned' -Signer $null | Should -Be 'Not signed'
        ConvertTo-SignatureText -State '' -Signer $null | Should -Be ''
    }
}

Describe 'Settings and metadata files' {

    It 'round-trips settings and ignores unknown keys' {
        $path = Join-Path $TestDrive 'settings\settings.json'
        $settings = Get-SigningSuiteSettings -Path $path
        $settings.TimestampMode | Should -Be 'Rfc3161'
        $settings.DualSign = $true
        $settings.TimestampServer = 'http://example.test'
        Save-SigningSuiteSettings -Settings $settings -Path $path
        Save-SigningSuiteSettings -Settings $settings -Path $path
        $loaded = Get-SigningSuiteSettings -Path $path
        $loaded.DualSign | Should -BeTrue
        $loaded.TimestampServer | Should -Be 'http://example.test'
        [System.IO.File]::Exists("$path.tmp") | Should -BeFalse
    }

    It 'falls back to defaults for a damaged settings file' {
        $path = Join-Path $TestDrive 'damaged.json'
        [System.IO.File]::WriteAllText($path, '{ not json')
        (Get-SigningSuiteSettings -Path $path).Engine | Should -Be 'Auto'
    }

    It 'writes Artifact Signing metadata the dlib reads' {
        $path = Join-Path $TestDrive 'artifact\metadata.json'
        [void](New-ArtifactSigningMetadata -Path $path -Endpoint 'https://eus.codesigning.azure.net' -AccountName 'account' -CertificateProfileName 'profile' -ExcludeCredentials 'ManagedIdentityCredential')
        $json = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
        $json.Endpoint | Should -Be 'https://eus.codesigning.azure.net/'
        $json.CodeSigningAccountName | Should -Be 'account'
        $json.CertificateProfileName | Should -Be 'profile'
        @($json.ExcludeCredentials) | Should -Be @('ManagedIdentityCredential')
        [System.IO.File]::ReadAllBytes($path)[0] | Should -Not -Be 0xEF
    }

    It 'rejects a metadata endpoint that is not HTTPS' {
        { New-ArtifactSigningMetadata -Path (Join-Path $TestDrive 'bad.json') -Endpoint 'http://x' -AccountName 'a' -CertificateProfileName 'p' } | Should -Throw
    }
}

Describe 'Signing with the PowerShell engine' {

    BeforeAll {
        $script:psRoot = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'ps-engine [x]')).FullName
        $pfx = Join-Path $TestDrive 'ps-engine.pfx'
        New-TestPfx -Path $pfx
        $script:certificate = Import-TestSigningCertificate -Path $pfx
        [System.IO.File]::WriteAllText((Join-Path $psRoot 'script.ps1'), "Write-Output 'signed'`r`n")
        [System.IO.File]::WriteAllText((Join-Path $psRoot '-dash.ps1'), "Write-Output 'dash'`r`n")
        [System.IO.File]::WriteAllText((Join-Path $psRoot 'legacy.vbs'), "WScript.Echo 1`r`n")
        New-TestPortableExecutable -Path (Join-Path $psRoot 'library.dll')
        [System.IO.File]::WriteAllText((Join-Path $psRoot 'fake.exe'), 'not a PE')
        [System.IO.File]::WriteAllText((Join-Path $psRoot 'tamper.ps1'), "Write-Output 'original'`r`n")
        [System.IO.File]::WriteAllText((Join-Path $psRoot 'readonly.ps1'), "Write-Output 1`r`n")
        (Get-Item -LiteralPath (Join-Path $psRoot 'readonly.ps1')).IsReadOnly = $true
        New-TestZip -Path (Join-Path $psRoot 'app.msix') -Entries @{ 'AppxManifest.xml' = '<Package><Identity Publisher="CN=Signing Suite Test"/></Package>' }
        Copy-Item -LiteralPath (Join-Path $env:windir 'System32\whoami.exe') -Destination (Join-Path $psRoot 'catalogued.exe')

        $script:results = @{}
        foreach ($name in 'script.ps1', '-dash.ps1', 'legacy.vbs', 'library.dll', 'fake.exe', 'tamper.ps1', 'readonly.ps1', 'app.msix', 'catalogued.exe') {
            $script:results[$name] = Invoke-FileSigning -LiteralPath (Join-Path $psRoot $name) -Engine PowerShell -Certificate $script:certificate
        }
    }

    AfterAll {
        $readonly = [System.IO.FileInfo]::new((Join-Path $script:psRoot 'readonly.ps1'))
        if ($readonly.Exists) {
            $readonly.IsReadOnly = $false
        }
        Remove-TestKey -Certificate $script:certificate
    }

    It 'signs <Name> with the selected certificate' -ForEach @(
        @{ Name = 'script.ps1' }
        @{ Name = '-dash.ps1' }
        @{ Name = 'legacy.vbs' }
        @{ Name = 'library.dll' }
        @{ Name = 'catalogued.exe' }
    ) {
        $script:results[$Name].Status | Should -Be 'Signed'
        $script:results[$Name].SignerThumbprint | Should -Be $script:certificate.Thumbprint
        (Get-FileSignatureState -LiteralPath (Join-Path $script:psRoot $Name)).Thumbprint | Should -Be $script:certificate.Thumbprint
        Test-FileUnlocked -Path (Join-Path $script:psRoot $Name) | Should -BeTrue
    }

    It 'reports a self-signed signature as untrusted, not invalid' {
        $script:results['script.ps1'].SignatureState | Should -Be 'Untrusted'
        $script:results['script.ps1'].Detail | Should -BeLike 'Signed; not trusted on this PC:*'
    }

    It 'fails <Name> without touching it: <Detail>' -ForEach @(
        @{ Name = 'fake.exe'; Detail = 'The file is not a valid Windows executable or library.' }
        @{ Name = 'readonly.ps1'; Detail = 'The file is read-only.' }
        @{ Name = 'app.msix'; Detail = 'App package files need the SignTool engine.' }
    ) {
        $script:results[$Name].Status | Should -Be 'Failed'
        $script:results[$Name].Detail | Should -Be $Detail
    }

    It 'leaves a file with no signing handler free for other processes' {
        Test-FileUnlocked -Path (Join-Path $script:psRoot 'fake.exe') | Should -BeTrue
    }

    It 'detects content changed after signing as an invalid signature' {
        $path = Join-Path $script:psRoot 'tamper.ps1'
        $text = [System.IO.File]::ReadAllText($path)
        [System.IO.File]::WriteAllText($path, $text.Replace("'original'", "'modified'"))
        (Get-FileSignatureState -LiteralPath $path).State | Should -Be 'Invalid'
    }

    It 'refuses an RFC 3161 timestamp instead of downgrading it' {
        $path = Join-Path $script:psRoot 'rfc.ps1'
        [System.IO.File]::WriteAllText($path, "Write-Output 1`r`n")
        $result = Invoke-FileSigning -LiteralPath $path -Engine PowerShell -Certificate $script:certificate -TimestampMode Rfc3161 -TimestampServer 'http://timestamp.digicert.com'
        $result.Status | Should -Be 'Failed'
        $result.Detail | Should -BeLike 'RFC 3161 timestamps need the SignTool engine*'
        (Get-FileSignatureState -LiteralPath $path).State | Should -Be 'NotSigned'
    }

    It 'fails a file signed without the timestamp that was asked for' {
        $path = Join-Path $script:psRoot 'no-timestamp.ps1'
        [System.IO.File]::WriteAllText($path, "Write-Output 1`r`n")
        $result = Invoke-FileSigning -LiteralPath $path -Engine PowerShell -Certificate $script:certificate -TimestampMode Authenticode -TimestampServer 'http://127.0.0.1:9/'
        $result.Status | Should -Be 'Failed'
        $result.Detail | Should -BeLike 'The file was signed without the requested timestamp*'
    }

    It 'reports a missing file and a timestamp request without a server' {
        (Invoke-FileSigning -LiteralPath (Join-Path $script:psRoot 'missing.ps1') -Engine PowerShell -Certificate $script:certificate).Detail | Should -Be 'The file no longer exists.'
        (Invoke-FileSigning -LiteralPath (Join-Path $script:psRoot 'script.ps1') -Engine PowerShell -Certificate $script:certificate -TimestampMode Authenticode).Detail | Should -BeLike 'A timestamp was requested*'
    }

    It 'verifies without signtool' {
        $verification = Test-FileSignature -LiteralPath (Join-Path $script:psRoot 'script.ps1')
        $verification.State | Should -Be 'Untrusted'
        $verification.Detail | Should -BeLike '*Not timestamped.'
    }
}

Describe 'Signing with the SignTool engine and a digest signing library' {

    BeforeAll {
        $script:toolRoot = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'signtool engine')).FullName
        $script:dlib = Get-TestDigestSignLibrary -Architecture 'x64'
        $script:identity = New-TestDlibIdentity -Folder $script:toolRoot
        $script:failMetadata = Join-Path $toolRoot 'fail.txt'
        [System.IO.File]::WriteAllText($script:failMetadata, 'fail=80090016')
        $script:common = @{
            Engine          = 'SignTool'
            SignToolPath    = if ($script:signTool) { $script:signTool.Path } else { '' }
            DlibPath        = $script:dlib
            MetadataPath    = $script:identity.MetadataPath
            CertificateFile = $script:identity.CertificateFile
        }
        [System.IO.File]::WriteAllText((Join-Path $toolRoot 'script.ps1'), "Write-Output 1`r`n")
        New-TestPortableExecutable -Path (Join-Path $toolRoot 'dual.dll')
        New-TestPortableExecutable -Path (Join-Path $toolRoot 'failing.dll')
        [System.IO.File]::WriteAllText((Join-Path $toolRoot 'dual.ps1'), "Write-Output 1`r`n")
    }

    It 'signs a script through the digest signing library' -Skip:(-not $script:dlibAvailable) {
        $result = Invoke-FileSigning -LiteralPath (Join-Path $script:toolRoot 'script.ps1') @script:common
        $result.Status | Should -Be 'Signed'
        $result.SignerThumbprint | Should -Be $script:identity.Thumbprint
    }

    It 'dual signs an executable with two timestamped signatures' -Skip:(-not $script:dlibAvailable -or $env:SIGNINGSUITE_OFFLINE) {
        $path = Join-Path $script:toolRoot 'dual.dll'
        $result = Invoke-FileSigning -LiteralPath $path @script:common -DualSign -TimestampMode Rfc3161 -TimestampServer 'http://timestamp.digicert.com'
        $result.Status | Should -Be 'Signed'
        $result.Passes | Should -Be 2
        $verification = Test-FileSignature -LiteralPath $path -SignToolPath $script:common.SignToolPath
        $verification.SignatureCount | Should -Be 2
        $verification.Detail | Should -BeLike '*2 signature(s), 2 timestamped.'
    }

    It 'signs a script once when dual signing is asked for' -Skip:(-not $script:dlibAvailable) {
        $result = Invoke-FileSigning -LiteralPath (Join-Path $script:toolRoot 'dual.ps1') @script:common -DualSign
        $result.Status | Should -Be 'Signed'
        $result.Passes | Should -Be 1
        $result.Detail | Should -BeLike '*PowerShell files hold one signature; signed with SHA256 only.*'
    }

    It 'surfaces the library error when digest signing fails' -Skip:(-not $script:dlibAvailable) {
        $parameters = $script:common.Clone()
        $parameters.MetadataPath = $script:failMetadata
        $result = Invoke-FileSigning -LiteralPath (Join-Path $script:toolRoot 'failing.dll') @parameters
        $result.Status | Should -Be 'Failed'
        $result.Detail | Should -BeLike '*private key container*'
        (Get-FileSignatureState -LiteralPath (Join-Path $script:toolRoot 'failing.dll')).State | Should -Be 'NotSigned'
    }

    It 'fails clearly when signtool.exe is missing' {
        $parameters = $script:common.Clone()
        $parameters.SignToolPath = Join-Path $TestDrive 'nope\signtool.exe'
        (Invoke-FileSigning -LiteralPath (Join-Path $script:toolRoot 'script.ps1') @parameters).Detail | Should -BeLike 'signtool.exe was not found*'
    }
}

Describe 'App packages' {

    BeforeAll {
        $script:appRoot = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'packages')).FullName
        $script:dlib = Get-TestDigestSignLibrary -Architecture 'x64'
        $script:identity = New-TestDlibIdentity -Folder $script:appRoot -Subject 'CN=Signing Suite Package Test'
        $makeAppx = Join-Path (Split-Path -Parent $script:signTool.Path) 'makeappx.exe'
        $png = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==')
        foreach ($case in @(@{ Name = 'match'; Publisher = 'CN=Signing Suite Package Test' }, @{ Name = 'mismatch'; Publisher = 'CN=Someone Else' })) {
            $content = [System.IO.Directory]::CreateDirectory((Join-Path $appRoot "$($case.Name)-content")).FullName
            [System.IO.File]::WriteAllBytes((Join-Path $content 'logo.png'), $png)
            New-TestPortableExecutable -Path (Join-Path $content 'app.exe')
            $manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10" xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities" IgnorableNamespaces="uap rescap">
  <Identity Name="SigningSuite.Fixture" Publisher="$($case.Publisher)" Version="1.0.0.0" ProcessorArchitecture="x64"/>
  <Properties><DisplayName>Fixture</DisplayName><PublisherDisplayName>Fixture</PublisherDisplayName><Logo>logo.png</Logo></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.26100.0"/></Dependencies>
  <Resources><Resource Language="en-us"/></Resources>
  <Applications><Application Id="App" Executable="app.exe" EntryPoint="Windows.FullTrustApplication"><uap:VisualElements DisplayName="Fixture" Description="Fixture" BackgroundColor="transparent" Square150x150Logo="logo.png" Square44x44Logo="logo.png"/></Application></Applications>
  <Capabilities><rescap:Capability Name="runFullTrust"/></Capabilities>
</Package>
"@
            [System.IO.File]::WriteAllText((Join-Path $content 'AppxManifest.xml'), $manifest)
            & $makeAppx pack /o /d $content /p (Join-Path $appRoot "$($case.Name).msix") *> $null
        }
        $script:packageParameters = @{
            Engine          = 'SignTool'
            SignToolPath    = $script:signTool.Path
            DlibPath        = $script:dlib
            MetadataPath    = $script:identity.MetadataPath
            CertificateFile = $script:identity.CertificateFile
        }
    }

    It 'signs a package whose Publisher matches the certificate' -Skip:(-not $script:packagesAvailable) {
        $result = Invoke-FileSigning -LiteralPath (Join-Path $script:appRoot 'match.msix') @script:packageParameters
        $result.Status | Should -Be 'Signed'
        (Get-SignableFileInfo -LiteralPath (Join-Path $script:appRoot 'match.msix')).Detail | Should -BeLike '*Publisher CN=Signing Suite Package Test.*'
    }

    It 'refuses a package whose Publisher differs before calling signtool' -Skip:(-not $script:packagesAvailable) {
        $result = Invoke-FileSigning -LiteralPath (Join-Path $script:appRoot 'mismatch.msix') @script:packageParameters
        $result.Status | Should -Be 'Failed'
        $result.Detail | Should -BeLike "The package Publisher 'CN=Someone Else' does not match*"
    }
}

Describe 'Office VBA signing' {

    BeforeAll {
        $script:officeRoot = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'office')).FullName
        $pfx = Join-Path $TestDrive 'office.pfx'
        New-TestPfx -Path $pfx
        $script:officeCertificate = Import-TestSigningCertificate -Path $pfx
        if ($env:SIGNINGSUITE_OFFICE_FIXTURES -and [System.IO.Directory]::Exists($env:SIGNINGSUITE_OFFICE_FIXTURES)) {
            Copy-Item -Path (Join-Path $env:SIGNINGSUITE_OFFICE_FIXTURES '*') -Destination $officeRoot
        }
        $script:officeSip = Get-OfficeSipStatus | Where-Object { $_.Is64Bit -eq [Environment]::Is64BitProcess } | Select-Object -First 1
    }

    AfterAll {
        Remove-TestKey -Certificate $script:officeCertificate
    }

    It 'signs <Name> in three passes' -Skip:(-not $script:officeAvailable) -ForEach @(
        @{ Name = 'Macro.xlsm' }
        @{ Name = 'Macro.xls' }
        @{ Name = 'Macro.docm' }
        @{ Name = 'Macro.ppt' }
    ) {
        $path = Join-Path $script:officeRoot $Name
        $result = Invoke-FileSigning -LiteralPath $path -Engine PowerShell -Certificate $script:officeCertificate
        $result.Status | Should -Be 'Signed'
        $result.Passes | Should -Be 3
        (Get-FileSignatureState -LiteralPath $path).Thumbprint | Should -Be $script:officeCertificate.Thumbprint
        Test-FileUnlocked -Path $path | Should -BeTrue
    }

    It 'skips a workbook without a VBA project' -Skip:(-not $script:officeAvailable) {
        $result = Invoke-FileSigning -LiteralPath (Join-Path $script:officeRoot 'NoMacro.xlsm') -Engine PowerShell -Certificate $script:officeCertificate
        $result.Status | Should -Be 'Skipped'
        $result.Detail | Should -Be 'No VBA project.'
    }

    It 'clears existing VBA signatures before re-signing' -Skip:(-not $script:officeClearAvailable) {
        $path = Join-Path $script:officeRoot 'Macro.pptm'
        $first = Invoke-FileSigning -LiteralPath $path -Engine PowerShell -Certificate $script:officeCertificate
        $first.Status | Should -Be 'Signed'
        $cleared = Clear-OfficeVbaSignature -LiteralPath $path -OffClearSigPath $script:officeSip.OffClearSigPath -Confirm:$false
        $cleared.Success | Should -BeTrue
        (Get-FileSignatureState -LiteralPath $path).State | Should -Be 'NotSigned'
        $again = Invoke-FileSigning -LiteralPath $path -Engine PowerShell -Certificate $script:officeCertificate -ClearOfficeSignatures -OffClearSigPath $script:officeSip.OffClearSigPath
        $again.Status | Should -Be 'Signed'
        $again.Passes | Should -Be 3
    }
}
