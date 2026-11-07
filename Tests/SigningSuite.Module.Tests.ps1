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

    It 'accepts only Microsoft-signed signtool candidates' {
        $unsigned = Join-Path $TestDrive 'publisher\signtool.exe'
        [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $unsigned))
        New-TestPortableExecutable -Path $unsigned
        Test-SignToolPublisher -LiteralPath $unsigned | Should -BeFalse
        Test-SignToolPublisher -LiteralPath (Join-Path $TestDrive 'publisher\missing.exe') | Should -BeFalse
        Test-SignToolPublisher -LiteralPath (Join-Path $env:windir 'System32\notepad.exe') | Should -BeTrue
    }

    It 'skips a signtool.exe on PATH that Microsoft did not sign' {
        $folder = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'path-signtool')).FullName
        New-TestPortableExecutable -Path (Join-Path $folder 'signtool.exe')
        $saved = $env:PATH
        try {
            $env:PATH = "$folder;$saved"
            $found = Find-SignTool -Architecture 'arm64' -WarningAction SilentlyContinue
            if ($found) {
                $found.Path | Should -Not -Be (Join-Path $folder 'signtool.exe')
            }
        }
        finally {
            $env:PATH = $saved
        }
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

    It 'joins the timestamp server error that continues on a line with no indent' {
        $text = "SignTool Error: The specified timestamp server either could not be reached or`r`nreturned an invalid response.`r`nSignTool Error: An error occurred while attempting to sign: C:\x.dll`r`n`r`nNumber of errors: 1`r`n"
        $messages = ConvertFrom-SignToolOutput -Text $text
        $messages.Errors | Should -Be @('The specified timestamp server either could not be reached or returned an invalid response.', 'An error occurred while attempting to sign: C:\x.dll')
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

    It 'skips a valid signature only from the expected certificate: <Case>' -ForEach @(
        @{ Case = 'same certificate'; Signer = 'AA'; Expected = 'AA'; Result = $true }
        @{ Case = 'another publisher'; Signer = 'BB'; Expected = 'AA'; Result = $false }
        @{ Case = 'identity without a known certificate'; Signer = 'BB'; Expected = ''; Result = $true }
    ) {
        Test-SkipValidSignature -SignatureState 'Valid' -Timestamped $true -TimestampMode 'Rfc3161' -SignerThumbprint $Signer -ExpectedThumbprint $Expected | Should -Be $Result
    }

    It 'shortens signature states for the file list' {
        ConvertTo-SignatureText -State 'Revoked' -Signer 'Contoso' | Should -Be 'Revoked: Contoso'
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
        $result = Invoke-FileSigning -LiteralPath $path -Engine PowerShell -Certificate $script:certificate -TimestampMode Authenticode -TimestampServer 'http://127.0.0.1:9/' -TimestampRetryCount 2 -TimestampRetryDelaySeconds 0
        $result.Status | Should -Be 'Failed'
        $result.Detail | Should -BeLike 'The file was signed without the requested timestamp*after 3 attempts*'
    }

    It 'signs again when the first attempt has no timestamp' {
        $path = Join-Path $script:psRoot 'retry-timestamp.ps1'
        [System.IO.File]::WriteAllText($path, "Write-Output 1`r`n")
        $stateCalls = @{ Count = 0 }
        $thumbprint = $script:certificate.Thumbprint
        $signer = $script:certificate
        Mock -ModuleName SigningSuite Set-AuthenticodeSignature {
            [pscustomobject]@{ SignerCertificate = $signer; Status = 'Valid'; StatusMessage = '' }
        }.GetNewClosure()
        Mock -ModuleName SigningSuite Get-FileSignatureState {
            $stateCalls.Count++
            [pscustomobject]@{ State = 'Untrusted'; Message = 'self-signed'; Signer = 'CN=Test'; Thumbprint = $thumbprint; Timestamped = ($stateCalls.Count -ge 2) }
        }.GetNewClosure()
        $result = Invoke-FileSigning -LiteralPath $path -Engine PowerShell -Certificate $script:certificate -TimestampMode Authenticode -TimestampServer 'http://127.0.0.1:9/' -TimestampRetryDelaySeconds 0
        $result.Status | Should -Be 'Signed'
        $result.Detail | Should -BeLike '*Timestamped on attempt 2 of 4.*'
        Should -Invoke -ModuleName SigningSuite Get-FileSignatureState -Times 2 -Exactly
        Should -Invoke -ModuleName SigningSuite Set-AuthenticodeSignature -Times 2 -Exactly
    }

    It 'signs once when no timestamp is asked for' {
        $path = Join-Path $script:psRoot 'no-retry.ps1'
        [System.IO.File]::WriteAllText($path, "Write-Output 1`r`n")
        Mock -ModuleName SigningSuite Start-Sleep { }
        $result = Invoke-FileSigning -LiteralPath $path -Engine PowerShell -Certificate $script:certificate -TimestampMode None
        $result.Status | Should -Be 'Signed'
        Should -Invoke -ModuleName SigningSuite Start-Sleep -Times 0 -Exactly
    }

    It 'retries a signtool timestamp server error and not other signtool errors: <Case>' -ForEach @(
        @{ Case = 'timestamp server'; ErrorLine = 'SignTool Error: The specified timestamp server either could not be reached or returned an invalid response.'; Calls = 2; Status = 'Signed' }
        @{ Case = 'other error'; ErrorLine = 'SignTool Error: No certificates were found that met all the given criteria.'; Calls = 1; Status = 'Failed' }
    ) {
        $path = Join-Path $script:psRoot "signtool-retry-$($Case -replace ' ', '-').ps1"
        [System.IO.File]::WriteAllText($path, "Write-Output 1`r`n")
        $tool = Join-Path $script:psRoot 'signtool-stub.exe'
        [System.IO.File]::WriteAllText($tool, 'stub')
        $signToolCalls = @{ Count = 0 }
        $errorText = $ErrorLine
        $thumbprint = $script:certificate.Thumbprint
        Mock -ModuleName SigningSuite Invoke-SignTool {
            $signToolCalls.Count++
            if ($signToolCalls.Count -eq 1) {
                return [pscustomobject]@{ ExitCode = 1; TimedOut = $false; Output = ''; Error = $errorText; Errors = @($errorText -replace '^SignTool Error:\s*', ''); Warnings = @() }
            }
            [pscustomobject]@{ ExitCode = 0; TimedOut = $false; Output = 'Successfully signed'; Error = ''; Errors = @(); Warnings = @() }
        }.GetNewClosure()
        Mock -ModuleName SigningSuite Get-FileSignatureState {
            [pscustomobject]@{ State = 'Untrusted'; Message = 'self-signed'; Signer = 'CN=Test'; Thumbprint = $thumbprint; Timestamped = $true }
        }.GetNewClosure()
        $result = Invoke-FileSigning -LiteralPath $path -Engine SignTool -SignToolPath $tool -Certificate $script:certificate -TimestampMode Rfc3161 -TimestampServer 'http://timestamp.example.test' -TimestampRetryDelaySeconds 0
        $result.Status | Should -Be $Status
        Should -Invoke -ModuleName SigningSuite Invoke-SignTool -Times $Calls -Exactly
    }

    It 'names the attempt count when every attempt hits a signtool timestamp server error' {
        $path = Join-Path $script:psRoot 'signtool-retry-exhausted.ps1'
        [System.IO.File]::WriteAllText($path, "Write-Output 1`r`n")
        $tool = Join-Path $script:psRoot 'signtool-stub.exe'
        [System.IO.File]::WriteAllText($tool, 'stub')
        Mock -ModuleName SigningSuite Invoke-SignTool {
            $text = 'SignTool Error: The specified timestamp server either could not be reached or returned an invalid response.'
            [pscustomobject]@{ ExitCode = 1; TimedOut = $false; Output = ''; Error = $text; Errors = @($text -replace '^SignTool Error:\s*', ''); Warnings = @() }
        }
        $result = Invoke-FileSigning -LiteralPath $path -Engine SignTool -SignToolPath $tool -Certificate $script:certificate -TimestampMode Rfc3161 -TimestampServer 'http://timestamp.example.test' -TimestampRetryCount 1 -TimestampRetryDelaySeconds 0
        $result.Status | Should -Be 'Failed'
        $result.Detail | Should -BeLike '*timestamp server*Failed after 2 attempts.'
        Should -Invoke -ModuleName SigningSuite Invoke-SignTool -Times 2 -Exactly
    }

    It 'retries an Office file only when its VBA signatures can be cleared first: <Case>' -ForEach @(
        @{ Case = 'unsigned before the run'; Before = 'NotSigned'; Clear = $false; Discover = $false; Order = 'sign clear sign sign sign'; Status = 'Signed' }
        @{ Case = 'unsigned, clearing tool found by the module'; Before = 'NotSigned'; Clear = $false; Discover = $true; Order = 'sign clear sign sign sign'; Status = 'Signed' }
        @{ Case = 'signed before, clearing asked for'; Before = 'Valid'; Clear = $true; Discover = $false; Order = 'clear sign clear sign sign sign'; Status = 'Signed' }
        @{ Case = 'signed before, no clearing'; Before = 'Valid'; Clear = $false; Discover = $false; Order = 'sign'; Status = 'Failed' }
    ) {
        $workbook = Join-Path $script:psRoot "retry-$($Case -replace '[ ,]+', '-').xlsm"
        New-TestZip -Path $workbook -Entries @{ '[Content_Types].xml' = '<Types/>'; 'xl/vbaProject.bin' = 'x' }
        $tool = Join-Path $script:psRoot 'signtool-stub.exe'
        [System.IO.File]::WriteAllText($tool, 'stub')
        $clearer = Join-Path $script:psRoot 'offclearsig-stub.exe'
        [System.IO.File]::WriteAllText($clearer, 'stub')
        $counter = @{ SignTool = 0 }
        $events = [System.Collections.Generic.List[string]]::new()
        $before = $Before
        $thumbprint = $script:certificate.Thumbprint
        Mock -ModuleName SigningSuite Get-SipSubject { [pscustomobject]@{ Supported = $true; Guid = [guid]::Empty; Name = 'Office'; ErrorCode = 0 } }
        Mock -ModuleName SigningSuite Clear-OfficeVbaSignature { $events.Add('clear'); [pscustomobject]@{ Success = $true; Message = '' } }.GetNewClosure()
        Mock -ModuleName SigningSuite Get-OfficeSipStatus { [pscustomobject]@{ Is64Bit = [Environment]::Is64BitProcess; OffClearSigPath = $clearer } }.GetNewClosure()
        Mock -ModuleName SigningSuite Invoke-SignTool {
            $counter.SignTool++
            $events.Add('sign')
            if ($counter.SignTool -eq 1) {
                $text = 'SignTool Error: The specified timestamp server either could not be reached or returned an invalid response.'
                return [pscustomobject]@{ ExitCode = 1; TimedOut = $false; Output = ''; Error = $text; Errors = @($text); Warnings = @() }
            }
            [pscustomobject]@{ ExitCode = 0; TimedOut = $false; Output = ''; Error = ''; Errors = @(); Warnings = @() }
        }.GetNewClosure()
        Mock -ModuleName SigningSuite Get-FileSignatureState {
            if ($counter.SignTool -eq 0) {
                return [pscustomobject]@{ State = $before; Message = ''; Signer = $null; Thumbprint = $null; Timestamped = $false }
            }
            [pscustomobject]@{ State = 'Untrusted'; Message = 'self-signed'; Signer = 'CN=Test'; Thumbprint = $thumbprint; Timestamped = $true }
        }.GetNewClosure()
        $parameters = @{
            LiteralPath                = $workbook
            Engine                     = 'SignTool'
            SignToolPath               = $tool
            Certificate                = $script:certificate
            TimestampMode              = 'Rfc3161'
            TimestampServer            = 'http://timestamp.example.test'
            TimestampRetryDelaySeconds = 0
            ClearOfficeSignatures      = $Clear
        }
        if (-not $Discover) {
            $parameters.OffClearSigPath = $clearer
        }
        $result = Invoke-FileSigning @parameters
        $result.Status | Should -Be $Status
        ($events -join ' ') | Should -Be $Order
    }

    It 'treats a timestamp warning on a signed pass as a missing timestamp: <Case>' -ForEach @(
        @{ Case = 'retry available'; Retries = 1; Calls = 4; Status = 'Signed' }
        @{ Case = 'no retry left'; Retries = 0; Calls = 2; Status = 'Failed' }
    ) {
        $path = Join-Path $script:psRoot "dual-warning-$Retries.dll"
        New-TestPortableExecutable -Path $path
        $tool = Join-Path $script:psRoot 'signtool-stub.exe'
        [System.IO.File]::WriteAllText($tool, 'stub')
        $counter = @{ SignTool = 0 }
        $thumbprint = $script:certificate.Thumbprint
        Mock -ModuleName SigningSuite Invoke-SignTool {
            $counter.SignTool++
            if ($counter.SignTool -eq 2) {
                return [pscustomobject]@{ ExitCode = 2; TimedOut = $false; Output = ''; Error = ''; Errors = @(); Warnings = @('Signing succeeded, but an error occurred while attempting to timestamp: dual.dll') }
            }
            [pscustomobject]@{ ExitCode = 0; TimedOut = $false; Output = ''; Error = ''; Errors = @(); Warnings = @() }
        }.GetNewClosure()
        Mock -ModuleName SigningSuite Get-FileSignatureState {
            [pscustomobject]@{ State = 'Untrusted'; Message = 'self-signed'; Signer = 'CN=Test'; Thumbprint = $thumbprint; Timestamped = $true }
        }.GetNewClosure()
        $result = Invoke-FileSigning -LiteralPath $path -Engine SignTool -SignToolPath $tool -Certificate $script:certificate -DualSign -TimestampMode Rfc3161 -TimestampServer 'http://timestamp.example.test' -TimestampRetryCount $Retries -TimestampRetryDelaySeconds 0
        $result.Status | Should -Be $Status
        Should -Invoke -ModuleName SigningSuite Invoke-SignTool -Times $Calls -Exactly
    }

    It 'recognizes timestamp failures in signing output: <Text>' -ForEach @(
        @{ Text = 'SignTool Error: The specified timestamp server either could not be reached or returned an invalid response.'; Expected = $true }
        @{ Text = 'SignTool Warning: Signing succeeded, but an error occurred while attempting to timestamp: a.exe'; Expected = $true }
        @{ Text = 'SignTool Error: No certificates were found that met all the given criteria.'; Expected = $false }
        @{ Text = ''; Expected = $false }
    ) {
        InModuleScope SigningSuite -Parameters @{ Text = $Text } { param($Text) Test-TimestampFailureText -Text $Text } | Should -Be $Expected
    }

    It 'reports a missing file and a timestamp request without a server' {
        (Invoke-FileSigning -LiteralPath (Join-Path $script:psRoot 'missing.ps1') -Engine PowerShell -Certificate $script:certificate).Detail | Should -Be 'The file no longer exists.'
        (Invoke-FileSigning -LiteralPath (Join-Path $script:psRoot 'script.ps1') -Engine PowerShell -Certificate $script:certificate -TimestampMode Authenticode).Detail | Should -BeLike 'A timestamp was requested*'
    }

    It 'checks revocation when verifying without failing an offline or self-signed chain' {
        $verification = Test-FileSignature -LiteralPath (Join-Path $script:psRoot 'script.ps1')
        $verification.State | Should -Be 'Untrusted'
        (Test-FileSignature -LiteralPath (Join-Path $script:psRoot 'script.ps1') -SkipRevocation).State | Should -Be 'Untrusted'
    }

    It 'leaves Office VBA signatures in place when a signing precondition fails: <Case>' -ForEach @(
        @{ Case = 'PowerShell engine with RFC 3161'; Engine = 'PowerShell'; Mode = 'Rfc3161'; Tool = $null; Detail = 'RFC 3161 timestamps need the SignTool engine*' }
        @{ Case = 'PowerShell engine without a certificate'; Engine = 'PowerShell'; Mode = 'None'; Tool = $null; Detail = 'The PowerShell engine needs a certificate*'; NoCertificate = $true }
        @{ Case = 'SignTool engine without signtool'; Engine = 'SignTool'; Mode = 'None'; Tool = 'missing'; Detail = 'signtool.exe was not found*' }
    ) {
        $workbook = Join-Path $script:psRoot "clear-$Engine-$Mode.xlsm"
        New-TestZip -Path $workbook -Entries @{ '[Content_Types].xml' = '<Types/>'; 'xl/vbaProject.bin' = 'x' }
        $marker = Join-Path $script:psRoot "clear-$Engine-$Mode.marker"
        $clearer = Join-Path $script:psRoot 'offclearsig-stub.cmd'
        [System.IO.File]::WriteAllText($clearer, "@echo cleared> `"%~dpn1.marker`"`r`n")
        $parameters = @{
            LiteralPath           = $workbook
            Engine                = $Engine
            TimestampMode         = $Mode
            TimestampServer       = 'http://timestamp.digicert.com'
            ClearOfficeSignatures = $true
            OffClearSigPath       = $clearer
            SignToolPath          = if ($Tool) { Join-Path $script:psRoot 'missing\signtool.exe' } else { '' }
        }
        if (-not $NoCertificate) {
            $parameters.Certificate = $script:certificate
        }
        Mock -ModuleName SigningSuite Get-SipSubject { [pscustomobject]@{ Supported = $true; Guid = [guid]::Empty; Name = 'Office'; ErrorCode = 0 } }
        $result = Invoke-FileSigning @parameters
        $result.Status | Should -Be 'Failed'
        $result.Detail | Should -BeLike $Detail
        [System.IO.File]::Exists($marker) | Should -BeFalse -Because 'VBA signatures must stay until signing can proceed'
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

Describe 'Access databases' {

    BeforeAll {
        $script:accessRoot = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'access [x]')).FullName
        $pfx = Join-Path $TestDrive 'access.pfx'
        New-TestPfx -Path $pfx
        $script:accessCertificate = Import-TestSigningCertificate -Path $pfx
        foreach ($name in 'App.accdb', 'App.accde', 'Old.mdb', 'Old.mde') {
            [System.IO.File]::WriteAllBytes((Join-Path $script:accessRoot $name), [byte[]](1..64))
        }
        $script:accessStub = Join-Path $script:accessRoot 'MSACCESS.EXE'
        [System.IO.File]::WriteAllText($script:accessStub, 'stub')
        $script:testKey = "Software\SigningSuiteTests\$([guid]::NewGuid().ToString('N'))\VBA\Security"
        $script:savedKeyPath = & (Get-Module SigningSuite) { $script:VbaSecurityKeyPath }
        & (Get-Module SigningSuite) { param($k) $script:VbaSecurityKeyPath = $k } $script:testKey
        $script:readTestKey = {
            $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($script:testKey)
            if (-not $key) { return $null }
            try {
                $values = @{}
                foreach ($name in $key.GetValueNames()) { $values[$name] = $key.GetValue($name) }
                $values
            }
            finally { $key.Close() }
        }
    }

    AfterAll {
        & (Get-Module SigningSuite) { param($k) $script:VbaSecurityKeyPath = $k } $script:savedKeyPath
        [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree(($script:testKey -replace '\\VBA\\Security$', ''), $false)
        $parent = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\SigningSuiteTests')
        if ($parent) {
            $empty = $parent.SubKeyCount -eq 0 -and $parent.ValueCount -eq 0
            $parent.Close()
            if ($empty) { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKey('Software\SigningSuiteTests', $false) }
        }
        Remove-TestKey -Certificate $script:accessCertificate
    }

    It 'maps <Extension> to the Access provider' -ForEach @(
        @{ Extension = '.accdb' }, @{ Extension = '.accde' }, @{ Extension = '.mdb' }, @{ Extension = '.MDE' }
    ) {
        (Get-FormatProvider -Extension $Extension).Id | Should -Be 'AccessVba'
    }

    It 'finds Access databases in a folder' {
        $found = @(Find-SignableFile -Path $script:accessRoot | ForEach-Object { [System.IO.Path]::GetFileName($_) })
        foreach ($name in 'App.accdb', 'App.accde', 'Old.mdb', 'Old.mde') {
            $found | Should -Contain $name
        }
    }

    It 'builds the MSACCESS.EXE arguments with the thumbprint selector' {
        $arguments = New-AccessSignArgument -LiteralPath 'C:\x y\App.accdb' -Thumbprint 'ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef 01'
        $arguments | Should -Be @('C:\x y\App.accdb', '/sign', '\ABCDEF0123456789ABCDEF0123456789ABCDEF01')
        { New-AccessSignArgument -LiteralPath 'a.accdb' -Thumbprint 'not a thumbprint' } | Should -Throw
    }

    It 'chooses the Access engine whatever engine was requested: <Case>' -ForEach @(
        @{ Case = 'automatic'; Requested = 'Auto'; Access = $true; Source = 'Store'; Engine = 'Access'; Reason = $null }
        @{ Case = 'PowerShell requested'; Requested = 'PowerShell'; Access = $true; Source = 'Store'; Engine = 'Access'; Reason = $null }
        @{ Case = 'Access missing'; Requested = 'Auto'; Access = $false; Source = 'Store'; Engine = $null; Reason = 'Microsoft Access was not found*' }
        @{ Case = 'digest signing library'; Requested = 'SignTool'; Access = $true; Source = 'Dlib'; Engine = $null; Reason = 'Access signs only with a certificate from the certificate store.' }
    ) {
        $choice = Resolve-SigningEngine -Provider (Get-FormatProvider -Id 'AccessVba') -Requested $Requested -SignToolAvailable $true -AccessAvailable $Access -Source $Source -TimestampMode Rfc3161
        $choice.Engine | Should -Be $Engine
        if ($Reason) { $choice.Reason | Should -BeLike $Reason }
    }

    It 'lists <Name> as ready with a signature it does not read' -ForEach @(
        @{ Name = 'App.accdb'; Microsoft365 = $true }
        @{ Name = 'Old.mdb'; Microsoft365 = $false }
    ) {
        $info = Get-SignableFileInfo -LiteralPath (Join-Path $script:accessRoot $Name)
        $info.Status | Should -Be 'Ready'
        $info.Format | Should -Be 'Access VBA'
        $info.SignatureState | Should -Be 'NotChecked'
        $info.Detail | Should -BeLike '*cannot read Access VBA signatures*'
        ($info.Detail -like '*Microsoft 365*') | Should -Be $Microsoft365
    }

    It 'reports a read-only database as failed in the list' {
        $path = Join-Path $script:accessRoot 'ReadOnly.accdb'
        [System.IO.File]::WriteAllBytes($path, [byte[]](1..8))
        (Get-Item -LiteralPath $path).IsReadOnly = $true
        try {
            $info = Get-SignableFileInfo -LiteralPath $path
            $info.Status | Should -Be 'Failed'
            $info.Detail | Should -BeLike 'The file is read-only.*'
        }
        finally {
            (Get-Item -LiteralPath $path).IsReadOnly = $false
        }
    }

    It 'reports the signature state as not checked in verify and in the list text' {
        (Get-FileSignatureState -LiteralPath (Join-Path $script:accessRoot 'App.accdb')).State | Should -Be 'NotChecked'
        $tool = Join-Path $script:accessRoot 'signtool-stub.exe'
        [System.IO.File]::WriteAllText($tool, 'stub')
        Mock -ModuleName SigningSuite Invoke-SignTool { throw 'signtool must not run for an Access database.' }
        $verification = Test-FileSignature -LiteralPath (Join-Path $script:accessRoot 'App.accdb') -SignToolPath $tool -SkipRevocation
        Should -Invoke -ModuleName SigningSuite Invoke-SignTool -Times 0 -Exactly
        $verification.State | Should -Be 'NotChecked'
        $verification.Detail | Should -BeLike 'Not checked.*'
        $verification.Detail | Should -Not -BeLike '*timestamped*'
        ConvertTo-SignatureText -State 'NotChecked' | Should -Be 'Not checked'
    }

    It 'refuses to remove an Access signature and says how to remove it' {
        $result = Remove-FileSignature -LiteralPath (Join-Path $script:accessRoot 'App.accdb') -Confirm:$false
        $result.Status | Should -Be 'Failed'
        $result.Detail | Should -BeLike '*Tools > Digital Signature > Remove*'
    }

    It 'writes the VBA signing values for the run and restores the earlier ones' {
        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($script:testKey)
        $key.SetValue('TimeStampURL', 'http://user.example.test', [Microsoft.Win32.RegistryValueKind]::String)
        $key.SetValue('TimeStampRetryDelay', 3, [Microsoft.Win32.RegistryValueKind]::DWord)
        $key.Close()
        $snapshot = InModuleScope SigningSuite { Set-VbaSigningSetting -TimestampServer 'http://timestamp.example.test' -TimestampRetryCount 2 -TimestampRetryDelaySeconds 4 -DigestAlgorithm SHA384 -Confirm:$false }
        $during = & $script:readTestKey
        $during.TimeStampURL | Should -Be 'http://timestamp.example.test'
        $during.TimeStampRetryCount | Should -Be 2
        $during.TimeStampRetryDelay | Should -Be 4000 -Because 'the delay value is in milliseconds'
        $during.V1HashEnhanced | Should -Be 3
        InModuleScope SigningSuite -Parameters @{ Snapshot = $snapshot } { param($Snapshot) Restore-VbaSigningSetting -Snapshot $Snapshot -Confirm:$false }
        $after = & $script:readTestKey
        $after.TimeStampURL | Should -Be 'http://user.example.test'
        $after.TimeStampRetryDelay | Should -Be 3
        $after.ContainsKey('TimeStampRetryCount') | Should -BeFalse
        $after.ContainsKey('V1HashEnhanced') | Should -BeFalse
        [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKey($script:testKey, $false)
    }

    It 'removes a user timestamp server for a run without a timestamp and removes a key it created' {
        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($script:testKey)
        $key.SetValue('TimeStampURL', 'http://user.example.test', [Microsoft.Win32.RegistryValueKind]::String)
        $key.Close()
        $snapshot = InModuleScope SigningSuite { Set-VbaSigningSetting -TimestampServer '' -Confirm:$false }
        (& $script:readTestKey).ContainsKey('TimeStampURL') | Should -BeFalse
        InModuleScope SigningSuite -Parameters @{ Snapshot = $snapshot } { param($Snapshot) Restore-VbaSigningSetting -Snapshot $Snapshot -Confirm:$false }
        (& $script:readTestKey).TimeStampURL | Should -Be 'http://user.example.test'
        [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKey($script:testKey, $false)

        $snapshot = InModuleScope SigningSuite { Set-VbaSigningSetting -TimestampServer 'http://timestamp.example.test' -Confirm:$false }
        InModuleScope SigningSuite -Parameters @{ Snapshot = $snapshot } { param($Snapshot) Restore-VbaSigningSetting -Snapshot $Snapshot -Confirm:$false }
        & $script:readTestKey | Should -BeNullOrEmpty -Because 'the key did not exist before the run'
    }

    Context 'signing through Access' {

        BeforeEach {
            Mock -ModuleName SigningSuite Test-CurrentUserCertificate { $true }
        }

        It 'signs, reports the signature as not checked, and sets the timestamp values only during the run' {
            $path = Join-Path $script:accessRoot 'Sign.accdb'
            [System.IO.File]::WriteAllBytes($path, [byte[]](1..64))
            # A mock body made with GetNewClosure does not receive the bound parameters, so the capture goes through a global.
            $global:SigningSuiteAccessRun = @{ Reader = $script:readTestKey }
            Mock -ModuleName SigningSuite Invoke-AccessProcess {
                $global:SigningSuiteAccessRun.Values = & $global:SigningSuiteAccessRun.Reader
                $global:SigningSuiteAccessRun.Arguments = $ArgumentList
                [System.IO.File]::AppendAllText($ArgumentList[0], 'signed')
                [pscustomobject]@{ TimedOut = $false; ExitCode = 0; DialogText = '' }
            }
            try {
                $result = Invoke-FileSigning -LiteralPath $path -Engine Access -AccessPath $script:accessStub -Certificate $script:accessCertificate -TimestampMode Rfc3161 -TimestampServer 'http://timestamp.example.test' -TimestampRetryCount 3 -TimestampRetryDelaySeconds 3
                $seen = $global:SigningSuiteAccessRun
            }
            finally {
                Remove-Variable -Name SigningSuiteAccessRun -Scope Global
            }
            $result.Status | Should -Be 'Signed'
            $result.SignatureState | Should -Be 'NotChecked'
            $result.Detail | Should -BeLike 'Access closed without an error and changed the database.*timestamp was requested from http://timestamp.example.test*Tools > Digital Signature*'
            $seen.Arguments | Should -Be @($path, '/sign', "\$($script:accessCertificate.Thumbprint)")
            $seen.Values.TimeStampURL | Should -Be 'http://timestamp.example.test'
            $seen.Values.TimeStampRetryDelay | Should -Be 3000
            & $script:readTestKey | Should -BeNullOrEmpty -Because 'the run restores the values that existed before it'
        }

        It 'fails with the Access dialog text when Access does not finish' {
            $path = Join-Path $script:accessRoot 'Dialog.accdb'
            [System.IO.File]::WriteAllBytes($path, [byte[]](1..64))
            Mock -ModuleName SigningSuite Invoke-AccessProcess { [pscustomobject]@{ TimedOut = $true; ExitCode = $null; DialogText = 'Microsoft Access cannot save the digital signature at this time.' } }
            $result = Invoke-FileSigning -LiteralPath $path -Engine Access -AccessPath $script:accessStub -Certificate $script:accessCertificate
            $result.Status | Should -Be 'Failed'
            $result.Detail | Should -Be 'Access showed: Microsoft Access cannot save the digital signature at this time. Access was closed before it finished; open the database in Access to check it. Signing .accdb and .accde files needs Access for Microsoft 365.'
        }

        It 'deletes the lock file that a stopped Access leaves behind' {
            $path = Join-Path $script:accessRoot 'Stopped.mdb'
            [System.IO.File]::WriteAllBytes($path, [byte[]](1..64))
            Mock -ModuleName SigningSuite Invoke-AccessProcess {
                [System.IO.File]::WriteAllText([System.IO.Path]::ChangeExtension($ArgumentList[0], '.ldb'), 'lock')
                [pscustomobject]@{ TimedOut = $true; ExitCode = $null; DialogText = '' }
            }
            $result = Invoke-FileSigning -LiteralPath $path -Engine Access -AccessPath $script:accessStub -Certificate $script:accessCertificate
            $result.Status | Should -Be 'Failed'
            $result.Detail | Should -Be 'Access did not finish within 90 seconds. Access was closed before it finished; open the database in Access to check it.'
            Test-Path -LiteralPath (Join-Path $script:accessRoot 'Stopped.ldb') | Should -BeFalse
        }

        It 'fails when Access closes without changing the database' {
            $path = Join-Path $script:accessRoot 'Unchanged.mdb'
            [System.IO.File]::WriteAllBytes($path, [byte[]](1..64))
            Mock -ModuleName SigningSuite Invoke-AccessProcess { [pscustomobject]@{ TimedOut = $false; ExitCode = 0; DialogText = '' } }
            $result = Invoke-FileSigning -LiteralPath $path -Engine Access -AccessPath $script:accessStub -Certificate $script:accessCertificate
            $result.Status | Should -Be 'Failed'
            $result.Detail | Should -BeLike 'Access closed without changing the database*'
        }

        It 'refuses before starting Access: <Case>' -ForEach @(
            @{ Case = 'certificate not in CurrentUser\My'; InStore = $false; Lock = $false; Tool = $true; Detail = 'Access reads the certificate from CurrentUser\My only*' }
            @{ Case = 'database open'; InStore = $true; Lock = $true; Tool = $true; Detail = 'The database is open, or an earlier Access session stopped without closing it (Locked.laccdb exists)*delete Locked.laccdb*' }
            @{ Case = 'Access missing'; InStore = $true; Lock = $false; Tool = $false; Detail = 'Microsoft Access was not found*' }
        ) {
            $path = Join-Path $script:accessRoot 'Locked.accdb'
            [System.IO.File]::WriteAllBytes($path, [byte[]](1..64))
            $lock = Join-Path $script:accessRoot 'Locked.laccdb'
            if ($Lock) { [System.IO.File]::WriteAllText($lock, 'lock') } elseif (Test-Path -LiteralPath $lock) { Remove-Item -LiteralPath $lock }
            $inStore = $InStore
            Mock -ModuleName SigningSuite Test-CurrentUserCertificate { $inStore }.GetNewClosure()
            Mock -ModuleName SigningSuite Invoke-AccessProcess { throw 'Access must not start.' }
            $tool = if ($Tool) { $script:accessStub } else { Join-Path $script:accessRoot 'missing\MSACCESS.EXE' }
            $result = Invoke-FileSigning -LiteralPath $path -Engine Access -AccessPath $tool -Certificate $script:accessCertificate
            $result.Status | Should -Be 'Failed'
            $result.Detail | Should -BeLike $Detail
            Should -Invoke -ModuleName SigningSuite Invoke-AccessProcess -Times 0 -Exactly
        }

        It 'reports a batch run with the Access engine, and without Access the reason' {
            $folder = [System.IO.Directory]::CreateDirectory((Join-Path $script:accessRoot 'batch')).FullName
            [System.IO.File]::WriteAllBytes((Join-Path $folder 'One.accdb'), [byte[]](1..64))
            Mock -ModuleName SigningSuite Invoke-AccessProcess {
                [System.IO.File]::AppendAllText($ArgumentList[0], 'signed')
                [pscustomobject]@{ TimedOut = $false; ExitCode = 0; DialogText = '' }
            }
            $signed = @(Invoke-SigningBatch -Path $folder -Certificate $script:accessCertificate -AccessPath $script:accessStub)
            $signed[0].Engine | Should -Be 'Access'
            $signed[0].Status | Should -Be 'Signed'
            $missing = @(Invoke-SigningBatch -Path $folder -Certificate $script:accessCertificate -AccessPath '')
            $missing[0].Status | Should -Be 'Failed'
            $missing[0].Detail | Should -BeLike 'Not signed: Microsoft Access was not found*'
        }
    }

    It 'stops a program that does not exit in time and returns the exit code of one that does' {
        $host32 = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $slow = InModuleScope SigningSuite -Parameters @{ Exe = $host32 } { param($Exe) Invoke-AccessProcess -AccessPath $Exe -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 60') -TimeoutSeconds 2 }
        $slow.TimedOut | Should -BeTrue
        $fast = InModuleScope SigningSuite -Parameters @{ Exe = $host32 } { param($Exe) Invoke-AccessProcess -AccessPath $Exe -ArgumentList @('-NoProfile', '-Command', 'exit 3') -TimeoutSeconds 30 }
        $fast.TimedOut | Should -BeFalse
        $fast.ExitCode | Should -Be 3
    }

    It 'reads dialog text in a time-limited runspace and returns nothing for a process without dialogs' {
        $text = InModuleScope SigningSuite { Read-ProcessDialogText -ProcessId $PID -TimeoutSeconds 15 }
        $text | Should -BeOfType [string]
        $text | Should -Be ''
    }

    It 'waits for an Access signing run of the same user in another process' {
        $path = Join-Path $script:accessRoot 'Waits.accdb'
        [System.IO.File]::WriteAllBytes($path, [byte[]](1..64))
        $ready = Join-Path $script:accessRoot 'mutex-ready.txt'
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $holder = "`$m = [System.Threading.Mutex]::new(`$false, 'Global\SigningSuite.VbaSigningSetting.$sid'); [void]`$m.WaitOne(); [System.IO.File]::WriteAllText('$ready', 'x'); Start-Sleep -Seconds 8; `$m.ReleaseMutex()"
        $process = Start-Process -FilePath (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList @('-NoProfile', '-Command', $holder) -WindowStyle Hidden -PassThru
        try {
            $deadline = [DateTime]::UtcNow.AddSeconds(20)
            while (-not [System.IO.File]::Exists($ready) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
            [System.IO.File]::Exists($ready) | Should -BeTrue
            Mock -ModuleName SigningSuite Test-CurrentUserCertificate { $true }
            Mock -ModuleName SigningSuite Invoke-AccessProcess { throw 'Access must not start while another run holds the lock.' }
            $result = Invoke-FileSigning -LiteralPath $path -Engine Access -AccessPath $script:accessStub -Certificate $script:accessCertificate -TimeoutSeconds 1
            $result.Status | Should -Be 'Failed'
            $result.Detail | Should -Be 'Another Access signing run of this user did not finish within 1 seconds.'
            Should -Invoke -ModuleName SigningSuite Invoke-AccessProcess -Times 0 -Exactly
        }
        finally {
            if (-not $process.HasExited) { $process.Kill() }
        }
    }

    It 'passes a database path with spaces and brackets as one argument' {
        $host32 = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $script = Join-Path $script:accessRoot 'echo args.ps1'
        $out = Join-Path $script:accessRoot 'args.txt'
        [System.IO.File]::WriteAllText($script, "param([string]`$Out) `$rest = @(`$args); [System.IO.File]::WriteAllText(`$Out, (`$rest -join '|'))`r`n")
        $arguments = @('-NoProfile', '-File', $script, $out) + (New-AccessSignArgument -LiteralPath 'C:\My Files [1]\App x.accdb' -Thumbprint ('A' * 40))
        $run = InModuleScope SigningSuite -Parameters @{ Exe = $host32; Arguments = $arguments } { param($Exe, $Arguments) Invoke-AccessProcess -AccessPath $Exe -ArgumentList $Arguments -TimeoutSeconds 30 }
        $run.ExitCode | Should -Be 0
        [System.IO.File]::ReadAllText($out) | Should -Be ('C:\My Files [1]\App x.accdb|/sign|\' + ('A' * 40))
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

Describe 'Signature removal' {

    BeforeAll {
        $script:removeRoot = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'remove [x]')).FullName
        $pfx = Join-Path $TestDrive 'remove.pfx'
        New-TestPfx -Path $pfx
        $script:removeCertificate = Import-TestSigningCertificate -Path $pfx
        [System.IO.File]::WriteAllText((Join-Path $removeRoot 'script.ps1'), "Write-Output 'signed'`r`n")
        [System.IO.File]::WriteAllText((Join-Path $removeRoot 'legacy.vbs'), "WScript.Echo 1`r`n")
        [System.IO.File]::WriteAllText((Join-Path $removeRoot 'job.wsf'), "<job><script language=`"VBScript`">WScript.Echo 1</script></job>`r`n")
        New-TestPortableExecutable -Path (Join-Path $removeRoot 'library.dll')
        [System.IO.File]::WriteAllText((Join-Path $removeRoot 'unsigned.ps1'), "Write-Output 1`r`n")
        [System.IO.File]::WriteAllText((Join-Path $removeRoot 'whatif.ps1'), "Write-Output 1`r`n")
        [System.IO.File]::WriteAllText((Join-Path $removeRoot 'readonly.ps1'), "Write-Output 1`r`n")
        [System.IO.File]::WriteAllText((Join-Path $removeRoot 'payload.txt'), 'x')
        & (Join-Path $env:windir 'System32\makecab.exe') (Join-Path $removeRoot 'payload.txt') (Join-Path $removeRoot 'archive.cab') *> $null
        foreach ($name in 'script.ps1', 'legacy.vbs', 'job.wsf', 'library.dll', 'whatif.ps1', 'readonly.ps1', 'archive.cab') {
            $null = Set-AuthenticodeSignature -LiteralPath (Join-Path $removeRoot $name) -Certificate $script:removeCertificate -HashAlgorithm SHA256
        }
        (Get-Item -LiteralPath (Join-Path $removeRoot 'readonly.ps1')).IsReadOnly = $true
    }

    AfterAll {
        $readonly = [System.IO.FileInfo]::new((Join-Path $script:removeRoot 'readonly.ps1'))
        if ($readonly.Exists) {
            $readonly.IsReadOnly = $false
        }
        Remove-TestKey -Certificate $script:removeCertificate
    }

    It 'removes the signature from <Name> and leaves the content intact' -ForEach @(
        @{ Name = 'script.ps1'; Content = "Write-Output 'signed'`r`n" }
        @{ Name = 'legacy.vbs'; Content = "WScript.Echo 1`r`n" }
        @{ Name = 'job.wsf'; Content = "<job><script language=`"VBScript`">WScript.Echo 1</script></job>`r`n" }
        @{ Name = 'library.dll'; Content = $null }
    ) {
        $path = Join-Path $script:removeRoot $Name
        (Get-FileSignatureState -LiteralPath $path).State | Should -Be 'Untrusted'
        $result = Remove-FileSignature -LiteralPath $path
        $result.Status | Should -Be 'Removed'
        $result.Detail | Should -Be 'Signature from Signing Suite Test removed.'
        $result.PreviousThumbprint | Should -Be $script:removeCertificate.Thumbprint
        $result.SignatureState | Should -Be 'NotSigned'
        (Get-FileSignatureState -LiteralPath $path).State | Should -Be 'NotSigned'
        Test-FileUnlocked -Path $path | Should -BeTrue
        if ($null -ne $Content) {
            [System.IO.File]::ReadAllText($path) | Should -Be $Content
        }
    }

    It 'skips a file that is not signed' {
        $result = Remove-FileSignature -LiteralPath (Join-Path $script:removeRoot 'unsigned.ps1')
        $result.Status | Should -Be 'Skipped'
        $result.Detail | Should -Be 'Not signed.'
    }

    It 'changes nothing with -WhatIf' {
        $path = Join-Path $script:removeRoot 'whatif.ps1'
        $result = Remove-FileSignature -LiteralPath $path -WhatIf
        $result.Status | Should -Be 'Skipped'
        (Get-FileSignatureState -LiteralPath $path).State | Should -Be 'Untrusted'
    }

    It 'fails <Name> without touching it: <Detail>' -ForEach @(
        @{ Name = 'readonly.ps1'; Status = 'Failed'; Detail = 'The file is read-only.' }
        @{ Name = 'missing.ps1'; Status = 'Failed'; Detail = 'The file no longer exists.' }
        @{ Name = 'archive.cab'; Status = 'Failed'; Detail = 'Windows cannot remove a cabinet signature; rebuild the cabinet without one.' }
        @{ Name = 'payload.txt'; Status = 'Skipped'; Detail = 'Not a signable file type.' }
    ) {
        $path = Join-Path $script:removeRoot $Name
        $result = Remove-FileSignature -LiteralPath $path
        $result.Status | Should -Be $Status
        $result.Detail | Should -Be $Detail
        if ($Name -in 'readonly.ps1', 'archive.cab') {
            (Get-FileSignatureState -LiteralPath $path).State | Should -Be 'Untrusted'
        }
    }

    It 'removes both signatures from a dual-signed executable' -Skip:(-not $script:dlibAvailable) {
        $path = Join-Path $script:removeRoot 'dual.dll'
        New-TestPortableExecutable -Path $path
        $identity = New-TestDlibIdentity -Folder $script:removeRoot
        $dlib = Get-TestDigestSignLibrary -Architecture 'x64'
        $signed = Invoke-FileSigning -LiteralPath $path -Engine SignTool -SignToolPath $script:signTool.Path -DlibPath $dlib -MetadataPath $identity.MetadataPath -CertificateFile $identity.CertificateFile -DualSign
        $signed.Status | Should -Be 'Signed'
        $signed.Passes | Should -Be 2
        (Remove-FileSignature -LiteralPath $path).Status | Should -Be 'Removed'
        (Test-FileSignature -LiteralPath $path -SignToolPath $script:signTool.Path).State | Should -Be 'NotSigned'
    }

    It 'lists and unsigns a folder as a batch' {
        $batchRoot = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'remove-batch')).FullName
        [System.IO.File]::WriteAllText((Join-Path $batchRoot 'signed.ps1'), "Write-Output 1`r`n")
        [System.IO.File]::WriteAllText((Join-Path $batchRoot 'plain.vbs'), "WScript.Echo 1`r`n")
        [System.IO.File]::WriteAllText((Join-Path $batchRoot 'notes.txt'), 'x')
        $null = Set-AuthenticodeSignature -LiteralPath (Join-Path $batchRoot 'signed.ps1') -Certificate $script:removeCertificate -HashAlgorithm SHA256

        $preview = @(Invoke-SignatureRemovalBatch -Path $batchRoot, (Join-Path $script:removeRoot 'archive.cab') -WhatIf)
        @($preview | Where-Object Status -eq 'WhatIf' | ForEach-Object Name) | Should -Be @('signed.ps1')
        @($preview | Where-Object Name -eq 'plain.vbs')[0].Status | Should -Be 'Skipped'
        @($preview | Where-Object Name -eq 'archive.cab')[0].Status | Should -Be 'Failed'
        (Get-FileSignatureState -LiteralPath (Join-Path $batchRoot 'signed.ps1')).State | Should -Be 'Untrusted'

        $results = @(Invoke-SignatureRemovalBatch -Path $batchRoot, (Join-Path $batchRoot 'notes.txt'))
        $byName = @{}
        foreach ($result in $results) {
            $byName[$result.Name] = $result
        }
        $byName['signed.ps1'].Status | Should -Be 'Removed'
        $byName['signed.ps1'].PreviousSigner | Should -Be 'Signing Suite Test'
        $byName['plain.vbs'].Status | Should -Be 'Skipped'
        $byName['notes.txt'].Status | Should -Be 'Skipped'
        (Get-FileSignatureState -LiteralPath (Join-Path $batchRoot 'signed.ps1')).State | Should -Be 'NotSigned'
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
