function New-TestCertificate {
    param(
        [string]$Subject = 'CN=Signing Suite Test',
        [bool]$CodeSigning = $true
    )

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $Subject, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    if ($CodeSigning) {
        $oids = [System.Security.Cryptography.OidCollection]::new()
        [void]$oids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
        $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $false))
    }
    $request.CreateSelfSigned([DateTimeOffset]::Now.AddMinutes(-5), [DateTimeOffset]::Now.AddDays(1))
}

function New-TestPfx {
    param(
        [string]$Path,
        [string]$Subject = 'CN=Signing Suite Test',
        [bool]$CodeSigning = $true,
        [string]$Protection = 'test-protection'
    )

    $certificate = New-TestCertificate -Subject $Subject -CodeSigning $CodeSigning
    try {
        [System.IO.File]::WriteAllBytes($Path, $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $Protection))
    }
    finally {
        $certificate.Dispose()
    }
}

function Import-TestSigningCertificate {
    <#
    .SYNOPSIS
        Loads a PFX with a persisted user key so Set-AuthenticodeSignature can use it; the certificate never enters a store.
    #>
    param(
        [string]$Path,
        [string]$Protection = 'test-protection'
    )

    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path, $Protection,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]'UserKeySet, PersistKeySet')
}

function Remove-TestKey {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    if (-not $Certificate) {
        return
    }
    $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if ($key -is [System.Security.Cryptography.RSACng]) {
        $key.Key.Delete()
    }
    elseif ($key -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
        $key.PersistKeyInCsp = $false
        $key.Clear()
    }
    $Certificate.Dispose()
}

function ConvertTo-TestSecureString {
    param([string]$Value)

    $secure = [System.Security.SecureString]::new()
    foreach ($character in $Value.ToCharArray()) {
        $secure.AppendChar($character)
    }
    $secure.MakeReadOnly()
    $secure
}

function New-TestZip {
    param(
        [string]$Path,
        [hashtable]$Entries
    )

    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::Open($Path, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $Entries.Keys) {
            $writer = [System.IO.StreamWriter]::new($zip.CreateEntry($name).Open())
            try {
                $writer.Write([string]$Entries[$name])
            }
            finally {
                $writer.Dispose()
            }
        }
    }
    finally {
        $zip.Dispose()
    }
}

function New-TestPortableExecutable {
    <#
    .SYNOPSIS
        Writes an unsigned managed DLL that no Windows catalog covers.
    #>
    param([string]$Path)

    # Add-Type resolves -OutputAssembly as a wildcard path, and Windows PowerShell requires a .dll name for a library.
    $name = 'SigningSuiteFixture' + [guid]::NewGuid().ToString('N')
    $staging = Join-Path ([System.IO.Path]::GetTempPath()) "$name.dll"
    Add-Type -TypeDefinition "public static class $name { public static int Value() { return 1; } }" -OutputAssembly $staging -OutputType Library
    try {
        [System.IO.File]::Copy($staging, $Path, $true)
    }
    finally {
        [System.IO.File]::Delete($staging)
    }
}

function Get-TestDigestSignLibrary {
    <#
    .SYNOPSIS
        Returns the test dlib for an architecture, building it when Visual Studio C++ tools are present.
    #>
    param([ValidateSet('x64', 'x86')][string]$Architecture = 'x64')

    $root = Join-Path $PSScriptRoot 'Native'
    $dll = Join-Path $root "bin\$Architecture\TestDigestSign.dll"
    if (-not [System.IO.File]::Exists($dll)) {
        try {
            & (Join-Path $root 'Build-TestDigestSign.ps1') *> $null
        }
        catch {
            return $null
        }
    }
    if ([System.IO.File]::Exists($dll)) {
        return $dll
    }
    $null
}

function New-TestDlibIdentity {
    <#
    .SYNOPSIS
        Writes a certificate file, an unencrypted PKCS #8 key and dlib metadata into a folder.
    #>
    param(
        [string]$Folder,
        [string]$Subject = 'CN=Signing Suite Dlib Test'
    )

    $certificate = New-TestCertificate -Subject $Subject
    try {
        $certificatePath = Join-Path $Folder 'dlib.cer'
        $keyPath = Join-Path $Folder 'dlib.p8'
        $metadataPath = Join-Path $Folder 'dlib-metadata.txt'
        [System.IO.File]::WriteAllBytes($certificatePath, $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
        if ($rsa.PSObject.Methods['ExportPkcs8PrivateKey']) {
            [System.IO.File]::WriteAllBytes($keyPath, $rsa.ExportPkcs8PrivateKey())
        }
        else {
            [System.IO.File]::WriteAllBytes($keyPath, ([System.Security.Cryptography.RSACng]$rsa).Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob))
        }
        [System.IO.File]::WriteAllText($metadataPath, "key=$keyPath")
        [pscustomobject]@{
            CertificateFile = $certificatePath
            MetadataPath    = $metadataPath
            Thumbprint      = $certificate.Thumbprint
            Subject         = $certificate.Subject
        }
    }
    finally {
        $certificate.Dispose()
    }
}

function Test-FileUnlocked {
    param([string]$Path)

    try {
        [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None).Dispose()
        return $true
    }
    catch {
        return $false
    }
}

function Wait-TestBackgroundJob {
    param([int]$TimeoutSeconds = 180)

    $frame = [System.Windows.Threading.DispatcherFrame]::new()
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $poll = [System.Windows.Threading.DispatcherTimer]::new()
    $poll.Interval = [TimeSpan]::FromMilliseconds(100)
    $poll.Add_Tick({
            if ($null -eq $script:Job -or [DateTime]::UtcNow -gt $deadline) {
                $poll.Stop()
                $frame.Continue = $false
            }
        })
    $poll.Start()
    [System.Windows.Threading.Dispatcher]::PushFrame($frame)
    $null -eq $script:Job
}
