$script:CodeSigningOid = '1.3.6.1.5.5.7.3.3'

function Test-CodeSigningUsage {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($oid in $extension.EnhancedKeyUsages) {
                if ($oid.Value -eq $script:CodeSigningOid) {
                    return $true
                }
            }
        }
    }
    return $false
}

function Get-SigningCertificate {
    <#
    .SYNOPSIS
        Lists currently valid code-signing certificates that have a private key, newest expiry first.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string[]]$StoreLocation = @('CurrentUser')
    )

    $now = Get-Date
    $seen = @{}
    foreach ($location in $StoreLocation) {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::My,
            [System.Security.Cryptography.X509Certificates.StoreLocation]$location)
        try {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadOnly, OpenExistingOnly')
        }
        catch {
            continue
        }
        try {
            foreach ($certificate in $store.Certificates) {
                if ($seen.ContainsKey($certificate.Thumbprint)) {
                    continue
                }
                if ($certificate.HasPrivateKey -and $certificate.NotBefore -le $now -and $certificate.NotAfter -gt $now -and
                    (Test-CodeSigningUsage -Certificate $certificate)) {
                    $seen[$certificate.Thumbprint] = $true
                    Add-Member -InputObject $certificate -NotePropertyName StoreLocation -NotePropertyValue $location -Force
                    $certificate
                }
            }
        }
        finally {
            $store.Close()
        }
    }
}

function Get-CertificateLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $nameType = [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName
    $location = if ($Certificate.PSObject.Properties['StoreLocation']) { $Certificate.StoreLocation } else { 'CurrentUser' }
    [pscustomobject]@{
        IssuedTo      = $Certificate.GetNameInfo($nameType, $false)
        IssuedBy      = $Certificate.GetNameInfo($nameType, $true)
        Subject       = $Certificate.Subject
        Expires       = $Certificate.NotAfter.ToString('yyyy-MM-dd')
        Thumbprint    = $Certificate.Thumbprint
        StoreLocation = $location
        KeyProvider   = Get-CertificateKeyProvider -Certificate $Certificate
        Certificate   = $Certificate
    }
}

function Get-CertificateKeyProvider {
    <#
    .SYNOPSIS
        Names the CSP or KSP that holds the certificate's private key without opening the key.
    .DESCRIPTION
        Reading CERT_KEY_PROV_INFO_PROP_ID does not touch the key, so smart cards and tokens are not prompted for a PIN.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not ('SigningSuite.Native.CertProperty' -as [type])) {
        Add-Type -Namespace SigningSuite.Native -Name CertProperty -MemberDefinition @'
[DllImport("crypt32.dll", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool CertGetCertificateContextProperty(IntPtr pCertContext, uint dwPropId, IntPtr pvData, ref uint pcbData);

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct CRYPT_KEY_PROV_INFO {
    public string pwszContainerName;
    public string pwszProvName;
    public uint dwProvType;
    public uint dwFlags;
    public uint cProvParam;
    public IntPtr rgProvParam;
    public uint dwKeySpec;
}
'@
    }

    $propertyId = 2
    $size = [uint32]0
    if (-not [SigningSuite.Native.CertProperty]::CertGetCertificateContextProperty($Certificate.Handle, $propertyId, [IntPtr]::Zero, [ref]$size)) {
        return $null
    }
    $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([int]$size)
    try {
        if (-not [SigningSuite.Native.CertProperty]::CertGetCertificateContextProperty($Certificate.Handle, $propertyId, $buffer, [ref]$size)) {
            return $null
        }
        $info = [System.Runtime.InteropServices.Marshal]::PtrToStructure($buffer, [type][SigningSuite.Native.CertProperty+CRYPT_KEY_PROV_INFO])
        return $info.pwszProvName
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
    }
}

function Import-PfxToUserStore {
    <#
    .SYNOPSIS
        Validates a PFX (private key, Code Signing EKU, validity dates) and only then adds it to Cert:\CurrentUser\My.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [System.Security.SecureString]$Password
    )

    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]

    # Without PersistKeySet the private key is removed on Dispose, so a rejected file leaves no key behind.
    $probe = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path, $Password, $flags::UserKeySet)
    try {
        if (-not $probe.HasPrivateKey) {
            throw 'The file does not contain a private key.'
        }
        if (-not (Test-CodeSigningUsage -Certificate $probe)) {
            throw 'The certificate is not valid for code signing (the Code Signing enhanced key usage is missing).'
        }
        $now = Get-Date
        if ($probe.NotBefore -gt $now -or $probe.NotAfter -le $now) {
            throw "The certificate is not currently valid ($($probe.NotBefore.ToString('yyyy-MM-dd')) to $($probe.NotAfter.ToString('yyyy-MM-dd')))."
        }
    }
    finally {
        $probe.Dispose()
    }

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path, $Password, ($flags::UserKeySet -bor $flags::PersistKeySet))
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try {
        $store.Add($certificate)
    }
    finally {
        $store.Close()
    }
    $certificate
}
