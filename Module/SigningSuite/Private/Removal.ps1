if (-not ('SigningSuite.Native.SipSignature' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace SigningSuite.Native
{
    public static class SipSignature
    {
        public const int NoSubjectInterfacePackage = -1;
        public const int RemovalNotSupported = -2;
        public const int RemovalRefused = -3;

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPT_DATA_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPT_ALGORITHM_IDENTIFIER
        {
            public IntPtr pszObjId;
            public CRYPT_DATA_BLOB Parameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SIP_SUBJECTINFO
        {
            public uint cbSize;
            public IntPtr pgSubjectType;
            public IntPtr hFile;
            public IntPtr pwsFileName;
            public IntPtr pwsDisplayName;
            public uint dwReserved1;
            public uint dwIntVersion;
            public IntPtr hProv;
            public CRYPT_ALGORITHM_IDENTIFIER DigestAlgorithm;
            public uint dwFlags;
            public uint dwEncodingType;
            public uint dwReserved2;
            public uint fdwCAPISettings;
            public uint fdwSecuritySettings;
            public uint dwIndex;
            public uint dwUnionChoice;
            public IntPtr psFlat;
            public IntPtr pClientData;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SIP_DISPATCH_INFO
        {
            public uint cbSize;
            public IntPtr hSIP;
            public IntPtr pfGet;
            public IntPtr pfPut;
            public IntPtr pfCreate;
            public IntPtr pfVerify;
            public IntPtr pfRemove;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private delegate bool RemoveSignedDataMsg(ref SIP_SUBJECTINFO pSubjectInfo, uint dwIndex);

        private const uint X509_ASN_ENCODING = 0x1;
        private const uint PKCS_7_ASN_ENCODING = 0x10000;

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptSIPRetrieveSubjectGuid(string FileName, IntPtr hFileIn, out Guid pgSubject);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptSIPLoad(ref Guid pgSubject, uint dwFlags, ref SIP_DISPATCH_INFO pSipDispatch);

        // Returns 0 when the subject interface package removed the embedded signature, one of the negative constants
        // when no removal was attempted, or the Win32 error the package reported.
        public static int Remove(string path)
        {
            Guid subject;
            if (!CryptSIPRetrieveSubjectGuid(path, IntPtr.Zero, out subject))
            {
                return NoSubjectInterfacePackage;
            }
            SIP_DISPATCH_INFO dispatch = new SIP_DISPATCH_INFO();
            dispatch.cbSize = (uint)Marshal.SizeOf(typeof(SIP_DISPATCH_INFO));
            if (!CryptSIPLoad(ref subject, 0, ref dispatch))
            {
                return Marshal.GetLastWin32Error();
            }
            if (dispatch.pfRemove == IntPtr.Zero)
            {
                return RemovalNotSupported;
            }
            RemoveSignedDataMsg remove = (RemoveSignedDataMsg)Marshal.GetDelegateForFunctionPointer(dispatch.pfRemove, typeof(RemoveSignedDataMsg));
            IntPtr subjectPointer = Marshal.AllocHGlobal(16);
            IntPtr namePointer = Marshal.StringToHGlobalUni(path);
            try
            {
                Marshal.Copy(subject.ToByteArray(), 0, subjectPointer, 16);
                SIP_SUBJECTINFO info = new SIP_SUBJECTINFO();
                info.cbSize = (uint)Marshal.SizeOf(typeof(SIP_SUBJECTINFO));
                info.pgSubjectType = subjectPointer;
                info.hFile = new IntPtr(-1);
                info.pwsFileName = namePointer;
                info.dwEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
                if (remove(ref info, 0))
                {
                    return 0;
                }
                int error = Marshal.GetLastWin32Error();
                return error == 0 ? RemovalRefused : error;
            }
            finally
            {
                Marshal.FreeHGlobal(subjectPointer);
                Marshal.FreeHGlobal(namePointer);
            }
        }
    }
}
'@
}

function Remove-FileSignature {
    <#
    .SYNOPSIS
        Removes the embedded Authenticode signature from one file, or the VBA signatures from one Office file.
    .DESCRIPTION
        Scripts, executables, installers and app packages are unsigned through the Subject Interface Package that
        Windows registers for the file type; Office files through offclearsig.exe. Cabinets and catalogs are refused:
        the cabinet package reports no removal, and a catalog is itself a signature.
    .OUTPUTS
        Object with Path, Status (Removed, Failed, Skipped), Detail, PreviousSigner, PreviousThumbprint,
        SignatureState, Signer, SignerThumbprint, Timestamped.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath,

        [string]$OffClearSigPath,

        [int]$TimeoutSeconds = 120
    )

    $result = [ordered]@{
        Path              = $LiteralPath
        Status            = 'Failed'
        Detail            = ''
        PreviousSigner    = $null
        PreviousThumbprint = $null
        SignatureState    = ''
        Signer            = $null
        SignerThumbprint  = $null
        Timestamped       = $false
    }

    $provider = Get-FormatProvider -Extension ([System.IO.Path]::GetExtension($LiteralPath))
    if (-not $provider) {
        $result.Status = 'Skipped'
        $result.Detail = 'Not a signable file type.'
        return [pscustomobject]$result
    }
    if (-not [System.IO.File]::Exists($LiteralPath)) {
        $result.Detail = 'The file no longer exists.'
        return [pscustomobject]$result
    }
    if ([System.IO.FileInfo]::new($LiteralPath).IsReadOnly) {
        $result.Detail = 'The file is read-only.'
        return [pscustomobject]$result
    }

    $before = Get-FileSignatureState -LiteralPath $LiteralPath
    $result.SignatureState = $before.State
    $result.Signer = $before.Signer
    $result.SignerThumbprint = $before.Thumbprint
    $result.Timestamped = [bool]$before.Timestamped
    if ($before.State -eq 'NotSigned') {
        $result.Status = 'Skipped'
        $result.Detail = 'Not signed.'
        return [pscustomobject]$result
    }
    if ($before.State -eq 'Unknown') {
        $result.Detail = "The signature could not be read: $($before.Message)"
        return [pscustomobject]$result
    }
    $result.PreviousSigner = $before.Signer
    $result.PreviousThumbprint = $before.Thumbprint

    if ($provider.Id -eq 'Catalog') {
        $result.Detail = 'A catalog file is itself a signature; delete the catalog instead.'
        return [pscustomobject]$result
    }
    if ($provider.Id -eq 'Cabinet') {
        $result.Detail = 'Windows cannot remove a cabinet signature; rebuild the cabinet without one.'
        return [pscustomobject]$result
    }
    if (-not $PSCmdlet.ShouldProcess($LiteralPath, 'Remove signature')) {
        $result.Status = 'Skipped'
        $result.Detail = 'Not changed.'
        return [pscustomobject]$result
    }

    if ($provider.Id -eq 'OfficeVba') {
        if (-not $OffClearSigPath -or -not [System.IO.File]::Exists($OffClearSigPath)) {
            $result.Detail = 'offclearsig.exe from the Office SIP package was not found, so the VBA signatures could not be removed.'
            return [pscustomobject]$result
        }
        $cleared = Clear-OfficeVbaSignature -LiteralPath $LiteralPath -OffClearSigPath $OffClearSigPath -TimeoutSeconds $TimeoutSeconds -Confirm:$false
        if (-not $cleared.Success) {
            $result.Detail = "The VBA signatures could not be removed: $($cleared.Message)"
            return [pscustomobject]$result
        }
    }
    else {
        # A dual-signed executable loses both signatures in one call; the bound keeps a package that reports success
        # without changing the file from looping.
        for ($attempt = 1; $attempt -le 4; $attempt++) {
            $code = [SigningSuite.Native.SipSignature]::Remove($LiteralPath)
            if ($code -ne 0) {
                $result.Detail = switch ($code) {
                    ([SigningSuite.Native.SipSignature]::NoSubjectInterfacePackage) { 'No signing handler (SIP) claims this file.' }
                    ([SigningSuite.Native.SipSignature]::RemovalNotSupported) { "The signing handler for $($provider.Name) files does not support signature removal." }
                    ([SigningSuite.Native.SipSignature]::RemovalRefused) { "The signing handler for $($provider.Name) files refused to remove the signature." }
                    default { "The signing handler reported an error: $([System.ComponentModel.Win32Exception]::new([int]$code).Message)" }
                }
                return [pscustomobject]$result
            }
            if ((Get-FileSignatureState -LiteralPath $LiteralPath).State -eq 'NotSigned') {
                break
            }
        }
    }

    $after = Get-FileSignatureState -LiteralPath $LiteralPath
    $result.SignatureState = $after.State
    $result.Signer = $after.Signer
    $result.SignerThumbprint = $after.Thumbprint
    $result.Timestamped = [bool]$after.Timestamped
    if ($after.State -ne 'NotSigned') {
        $result.Detail = "Removal reported success but the file is still $($after.State): $($after.Message)"
        return [pscustomobject]$result
    }
    $result.Status = 'Removed'
    $result.Detail = if ($before.Signer) { "Signature from $($before.Signer) removed." } else { 'Signature removed.' }
    [pscustomobject]$result
}
