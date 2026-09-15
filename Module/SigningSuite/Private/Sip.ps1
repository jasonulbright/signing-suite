if (-not ('SigningSuite.Native.Sip' -as [type])) {
    Add-Type -Namespace SigningSuite.Native -Name Sip -MemberDefinition @'
[DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool CryptSIPRetrieveSubjectGuid(string FileName, IntPtr hFileIn, out Guid pgSubject);

public static bool FileContains(string path, byte[] pattern)
{
    const int bufferSize = 1 << 20;
    byte[] buffer = new byte[bufferSize + pattern.Length];
    int carry = 0;
    using (var stream = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite, 1 << 16))
    {
        while (true)
        {
            int read = stream.Read(buffer, carry, bufferSize);
            if (read <= 0)
            {
                return false;
            }
            int length = carry + read;
            for (int i = 0; i <= length - pattern.Length; i++)
            {
                int j = 0;
                while (j < pattern.Length && buffer[i + j] == pattern[j])
                {
                    j++;
                }
                if (j == pattern.Length)
                {
                    return true;
                }
            }
            carry = Math.Min(pattern.Length - 1, length);
            Buffer.BlockCopy(buffer, length - carry, buffer, 0, carry);
        }
    }
}
'@
}

$script:KnownSipSubjects = @{
    'c689aab8-8e78-11d0-8c47-00c04fc295ee' = 'Portable executable'
    'c689aab9-8e78-11d0-8c47-00c04fc295ee' = 'Java class'
    'c689aaba-8e78-11d0-8c47-00c04fc295ee' = 'Cabinet'
    'de351a42-8e59-11d0-8c47-00c04fc295ee' = 'Flat image'
    'de351a43-8e59-11d0-8c47-00c04fc295ee' = 'Catalog'
    '9ba61d3f-e73a-11d0-8cd2-00c04fc295ee' = 'Certificate trust list'
    '000c10f1-0000-0000-c000-000000000046' = 'Windows Installer'
    '603bcc1f-4b59-4e08-b724-d2c6297ef351' = 'PowerShell'
    '06c9e010-38ce-11d4-a2a3-00104bd35090' = 'JScript'
    '1629f04e-2799-4db5-8fe5-ace10f17ebab' = 'VBScript'
    '1a610570-38ce-11d4-a2a3-00104bd35090' = 'Windows Script File'
    '9f3053c5-439d-4bf7-8a77-04f0450a1d9f' = 'Electronic software distribution'
}

function Get-SipSubject {
    <#
    .SYNOPSIS
        Asks Windows which Subject Interface Package claims a file.
    .OUTPUTS
        Object with Supported, Guid, Name and ErrorCode. Supported is false when no SIP claims the file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath
    )

    $guid = [guid]::Empty
    $supported = [SigningSuite.Native.Sip]::CryptSIPRetrieveSubjectGuid($LiteralPath, [IntPtr]::Zero, [ref]$guid)
    # SetLastError holds a stale value on success for some SIPs (pwrshsip leaves 0x32), so the code only means something on failure.
    $errorCode = if ($supported) { 0 } else { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $key = $guid.ToString()
    $name = if ($script:KnownSipSubjects.ContainsKey($key)) { $script:KnownSipSubjects[$key] } elseif ($supported) { 'Registered SIP' } else { $null }

    [pscustomobject]@{
        Supported = [bool]$supported
        Guid      = $guid
        Name      = $name
        ErrorCode = $errorCode
    }
}
