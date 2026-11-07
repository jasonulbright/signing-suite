$script:AccessExtensions = @('.accdb', '.accde', '.mdb', '.mde')
$script:VbaSecurityKeyPath = 'Software\Microsoft\VBA\Security'
$script:VbaHashValues = @{ SHA256 = 2; SHA384 = 3; SHA512 = 4 }
$script:AccessNotCheckedMessage = 'The app cannot read Access VBA signatures; Microsoft does not document where Access stores them.'
# Path and last write time of each MSACCESS.EXE whose signature was checked, so the check runs once per file version.
$script:MsAccessPublisherCache = @{}

function Find-MsAccess {
    <#
    .SYNOPSIS
        Locates MSACCESS.EXE from its App Paths registration or the default Microsoft 365 install folders.
    .DESCRIPTION
        Only HKLM registrations and Program Files paths are used, and only a file with a valid Microsoft signature is
        returned: the signing run starts this program with the selected certificate's thumbprint.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $candidates = [System.Collections.Generic.List[string]]::new()
    foreach ($view in [Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try {
            $key = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\MSACCESS.EXE')
            if ($key) {
                try {
                    $value = [string]$key.GetValue('')
                    if ($value) {
                        $candidates.Add($value.Trim('"'))
                    }
                }
                finally {
                    $key.Close()
                }
            }
        }
        finally {
            $base.Close()
        }
    }
    foreach ($root in $env:ProgramFiles, ${env:ProgramFiles(x86)}) {
        if ($root) {
            $candidates.Add((Join-Path $root 'Microsoft Office\root\Office16\MSACCESS.EXE'))
        }
    }
    foreach ($candidate in $candidates) {
        if (-not [System.IO.File]::Exists($candidate)) {
            continue
        }
        $full = [System.IO.Path]::GetFullPath($candidate)
        $cacheKey = '{0}|{1}' -f $full.ToLowerInvariant(), [System.IO.File]::GetLastWriteTimeUtc($full).Ticks
        if (-not $script:MsAccessPublisherCache.ContainsKey($cacheKey)) {
            $script:MsAccessPublisherCache[$cacheKey] = Test-SignToolPublisher -LiteralPath $full
        }
        if ($script:MsAccessPublisherCache[$cacheKey]) {
            return $full
        }
    }
}

function New-AccessSignArgument {
    <#
    .SYNOPSIS
        Builds the MSACCESS.EXE argument list that signs the VBA project of one database.
    .DESCRIPTION
        A backslash before the thumbprint selects the certificate by thumbprint; a bare name selects the first
        certificate with that name.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath,

        [Parameter(Mandatory)]
        [ValidatePattern('^[0-9A-Fa-f\s]{40,}$')]
        [string]$Thumbprint
    )

    [string[]]@($LiteralPath, '/sign', ('\' + ($Thumbprint -replace '\s', '').ToUpperInvariant()))
}

function Test-CurrentUserCertificate {
    <#
    .SYNOPSIS
        True when CurrentUser\My holds a certificate with the thumbprint.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Thumbprint
    )

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
        $found = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, ($Thumbprint -replace '\s', ''), $false)
        $found.Count -gt 0
    }
    catch {
        $false
    }
    finally {
        $store.Close()
    }
}

function Get-AccessLockFilePath {
    <#
    .SYNOPSIS
        Returns the lock file that Access keeps beside an open database.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath
    )

    $extension = [System.IO.Path]::GetExtension($LiteralPath).ToLowerInvariant()
    $lockExtension = if ($extension -in '.mdb', '.mde') { '.ldb' } else { '.laccdb' }
    [System.IO.Path]::ChangeExtension($LiteralPath, $lockExtension)
}

function Set-VbaSigningSetting {
    <#
    .SYNOPSIS
        Writes the per-user VBA signing values that Access reads, and returns the earlier values for Restore-VbaSigningSetting.
    .DESCRIPTION
        TimeStampURL, TimeStampRetryCount, TimeStampRetryDelay (milliseconds) and V1HashEnhanced are the values the
        Visual Basic Editor reads under HKCU\Software\Microsoft\VBA\Security. With no timestamp server, TimeStampURL is
        removed for the run so a value the user set does not add a timestamp the run did not ask for.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [AllowEmptyString()]
        [string]$TimestampServer,

        [ValidateRange(0, 10)]
        [int]$TimestampRetryCount = 3,

        [ValidateRange(0, 60)]
        [int]$TimestampRetryDelaySeconds = 3,

        [ValidateSet('SHA256', 'SHA384', 'SHA512')]
        [string]$DigestAlgorithm = 'SHA256',

        [string]$KeyPath = $script:VbaSecurityKeyPath
    )

    $names = 'TimeStampURL', 'TimeStampRetryCount', 'TimeStampRetryDelay', 'V1HashEnhanced'
    $existing = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($KeyPath)
    $snapshot = [ordered]@{ KeyPath = $KeyPath; KeyExisted = $null -ne $existing; Values = @{} }
    try {
        foreach ($name in $names) {
            $value = if ($existing) { $existing.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } else { $null }
            $snapshot.Values[$name] = if ($null -ne $value) { @{ Value = $value; Kind = $existing.GetValueKind($name) } } else { $null }
        }
    }
    finally {
        if ($existing) {
            $existing.Close()
        }
    }
    if (-not $PSCmdlet.ShouldProcess("HKCU\$KeyPath", 'Set VBA signing values')) {
        return [pscustomobject]$snapshot
    }

    $snapshot = [pscustomobject]$snapshot
    try {
        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($KeyPath)
        try {
            if ($TimestampServer) {
                $key.SetValue('TimeStampURL', $TimestampServer, [Microsoft.Win32.RegistryValueKind]::String)
                $key.SetValue('TimeStampRetryCount', $TimestampRetryCount, [Microsoft.Win32.RegistryValueKind]::DWord)
                $key.SetValue('TimeStampRetryDelay', $TimestampRetryDelaySeconds * 1000, [Microsoft.Win32.RegistryValueKind]::DWord)
            }
            else {
                $key.DeleteValue('TimeStampURL', $false)
            }
            $key.SetValue('V1HashEnhanced', $script:VbaHashValues[$DigestAlgorithm], [Microsoft.Win32.RegistryValueKind]::DWord)
        }
        finally {
            $key.Close()
        }
    }
    catch {
        # A write that fails part of the way leaves earlier writes behind; put the user's values back first.
        Restore-VbaSigningSetting -Snapshot $snapshot -Confirm:$false
        throw
    }
    $snapshot
}

function Restore-VbaSigningSetting {
    <#
    .SYNOPSIS
        Puts back the VBA signing values that Set-VbaSigningSetting saved, and removes the key when it created it.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [object]$Snapshot
    )

    if (-not $PSCmdlet.ShouldProcess("HKCU\$($Snapshot.KeyPath)", 'Restore VBA signing values')) {
        return
    }
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($Snapshot.KeyPath, $true)
    if (-not $key) {
        return
    }
    try {
        foreach ($name in @($Snapshot.Values.Keys)) {
            $saved = $Snapshot.Values[$name]
            if ($saved) {
                $key.SetValue($name, $saved.Value, $saved.Kind)
            }
            else {
                $key.DeleteValue($name, $false)
            }
        }
        $empty = $key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0
    }
    finally {
        $key.Close()
    }
    if (-not $Snapshot.KeyExisted -and $empty) {
        [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKey($Snapshot.KeyPath, $false)
    }
}

function Get-ProcessDialogText {
    <#
    .SYNOPSIS
        Reads the text of the dialogs that a process shows, for a failure message.
    .DESCRIPTION
        Access reports a signing failure in a modal dialog inside its main window and does not exit.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [int]$ProcessId
    )

    try {
        Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
        $automation = [System.Windows.Automation.AutomationElement]
        $byProcess = [System.Windows.Automation.PropertyCondition]::new($automation::ProcessIdProperty, $ProcessId)
        $isWindow = [System.Windows.Automation.PropertyCondition]::new($automation::ControlTypeProperty, [System.Windows.Automation.ControlType]::Window)
        $isText = [System.Windows.Automation.PropertyCondition]::new($automation::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
        $lines = [System.Collections.Generic.List[string]]::new()
        foreach ($top in $automation::RootElement.FindAll([System.Windows.Automation.TreeScope]::Children, $byProcess)) {
            # A dialog can sit inside the main window or be a top-level window of its own.
            $dialogs = if ($top.Current.ClassName -eq '#32770') { @($top) } else { @($top.FindAll([System.Windows.Automation.TreeScope]::Descendants, $isWindow)) }
            foreach ($dialog in $dialogs) {
                foreach ($text in $dialog.FindAll([System.Windows.Automation.TreeScope]::Descendants, $isText)) {
                    $name = ([string]$text.Current.Name).Trim()
                    if ($name -and $name -ne $dialog.Current.Name -and -not $lines.Contains($name)) {
                        $lines.Add($name)
                    }
                }
            }
        }
        ($lines -join ' ') -replace '\s+', ' '
    }
    catch {
        ''
    }
}

function Invoke-AccessFileSigning {
    <#
    .SYNOPSIS
        Signs the VBA project of an Access database with MSACCESS.EXE /sign.
    .DESCRIPTION
        Access reads the certificate from CurrentUser\My, opens the database, signs the project and exits. On a failure
        it shows a dialog and stays open, so a run that does not end within the timeout is stopped and the dialog text
        reported. The timestamp server and digest are passed through the per-user VBA signing values, which are
        restored after the run. The signature itself is not read back: Microsoft does not document where Access
        stores it.
    .OUTPUTS
        Object with Path, Status (Signed, Failed), Detail, Passes, SignatureState, Signer, SignerThumbprint, Timestamped.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath,

        [string]$AccessPath,

        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [ValidateSet('SHA256', 'SHA384', 'SHA512')]
        [string]$DigestAlgorithm = 'SHA256',

        [ValidateSet('None', 'Rfc3161', 'Authenticode')]
        [string]$TimestampMode = 'None',

        [string]$TimestampServer,

        [ValidateRange(0, 10)]
        [int]$TimestampRetryCount = 3,

        [ValidateRange(0, 60)]
        [int]$TimestampRetryDelaySeconds = 3,

        [int]$TimeoutSeconds = 300
    )

    if (-not $Certificate) {
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail 'Access signs only with a certificate from the certificate store.'
    }
    if (-not (Test-CurrentUserCertificate -Thumbprint $Certificate.Thumbprint)) {
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail 'Access reads the certificate from CurrentUser\My only; the selected certificate is not in that store.'
    }
    if (-not $AccessPath -or -not [System.IO.File]::Exists($AccessPath)) {
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail 'Microsoft Access was not found. Access databases are signed by Access itself.'
    }
    $lockFile = Get-AccessLockFilePath -LiteralPath $LiteralPath
    $lockName = [System.IO.Path]::GetFileName($lockFile)
    if ([System.IO.File]::Exists($lockFile)) {
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail "The database is open, or an earlier Access session stopped without closing it ($lockName exists). Close the database in Access. If it is not open, delete $lockName and try again."
    }

    $before = [System.IO.FileInfo]::new($LiteralPath)
    $beforeWrite = $before.LastWriteTimeUtc
    $beforeLength = $before.Length
    $server = if ($TimestampMode -ne 'None') { $TimestampServer } else { '' }
    $snapshot = $null
    try {
        $snapshot = Set-VbaSigningSetting -TimestampServer $server -TimestampRetryCount $TimestampRetryCount -TimestampRetryDelaySeconds $TimestampRetryDelaySeconds -DigestAlgorithm $DigestAlgorithm -Confirm:$false
        $arguments = New-AccessSignArgument -LiteralPath $LiteralPath -Thumbprint $Certificate.Thumbprint
        $run = Invoke-AccessProcess -AccessPath $AccessPath -ArgumentList $arguments -TimeoutSeconds $TimeoutSeconds
    }
    finally {
        if ($snapshot) {
            Restore-VbaSigningSetting -Snapshot $snapshot -Confirm:$false
        }
    }

    if ($run.TimedOut) {
        $reason = if ($run.DialogText) { "Access showed: $($run.DialogText)" } else { "Access did not finish within $TimeoutSeconds seconds." }
        $hint = if ([System.IO.Path]::GetExtension($LiteralPath) -in '.accdb', '.accde') { ' Signing .accdb and .accde files needs Access for Microsoft 365.' } else { '' }
        # A stopped Access cannot remove its lock file. No lock file existed before this run, so the one left is stale.
        $lockNote = ''
        if ([System.IO.File]::Exists($lockFile)) {
            try {
                [System.IO.File]::Delete($lockFile)
            }
            catch {
                $lockNote = " Delete $lockName before the next attempt."
            }
        }
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail "$reason Access was closed before it finished; open the database in Access to check it.$lockNote$hint"
    }
    if ($run.ExitCode -ne 0) {
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail "Access exited with code $($run.ExitCode)."
    }
    $after = [System.IO.FileInfo]::new($LiteralPath)
    if ($after.LastWriteTimeUtc -eq $beforeWrite -and $after.Length -eq $beforeLength) {
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail 'Access closed without changing the database, so it did not sign the VBA project. The database may have no VBA project.'
    }

    $notes = [System.Collections.Generic.List[string]]::new()
    $notes.Add('Access closed without an error and changed the database.')
    if ($server) {
        $notes.Add("A timestamp was requested from $server.")
    }
    $notes.Add('The app cannot read Access VBA signatures; check the signature in the Visual Basic Editor (Tools > Digital Signature).')
    $state = [pscustomobject]@{ State = 'NotChecked'; Signer = $null; Thumbprint = $null; Timestamped = $false }
    New-SigningResult -Path $LiteralPath -Status 'Signed' -Passes 1 -Signature $state -Detail ($notes -join ' ')
}

function Invoke-AccessProcess {
    <#
    .SYNOPSIS
        Starts MSACCESS.EXE, waits for it to exit, and on a timeout reads its dialog text and stops it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessPath,

        [Parameter(Mandatory)]
        [string[]]$ArgumentList,

        [int]$TimeoutSeconds = 300
    )

    $start = [System.Diagnostics.ProcessStartInfo]::new($AccessPath)
    $start.Arguments = (@($ArgumentList | ForEach-Object { ConvertTo-CommandLineArgument -Value $_ }) -join ' ')
    $start.UseShellExecute = $false
    $process = [System.Diagnostics.Process]::Start($start)
    try {
        if ($process.WaitForExit([Math]::Max(1, $TimeoutSeconds) * 1000)) {
            return [pscustomobject]@{ TimedOut = $false; ExitCode = $process.ExitCode; DialogText = '' }
        }
        $text = Get-ProcessDialogText -ProcessId $process.Id
        try {
            $process.Kill()
            [void]$process.WaitForExit(10000)
        }
        catch [System.InvalidOperationException], [System.ComponentModel.Win32Exception] {
            # The process exited between the timeout and the kill.
            if (-not $process.HasExited) {
                throw
            }
        }
        [pscustomobject]@{ TimedOut = $true; ExitCode = $null; DialogText = $text }
    }
    finally {
        $process.Dispose()
    }
}
