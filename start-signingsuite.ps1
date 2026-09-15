#Requires -Version 5.1
<#
.SYNOPSIS
    Signing Suite: signs scripts, executables, installers, catalogs, app packages and Office VBA projects.

.DESCRIPTION
    Drop files or folders onto the window, or use Add files / Add folder. Folders are searched recursively for every
    signable format. Each file shows its format, its current signature and whether it can be signed. Sign signs the
    listed files that are ready or failed and visible under the current filter.

    Signing identities: a code-signing certificate from the certificate store (including smart cards and hardware
    tokens), Azure Artifact Signing, or any digest signing library that signtool.exe loads with /dlib.

    Engines: SignTool (signtool.exe from the Windows SDK) or PowerShell (Set-AuthenticodeSignature). App packages,
    RFC 3161 timestamps, dual signing, Artifact Signing and digest signing libraries need SignTool.

.PARAMETER Path
    Files or folders to list when the window opens.

.EXAMPLE
    powershell.exe -NoProfile -STA -File .\start-signingsuite.ps1

.NOTES
    ScriptName : start-signingsuite.ps1
    Version    : 2026.09.15.0002
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments)]
    [string[]]$Path
)

#region Relaunch
if ($PSVersionTable.PSEdition -ne 'Desktop') {
    # A backslash before a closing quote escapes the quote; doubling trailing backslashes keeps each argument whole.
    $relaunch = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File') +
        @(@($PSCommandPath) + @($Path) | Where-Object { $_ } | ForEach-Object { '"' + ($_ -replace '(\\+)$', '$1$1') + '"' })
    Start-Process -FilePath (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $relaunch
    return
}
#endregion

if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    throw "WPF requires a single-threaded apartment. Start the tool with: powershell.exe -STA -File `"$PSCommandPath`""
}

#region Environment
# Windows PowerShell started from some PowerShell 7 sessions keeps the 7.x module folders in PSModulePath. Importing
# Microsoft.PowerShell.Security then fails with "The member AuditToString is already present", and
# Import-PowerShellDataFile goes missing.
# The Windows PowerShell defaults come first so a user module still takes precedence over a system module of the same name.
$env:PSModulePath = (@(
        @((Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules'), (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'), (Join-Path $PSHOME 'Modules')) +
        @($env:PSModulePath -split ';') +
        @([Environment]::GetEnvironmentVariable('PSModulePath', 'User') -split ';') +
        @([Environment]::GetEnvironmentVariable('PSModulePath', 'Machine') -split ';') |
        Where-Object { $_ -and $_ -notmatch '(?<!Windows)PowerShell\\(7|Modules)' -and $_ -notmatch '\\Microsoft\.PowerShell_' } |
        ForEach-Object -Begin { $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) } -Process {
            $folder = $_.TrimEnd('\')
            if ($seen.Add($folder)) { $folder }
        }
    ) -join ';')
#endregion

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms
Import-Module -Name Microsoft.PowerShell.Security

$script:AppRoot = $PSScriptRoot
$script:ModuleManifest = Join-Path $PSScriptRoot 'Module\SigningSuite\SigningSuite.psd1'
Import-Module -Name $script:ModuleManifest -Force

$script:AppTitle = 'Signing Suite'
$script:AppVersion = (Import-PowerShellDataFile -LiteralPath $script:ModuleManifest).PrivateData.SigningSuiteVersion
$script:ScriptPath = $PSCommandPath
$script:SipDownloadUrl = 'https://www.microsoft.com/download/details.aspx?id=56617'
$script:SdkDownloadUrl = 'https://developer.microsoft.com/windows/downloads/windows-sdk/'
$script:TimestampPattern = '^https?://[^\s]+$'
$script:MainWindow = $null
$script:Job = $null
$script:CloseWhenIdle = $false
$script:StartupDone = $false
$script:SipAction = $null
$script:SignStats = $null
$script:ScanStats = $null
$script:SignTool = $null
$script:Settings = Get-SigningSuiteSettings
$script:Identity = [pscustomobject]@{
    Source          = 'Store'
    Certificate     = $null
    DlibPath        = ''
    MetadataPath    = ''
    CertificateFile = ''
}
$script:Rows = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:RowIndex = @{}

#region Background workers (run in their own runspace; they only talk to the UI through the queue)

$script:ScanWorker = {
    param(
        [string[]]$Paths,
        [string]$ModuleManifest,
        [System.Collections.Concurrent.ConcurrentQueue[object]]$Queue,
        [hashtable]$Cancel
    )

    Import-Module -Name $ModuleManifest -ErrorAction Stop
    Import-Module -Name Microsoft.PowerShell.Security

    $unreadable = 0
    $files = @(Find-SignableFile -Path $Paths -UnreadableCount ([ref]$unreadable))
    $Queue.Enqueue([pscustomobject]@{ Kind = 'ScanTotal'; Total = $files.Count })
    foreach ($file in $files) {
        if ($Cancel.Requested) {
            break
        }
        try {
            $info = Get-SignableFileInfo -LiteralPath $file
        }
        catch {
            $info = [pscustomobject]@{
                Path             = $file
                Name             = [System.IO.Path]::GetFileName($file)
                Folder           = [System.IO.Path]::GetDirectoryName($file)
                Extension        = [System.IO.Path]::GetExtension($file)
                ProviderId       = $null
                Format           = ''
                Status           = 'Skipped'
                Detail           = "Could not examine the file: $($_.Exception.Message)"
                SignatureState   = ''
                Signer           = $null
                SignerThumbprint = $null
                Timestamped      = $false
                Publisher        = $null
            }
        }
        $Queue.Enqueue([pscustomobject]@{ Kind = 'File'; Info = $info })
    }
    $Queue.Enqueue([pscustomobject]@{ Kind = 'ScanDone'; Unreadable = $unreadable; Cancelled = [bool]$Cancel.Requested })
}

$script:SignWorker = {
    param(
        [object[]]$Items,
        [hashtable]$Options,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$ModuleManifest,
        [System.Collections.Concurrent.ConcurrentQueue[object]]$Queue,
        [hashtable]$Cancel
    )

    Import-Module -Name $ModuleManifest -ErrorAction Stop
    Import-Module -Name Microsoft.PowerShell.Security

    foreach ($item in $Items) {
        if ($Cancel.Requested) {
            break
        }
        $parameters = @{
            LiteralPath           = $item.Path
            Engine                = $item.Engine
            DigestAlgorithm       = $Options.DigestAlgorithm
            TimestampMode         = $Options.TimestampMode
            TimestampServer       = $Options.TimestampServer
            DualSign              = [bool]$Options.DualSign
            ClearOfficeSignatures = [bool]$Options.ClearVbaSignatures
            OffClearSigPath       = $Options.OffClearSigPath
            Description           = $Options.Description
            DescriptionUrl        = $Options.DescriptionUrl
            SignToolPath          = $Options.SignToolPath
        }
        if ($Certificate) {
            $parameters.Certificate = $Certificate
        }
        if ($Options.DlibPath) {
            $parameters.DlibPath = $Options.DlibPath
            $parameters.MetadataPath = $Options.MetadataPath
        }
        if ($Options.CertificateFile) {
            $parameters.CertificateFile = $Options.CertificateFile
        }
        try {
            $result = Invoke-FileSigning @parameters
        }
        catch {
            $result = [pscustomobject]@{
                Path             = $item.Path
                Status           = 'Failed'
                Detail           = $_.Exception.Message
                Passes           = 0
                SignatureState   = ''
                Signer           = $null
                SignerThumbprint = $null
                Timestamped      = $false
            }
        }
        $Queue.Enqueue([pscustomobject]@{ Kind = 'Result'; Result = $result })
    }
}

$script:VerifyWorker = {
    param(
        [string[]]$Paths,
        [string]$SignToolPath,
        [string]$ModuleManifest,
        [System.Collections.Concurrent.ConcurrentQueue[object]]$Queue,
        [hashtable]$Cancel
    )

    Import-Module -Name $ModuleManifest -ErrorAction Stop

    foreach ($path in $Paths) {
        if ($Cancel.Requested) {
            break
        }
        try {
            $verification = Test-FileSignature -LiteralPath $path -SignToolPath $SignToolPath
        }
        catch {
            $verification = [pscustomobject]@{
                Path             = $path
                State            = 'Unknown'
                Signer           = $null
                SignerThumbprint = $null
                Timestamped      = $false
                SignatureCount   = $null
                Detail           = "The signature could not be checked: $($_.Exception.Message)"
            }
        }
        $Queue.Enqueue([pscustomobject]@{ Kind = 'Verified'; Verification = $verification })
    }
}

#endregion

#region Shared helpers

function Show-Message {
    param(
        [string]$Text,
        [System.Windows.MessageBoxImage]$Icon = [System.Windows.MessageBoxImage]::Information,
        [System.Windows.MessageBoxButton]$Buttons = [System.Windows.MessageBoxButton]::OK,
        [System.Windows.Window]$Owner = $script:MainWindow
    )

    if ($Owner -and $Owner.IsVisible) {
        return [System.Windows.MessageBox]::Show($Owner, $Text, $script:AppTitle, $Buttons, $Icon)
    }
    [System.Windows.MessageBox]::Show($Text, $script:AppTitle, $Buttons, $Icon)
}

function Invoke-Safely {
    param([scriptblock]$Action)

    try {
        & $Action
    }
    catch {
        [void](Show-Message -Text $_.Exception.Message -Icon Error)
    }
}

function Test-IsElevated {
    $principal = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ComboTag {
    param([System.Windows.Controls.ComboBox]$Combo)

    if ($Combo.SelectedItem -is [System.Windows.Controls.ComboBoxItem]) {
        return [string]$Combo.SelectedItem.Tag
    }
    [string]$Combo.SelectedItem
}

function Select-ComboTag {
    param(
        [System.Windows.Controls.ComboBox]$Combo,
        [string]$Tag
    )

    foreach ($item in $Combo.Items) {
        if ($item -is [System.Windows.Controls.ComboBoxItem] -and [string]$item.Tag -eq $Tag) {
            $Combo.SelectedItem = $item
            return
        }
    }
    $Combo.SelectedIndex = 0
}

function ConvertFrom-XamlWindow {
    param(
        [string]$Xaml,
        [System.Windows.Window]$Owner
    )

    $window = [System.Windows.Markup.XamlReader]::Parse($Xaml)
    if ($Owner -and $Owner.IsVisible) {
        $window.Owner = $Owner
    }
    else {
        $window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::CenterScreen
    }
    $window
}

function Select-OpenFile {
    param(
        [string]$Title,
        [string]$Filter,
        [string]$InitialPath
    )

    $dialog = [Microsoft.Win32.OpenFileDialog]::new()
    $dialog.Title = $Title
    $dialog.Filter = $Filter
    if ($InitialPath -and [System.IO.File]::Exists($InitialPath)) {
        $dialog.InitialDirectory = [System.IO.Path]::GetDirectoryName($InitialPath)
        $dialog.FileName = [System.IO.Path]::GetFileName($InitialPath)
    }
    if ($dialog.ShowDialog() -eq $true) {
        return $dialog.FileName
    }
    $null
}

#endregion

#region Dialogs

$script:PasswordXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Certificate password" Width="440" SizeToContent="Height" ResizeMode="NoResize"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False"
        FontFamily="Segoe UI" FontSize="13" Background="#FFF5F6F8">
  <StackPanel Margin="18">
    <TextBlock x:Name="PromptText" TextWrapping="Wrap" Margin="0,0,0,10"/>
    <PasswordBox x:Name="PasswordInput" Padding="4,3" AutomationProperties.Name="Password"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,18,0,0">
      <Button x:Name="OkButton" Content="Import" IsDefault="True" MinWidth="90" Padding="12,4" Margin="0,0,8,0"/>
      <Button Content="Cancel" IsCancel="True" MinWidth="90" Padding="12,4"/>
    </StackPanel>
  </StackPanel>
</Window>
'@

$script:PickerXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Select signing certificate" Width="980" Height="400" MinWidth="680" MinHeight="300"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False"
        FontFamily="Segoe UI" FontSize="13" Background="#FFF5F6F8">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <TextBlock x:Name="PickerMessage" TextWrapping="Wrap" Margin="0,0,0,10"/>
    <ListView x:Name="CertList" Grid.Row="1" SelectionMode="Single" Background="White" Foreground="#FF1F2933" AutomationProperties.Name="Certificates">
      <ListView.View>
        <GridView>
          <GridViewColumn Header="Issued to" Width="190" DisplayMemberBinding="{Binding IssuedTo}"/>
          <GridViewColumn Header="Issued by" Width="160" DisplayMemberBinding="{Binding IssuedBy}"/>
          <GridViewColumn Header="Expires" Width="86" DisplayMemberBinding="{Binding Expires}"/>
          <GridViewColumn Header="Store" Width="96" DisplayMemberBinding="{Binding StoreLocation}"/>
          <GridViewColumn Header="Key provider" Width="200" DisplayMemberBinding="{Binding KeyProvider}"/>
          <GridViewColumn Header="Thumbprint" Width="320" DisplayMemberBinding="{Binding Thumbprint}"/>
        </GridView>
      </ListView.View>
    </ListView>
    <DockPanel Grid.Row="2" Margin="0,12,0,0" LastChildFill="False">
      <Button x:Name="ImportButton" DockPanel.Dock="Left" Content="_Import .pfx..." MinWidth="110" Padding="12,4"/>
      <Button DockPanel.Dock="Right" Content="Cancel" IsCancel="True" MinWidth="90" Padding="12,4"/>
      <Button x:Name="UseButton" DockPanel.Dock="Right" Content="Use selected" IsDefault="True" MinWidth="110" Padding="12,4" Margin="0,0,8,0"/>
    </DockPanel>
  </Grid>
</Window>
'@

$script:ToolIdentityXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Signing identity" Width="720" SizeToContent="Height" ResizeMode="NoResize"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False"
        FontFamily="Segoe UI" FontSize="13" Background="#FFF5F6F8">
  <StackPanel Margin="18">
    <TextBlock x:Name="IntroText" TextWrapping="Wrap" Margin="0,0,0,12"/>
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="170"/>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
      </Grid.RowDefinitions>
      <TextBlock Text="Digest signing library" VerticalAlignment="Center"/>
      <TextBox x:Name="DlibBox" Grid.Column="1" Margin="0,4" Padding="4,2" AutomationProperties.Name="Digest signing library path"/>
      <Button x:Name="DlibBrowse" Grid.Column="2" Content="Browse..." Margin="8,4,0,4" MinWidth="80" Padding="10,3"/>
      <TextBlock Grid.Row="1" Text="Metadata file" VerticalAlignment="Center"/>
      <TextBox x:Name="MetadataBox" Grid.Row="1" Grid.Column="1" Margin="0,4" Padding="4,2" AutomationProperties.Name="Metadata file path"/>
      <Button x:Name="MetadataBrowse" Grid.Row="1" Grid.Column="2" Content="Browse..." Margin="8,4,0,4" MinWidth="80" Padding="10,3"/>
      <TextBlock x:Name="CertificateLabel" Grid.Row="2" Text="Certificate file (.cer)" VerticalAlignment="Center"/>
      <TextBox x:Name="CertificateBox" Grid.Row="2" Grid.Column="1" Margin="0,4" Padding="4,2" AutomationProperties.Name="Certificate file path"/>
      <Button x:Name="CertificateBrowse" Grid.Row="2" Grid.Column="2" Content="Browse..." Margin="8,4,0,4" MinWidth="80" Padding="10,3"/>
    </Grid>
    <Border x:Name="CreatePanel" Margin="0,14,0,0" Background="White" BorderBrush="#FFD5D9E0" BorderThickness="1" CornerRadius="4" Padding="12,8">
      <StackPanel>
        <TextBlock Text="Create metadata.json" FontWeight="SemiBold" Margin="0,0,0,6"/>
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="158"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock Text="Account endpoint" VerticalAlignment="Center"/>
          <TextBox x:Name="EndpointBox" Grid.Column="1" Margin="0,3" Padding="4,2" ToolTip="https://&lt;region&gt;.codesigning.azure.net/" AutomationProperties.Name="Account endpoint"/>
          <TextBlock Grid.Row="1" Text="Account name" VerticalAlignment="Center"/>
          <TextBox x:Name="AccountBox" Grid.Row="1" Grid.Column="1" Margin="0,3" Padding="4,2" AutomationProperties.Name="Account name"/>
          <TextBlock Grid.Row="2" Text="Certificate profile" VerticalAlignment="Center"/>
          <TextBox x:Name="ProfileBox" Grid.Row="2" Grid.Column="1" Margin="0,3" Padding="4,2" AutomationProperties.Name="Certificate profile"/>
        </Grid>
        <DockPanel Margin="0,8,0,0" LastChildFill="True">
          <Button x:Name="CreateButton" DockPanel.Dock="Right" Content="Save metadata.json..." MinWidth="150" Padding="10,3"/>
          <TextBlock TextWrapping="Wrap" Foreground="#FF5F6B7A" FontSize="11" VerticalAlignment="Center"
                     Text="Sign in first with Azure CLI (az login), Azure PowerShell, Visual Studio, or the AZURE_CLIENT_ID, AZURE_TENANT_ID and AZURE_CLIENT_SECRET environment variables."/>
        </DockPanel>
      </StackPanel>
    </Border>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,18,0,0">
      <Button x:Name="OkButton" Content="Use" IsDefault="True" MinWidth="90" Padding="12,4" Margin="0,0,8,0"/>
      <Button Content="Cancel" IsCancel="True" MinWidth="90" Padding="12,4"/>
    </StackPanel>
  </StackPanel>
</Window>
'@

function Read-PfxPassword {
    param(
        [string]$FileName,
        [System.Windows.Window]$Owner
    )

    $dialog = ConvertFrom-XamlWindow -Xaml $script:PasswordXaml -Owner $Owner
    $passwordInput = $dialog.FindName('PasswordInput')
    $dialog.FindName('PromptText').Text = "Enter the password for $FileName"
    $captured = @{ Password = $null }

    $dialog.FindName('OkButton').Add_Click({
            $captured.Password = $passwordInput.SecurePassword
            $dialog.DialogResult = $true
        })
    $dialog.Add_ContentRendered({ [void]$passwordInput.Focus() })

    if ($dialog.ShowDialog() -eq $true) {
        return $captured.Password
    }
    $null
}

function Invoke-PfxImport {
    param([System.Windows.Window]$Owner)

    $file = Select-OpenFile -Title 'Select the code-signing certificate (.pfx) to import' -Filter 'Certificate with private key (*.pfx;*.p12)|*.pfx;*.p12'
    if (-not $file) {
        return $null
    }
    $password = Read-PfxPassword -FileName ([System.IO.Path]::GetFileName($file)) -Owner $Owner
    if ($null -eq $password) {
        return $null
    }
    try {
        $certificate = Import-PfxToUserStore -Path $file -Password $password
        [void](Show-Message -Owner $Owner -Text "Imported '$($certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false))' into your personal certificate store.")
        return $certificate
    }
    catch {
        [void](Show-Message -Owner $Owner -Icon Error -Text "Import failed: $($_.Exception.Message)")
        return $null
    }
    finally {
        $password.Dispose()
    }
}

function Show-CertificatePicker {
    param([System.Windows.Window]$Owner)

    $dialog = ConvertFrom-XamlWindow -Xaml $script:PickerXaml -Owner $Owner
    $list = $dialog.FindName('CertList')
    $message = $dialog.FindName('PickerMessage')
    $useButton = $dialog.FindName('UseButton')
    $state = @{ Selected = $null }

    $refresh = {
        param([string]$SelectThumbprint)

        $labels = @(Get-SigningCertificate -StoreLocation CurrentUser, LocalMachine | ForEach-Object { Get-CertificateLabel -Certificate $_ })
        $list.ItemsSource = $labels
        $useButton.IsEnabled = $labels.Count -gt 0
        if ($labels.Count -eq 0) {
            $message.Text = 'No valid code-signing certificate with a private key is in the personal certificate stores. Import a .pfx file, or connect the smart card or token that holds the certificate.'
            return
        }
        $message.Text = "Select the certificate to sign with ($($labels.Count) available). Certificates on smart cards and tokens may ask for a PIN when signing."
        $list.SelectedIndex = 0
        foreach ($label in $labels) {
            if ($label.Thumbprint -eq $SelectThumbprint) {
                $list.SelectedItem = $label
            }
        }
    }

    $accept = {
        if ($list.SelectedItem) {
            $state.Selected = $list.SelectedItem.Certificate
            $dialog.DialogResult = $true
        }
    }
    $useButton.Add_Click($accept)
    $list.Add_MouseDoubleClick($accept)
    $dialog.FindName('ImportButton').Add_Click({
            $imported = Invoke-PfxImport -Owner $dialog
            if ($imported) {
                & $refresh $imported.Thumbprint
            }
        })

    $current = if ($script:Identity.Certificate) { $script:Identity.Certificate.Thumbprint } else { '' }
    & $refresh $current
    $dialog.Add_ContentRendered({ [void]$list.Focus() })
    if ($dialog.ShowDialog() -eq $true) {
        return $state.Selected
    }
    $null
}

function Show-ToolIdentityDialog {
    <#
    .SYNOPSIS
        Collects the digest signing library, metadata file and optional certificate file for Artifact Signing or a generic dlib.
    #>
    param(
        [ValidateSet('ArtifactSigning', 'Dlib')]
        [string]$Source,
        [System.Windows.Window]$Owner
    )

    $dialog = ConvertFrom-XamlWindow -Xaml $script:ToolIdentityXaml -Owner $Owner
    $controls = @{}
    foreach ($name in 'IntroText', 'DlibBox', 'DlibBrowse', 'MetadataBox', 'MetadataBrowse', 'CertificateLabel', 'CertificateBox', 'CertificateBrowse',
        'CreatePanel', 'EndpointBox', 'AccountBox', 'ProfileBox', 'CreateButton', 'OkButton') {
        $controls[$name] = $dialog.FindName($name)
    }
    $result = @{ Value = $null }

    if ($Source -eq 'ArtifactSigning') {
        $dialog.Title = 'Artifact Signing'
        $controls.IntroText.Text = 'Artifact Signing signs through signtool.exe with the Azure.CodeSigning.Dlib.dll from the Artifact Signing Client Tools and a metadata.json naming the account and certificate profile. The certificate comes from the service. Use http://timestamp.acs.microsoft.com as the RFC 3161 timestamp server.'
        $controls.DlibBox.Text = if ($script:Settings.ArtifactDlibPath) { $script:Settings.ArtifactDlibPath } else { [string](Find-ArtifactSigningDlib) }
        $controls.MetadataBox.Text = $script:Settings.ArtifactMetadataPath
        $controls.CertificateLabel.Visibility = 'Collapsed'
        $controls.CertificateBox.Visibility = 'Collapsed'
        $controls.CertificateBrowse.Visibility = 'Collapsed'
    }
    else {
        $dialog.Title = 'Digest signing library'
        $controls.IntroText.Text = 'signtool.exe loads the library with /dlib and passes the metadata file with /dmdf. The library signs the digest with a key it holds, such as an HSM or a cloud key service. Name the public certificate (.cer) unless the library supplies it.'
        $controls.DlibBox.Text = $script:Settings.DlibPath
        $controls.MetadataBox.Text = $script:Settings.DlibMetadataPath
        $controls.CertificateBox.Text = $script:Settings.DlibCertificateFile
        $controls.CreatePanel.Visibility = 'Collapsed'
    }

    $controls.DlibBrowse.Add_Click({
            $picked = Select-OpenFile -Title 'Select the digest signing library' -Filter 'Library (*.dll)|*.dll' -InitialPath $controls.DlibBox.Text
            if ($picked) { $controls.DlibBox.Text = $picked }
        })
    $controls.MetadataBrowse.Add_Click({
            $picked = Select-OpenFile -Title 'Select the metadata file' -Filter 'Metadata (*.json;*.txt)|*.json;*.txt|All files (*.*)|*.*' -InitialPath $controls.MetadataBox.Text
            if ($picked) { $controls.MetadataBox.Text = $picked }
        })
    $controls.CertificateBrowse.Add_Click({
            $picked = Select-OpenFile -Title 'Select the signing certificate' -Filter 'Certificate (*.cer;*.crt)|*.cer;*.crt' -InitialPath $controls.CertificateBox.Text
            if ($picked) { $controls.CertificateBox.Text = $picked }
        })
    $controls.CreateButton.Add_Click({
            try {
                $save = [Microsoft.Win32.SaveFileDialog]::new()
                $save.Title = 'Save Artifact Signing metadata'
                $save.Filter = 'JSON (*.json)|*.json'
                $save.FileName = 'metadata.json'
                $save.InitialDirectory = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)) 'SigningSuite'
                [void][System.IO.Directory]::CreateDirectory($save.InitialDirectory)
                if ($save.ShowDialog($dialog) -eq $true) {
                    $item = New-ArtifactSigningMetadata -Path $save.FileName -Endpoint $controls.EndpointBox.Text.Trim() -AccountName $controls.AccountBox.Text.Trim() -CertificateProfileName $controls.ProfileBox.Text.Trim()
                    $controls.MetadataBox.Text = $item.FullName
                }
            }
            catch {
                [void](Show-Message -Owner $dialog -Icon Error -Text "The metadata file was not saved: $($_.Exception.Message)")
            }
        })
    $controls.OkButton.Add_Click({
            $dlib = $controls.DlibBox.Text.Trim()
            $metadata = $controls.MetadataBox.Text.Trim()
            $certificateFile = $controls.CertificateBox.Text.Trim()
            $problems = @()
            if (-not $dlib -or -not [System.IO.File]::Exists($dlib)) { $problems += 'Choose an existing digest signing library.' }
            if ($Source -eq 'ArtifactSigning' -and (-not $metadata -or -not [System.IO.File]::Exists($metadata))) { $problems += 'Choose or create the metadata.json file.' }
            if ($Source -eq 'Dlib' -and $metadata -and -not [System.IO.File]::Exists($metadata)) { $problems += 'The metadata file does not exist.' }
            if ($Source -eq 'Dlib' -and $certificateFile -and -not [System.IO.File]::Exists($certificateFile)) { $problems += 'The certificate file does not exist.' }
            if ($problems.Count -gt 0) {
                [void](Show-Message -Owner $dialog -Icon Warning -Text ($problems -join "`n"))
                return
            }
            $result.Value = [pscustomobject]@{ DlibPath = $dlib; MetadataPath = $metadata; CertificateFile = $certificateFile }
            $dialog.DialogResult = $true
        })

    $dialog.Add_ContentRendered({ [void]$controls.DlibBox.Focus() })
    if ($dialog.ShowDialog() -eq $true) {
        return $result.Value
    }
    $null
}

#endregion

#region Background job plumbing

$script:JobTimer = [System.Windows.Threading.DispatcherTimer]::new()
$script:JobTimer.Interval = [TimeSpan]::FromMilliseconds(120)

function Invoke-BackgroundJob {
    param(
        [scriptblock]$Worker,
        [hashtable]$Parameters,
        [scriptblock]$OnMessage,
        [scriptblock]$OnComplete
    )

    $queue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    $cancel = [hashtable]::Synchronized(@{ Requested = $false })
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = [System.Threading.ApartmentState]::STA
    $runspace.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $runspace.Open()

    $powershell = [powershell]::Create()
    $powershell.Runspace = $runspace
    # Added as text so the worker binds to its own runspace; UI objects never cross threads.
    [void]$powershell.AddScript($Worker.ToString())
    foreach ($name in $Parameters.Keys) {
        [void]$powershell.AddParameter($name, $Parameters[$name])
    }
    [void]$powershell.AddParameter('Queue', $queue)
    [void]$powershell.AddParameter('Cancel', $cancel)

    $script:Job = [pscustomobject]@{
        PowerShell   = $powershell
        Runspace     = $runspace
        Queue        = $queue
        Cancel       = $cancel
        OnMessage    = $OnMessage
        OnComplete   = $OnComplete
        MessageError = $null
        Handle       = $powershell.BeginInvoke()
    }
    $script:JobTimer.Start()
}

function Receive-BackgroundJob {
    $job = $script:Job
    if ($null -eq $job) {
        $script:JobTimer.Stop()
        return
    }

    # Sampled before draining: once the pipeline has completed, every message is already queued.
    $finished = $job.Handle.IsCompleted
    $message = $null
    $drained = 0
    while ($drained -lt 500 -and $job.Queue.TryDequeue([ref]$message)) {
        $drained++
        try {
            & $job.OnMessage $message
        }
        catch {
            if (-not $job.MessageError) {
                $job.MessageError = $_.Exception.Message
            }
        }
    }
    if (-not $finished -or -not $job.Queue.IsEmpty) {
        return
    }

    $script:JobTimer.Stop()
    $script:Job = $null
    $failure = $job.MessageError
    try {
        [void]$job.PowerShell.EndInvoke($job.Handle)
        if (-not $failure -and $job.PowerShell.Streams.Error.Count -gt 0) {
            $failure = $job.PowerShell.Streams.Error[0].ToString()
        }
    }
    catch {
        $failure = $_.Exception.Message
    }
    finally {
        $job.PowerShell.Dispose()
        $job.Runspace.Dispose()
    }
    & $job.OnComplete $failure ([bool]$job.Cancel.Requested)
    if ($script:CloseWhenIdle -and $script:MainWindow) {
        $script:MainWindow.Close()
    }
}

$script:JobTimer.Add_Tick({
        try {
            Receive-BackgroundJob
        }
        catch {
            [void](Show-Message -Icon Error -Text "Background task error: $($_.Exception.Message)")
        }
    })

function Stop-BackgroundJob {
    if ($script:Job) {
        $script:Job.Cancel.Requested = $true
        $script:ui.CancelButton.IsEnabled = $false
        $script:ui.SummaryText.Text = 'Stopping after the current file...'
    }
}

#endregion

#region Main window

$script:MainXaml = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'MainWindow.xaml'))

function ConvertTo-FileRow {
    param([object]$Info)

    [pscustomobject]@{
        Status           = $Info.Status
        Name             = $Info.Name
        Format           = $Info.Format
        ProviderId       = $Info.ProviderId
        SignatureState   = $Info.SignatureState
        Signer           = $Info.Signer
        SignerThumbprint = $Info.SignerThumbprint
        Timestamped      = [bool]$Info.Timestamped
        SignatureText    = ConvertTo-SignatureText -State $Info.SignatureState -Signer $Info.Signer
        Detail           = $Info.Detail
        Folder           = $Info.Folder
        Path             = $Info.Path
    }
}

function Set-FileRow {
    param([object]$Row)

    if ($script:RowIndex.ContainsKey($Row.Path)) {
        $script:Rows[$script:RowIndex[$Row.Path]] = $Row
    }
    else {
        $script:RowIndex[$Row.Path] = $script:Rows.Count
        $script:Rows.Add($Row)
    }
}

function Update-FileRow {
    param(
        [string]$Path,
        [hashtable]$Changes
    )

    if (-not $script:RowIndex.ContainsKey($Path)) {
        return
    }
    $old = $script:Rows[$script:RowIndex[$Path]]
    $copy = [ordered]@{}
    foreach ($property in $old.PSObject.Properties) {
        $copy[$property.Name] = $property.Value
    }
    foreach ($key in $Changes.Keys) {
        $copy[$key] = $Changes[$key]
    }
    $copy.SignatureText = ConvertTo-SignatureText -State $copy.SignatureState -Signer $copy.Signer
    $script:Rows[$script:RowIndex[$Path]] = [pscustomobject]$copy
}

function Reset-RowIndex {
    $script:RowIndex.Clear()
    for ($i = 0; $i -lt $script:Rows.Count; $i++) {
        $script:RowIndex[$script:Rows[$i].Path] = $i
    }
}

function Test-RowVisible {
    param([object]$Row)

    $format = Get-ComboTag -Combo $script:ui.FormatFilter
    if ($format -and $format -ne 'All' -and $Row.ProviderId -ne $format) {
        return $false
    }
    $status = Get-ComboTag -Combo $script:ui.StatusFilter
    if ($status -and $status -ne 'All' -and $Row.Status -ne $status) {
        return $false
    }
    $search = $script:ui.SearchBox.Text
    if ($search -and $Row.Path.IndexOf($search, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        return $false
    }
    $true
}

function Get-VisibleRows {
    @($script:Rows | Where-Object { Test-RowVisible -Row $_ })
}

function Get-SigningCandidates {
    $skipValid = [bool]$script:ui.SkipValidCheck.IsChecked
    $timestampMode = Get-ComboTag -Combo $script:ui.TimestampModeCombo
    if ($timestampMode -notin 'None', 'Rfc3161', 'Authenticode') {
        $timestampMode = 'None'
    }
    $pending = @()
    $skippedValid = 0
    foreach ($row in Get-VisibleRows) {
        if ($row.Status -ne 'Ready' -and $row.Status -ne 'Failed') {
            continue
        }
        if ($skipValid -and $row.Status -eq 'Ready' -and (Test-SkipValidSignature -SignatureState $row.SignatureState -Timestamped ([bool]$row.Timestamped) -TimestampMode $timestampMode)) {
            $skippedValid++
            continue
        }
        $pending += $row
    }
    [pscustomobject]@{ Rows = $pending; SkippedValid = $skippedValid }
}

function Test-IdentityReady {
    switch ($script:Identity.Source) {
        'Store' { return $null -ne $script:Identity.Certificate }
        default { return [bool]$script:Identity.DlibPath }
    }
}

function Sync-Controls {
    $counts = @{ Ready = 0; Signed = 0; Failed = 0; Skipped = 0 }
    foreach ($row in $script:Rows) {
        if ($counts.ContainsKey($row.Status)) {
            $counts[$row.Status]++
        }
    }
    $candidates = Get-SigningCandidates
    $pending = @($candidates.Rows).Count
    $idle = $null -eq $script:Job
    $script:ui.SignButton.Content = if ($pending -eq 1) { 'Sign 1 file' } else { "Sign $pending files" }
    $script:ui.SignButton.IsEnabled = $idle -and $pending -gt 0 -and (Test-IdentityReady)
    $script:ui.VerifyButton.IsEnabled = $idle -and $script:Rows.Count -gt 0
    $script:ui.ExportButton.IsEnabled = $idle -and $script:Rows.Count -gt 0
    $script:ui.RescanButton.IsEnabled = $idle -and $script:Rows.Count -gt 0
    $script:ui.RemoveButton.IsEnabled = $idle -and $script:ui.FileGrid.SelectedItems.Count -gt 0
    $visible = @(Get-VisibleRows).Count
    $script:ui.FilterCountText.Text = if ($visible -eq $script:Rows.Count) { "$($script:Rows.Count) files" } else { "$visible of $($script:Rows.Count) files shown" }

    if ($idle) {
        if ($script:Rows.Count -eq 0) {
            $script:ui.SummaryText.Text = 'No files added yet.'
        }
        else {
            $text = "$($script:Rows.Count) files: $($counts.Ready) ready, $($counts.Signed) signed, $($counts.Failed) failed, $($counts.Skipped) skipped"
            if ($candidates.SkippedValid -gt 0) {
                $text += "; $($candidates.SkippedValid) already validly signed"
            }
            $script:ui.SummaryText.Text = $text
        }
    }
    Show-SipStatus
}

function Switch-BusyState {
    param(
        [bool]$Busy,
        [int]$Maximum = 0
    )

    foreach ($name in 'AddFilesButton', 'AddFolderButton', 'ClearButton', 'ChangeIdentityButton', 'SourceCombo', 'OptionsExpander', 'SipActionButton', 'SignToolActionButton') {
        $script:ui[$name].IsEnabled = -not $Busy
    }
    $script:ui.CancelButton.IsEnabled = $Busy
    $progress = $script:ui.Progress
    $progress.IsIndeterminate = $Busy -and $Maximum -eq 0
    $progress.Maximum = [Math]::Max(1, $Maximum)
    $progress.Value = 0
    $progress.Visibility = if ($Busy) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Hidden }
    Sync-Controls
}

function Update-IdentityDisplay {
    $ui = $script:ui
    $ui.IdentityText.ClearValue([System.Windows.Controls.TextBlock]::ForegroundProperty)
    switch ($script:Identity.Source) {
        'Store' {
            $ui.IdentityCaption.Text = 'Signing certificate'
            $certificate = $script:Identity.Certificate
            if ($certificate) {
                $label = Get-CertificateLabel -Certificate $certificate
                $ui.IdentityText.Text = $label.IssuedTo
                $provider = if ($label.KeyProvider) { "   |   Key $($label.KeyProvider)" } else { '' }
                $ui.IdentityDetailText.Text = "Issued by $($label.IssuedBy)   |   Expires $($label.Expires)   |   $($label.StoreLocation)   |   Thumbprint $($label.Thumbprint)$provider"
            }
            else {
                $ui.IdentityText.Text = 'No signing certificate selected'
                $ui.IdentityText.Foreground = [System.Windows.Media.Brushes]::Firebrick
                $ui.IdentityDetailText.Text = 'Choose Change... to select or import a code-signing certificate.'
            }
        }
        'ArtifactSigning' {
            $ui.IdentityCaption.Text = 'Artifact Signing'
            if ($script:Identity.DlibPath) {
                $ui.IdentityText.Text = [System.IO.Path]::GetFileName($script:Identity.MetadataPath)
                $ui.IdentityDetailText.Text = "Metadata $($script:Identity.MetadataPath)   |   Library $($script:Identity.DlibPath)"
            }
            else {
                $ui.IdentityText.Text = 'Artifact Signing is not set up'
                $ui.IdentityText.Foreground = [System.Windows.Media.Brushes]::Firebrick
                $ui.IdentityDetailText.Text = 'Choose Change... to pick the client library and metadata.json.'
            }
        }
        'Dlib' {
            $ui.IdentityCaption.Text = 'Digest signing library'
            if ($script:Identity.DlibPath) {
                $ui.IdentityText.Text = [System.IO.Path]::GetFileName($script:Identity.DlibPath)
                $certificateText = if ($script:Identity.CertificateFile) { "Certificate $($script:Identity.CertificateFile)" } else { 'Certificate supplied by the library' }
                $ui.IdentityDetailText.Text = "$certificateText   |   Metadata $($script:Identity.MetadataPath)   |   Library $($script:Identity.DlibPath)"
            }
            else {
                $ui.IdentityText.Text = 'No digest signing library selected'
                $ui.IdentityText.Foreground = [System.Windows.Media.Brushes]::Firebrick
                $ui.IdentityDetailText.Text = 'Choose Change... to pick the library, its metadata file and the certificate.'
            }
        }
    }
    Update-EngineInfo
    Sync-Controls
}

function Set-IdentitySource {
    param([string]$Source)

    $script:Identity.Source = $Source
    switch ($Source) {
        'Store' {
            if (-not $script:Identity.Certificate) {
                $certificates = @(Get-SigningCertificate -StoreLocation CurrentUser, LocalMachine)
                $saved = $certificates | Where-Object Thumbprint -eq $script:Settings.CertificateThumbprint | Select-Object -First 1
                if ($saved) {
                    $script:Identity.Certificate = $saved
                }
                elseif ($certificates.Count -eq 1) {
                    $script:Identity.Certificate = $certificates[0]
                }
            }
            $script:Identity.DlibPath = ''
            $script:Identity.MetadataPath = ''
            $script:Identity.CertificateFile = ''
        }
        'ArtifactSigning' {
            $dlib = if ($script:Settings.ArtifactDlibPath -and [System.IO.File]::Exists($script:Settings.ArtifactDlibPath)) { $script:Settings.ArtifactDlibPath } else { [string](Find-ArtifactSigningDlib) }
            $metadata = $script:Settings.ArtifactMetadataPath
            $ready = $dlib -and $metadata -and [System.IO.File]::Exists($metadata)
            $script:Identity.DlibPath = if ($ready) { $dlib } else { '' }
            $script:Identity.MetadataPath = if ($ready) { $metadata } else { '' }
            $script:Identity.CertificateFile = ''
        }
        'Dlib' {
            $ready = $script:Settings.DlibPath -and [System.IO.File]::Exists($script:Settings.DlibPath)
            $script:Identity.DlibPath = if ($ready) { $script:Settings.DlibPath } else { '' }
            $script:Identity.MetadataPath = if ($ready) { $script:Settings.DlibMetadataPath } else { '' }
            $script:Identity.CertificateFile = if ($ready) { $script:Settings.DlibCertificateFile } else { '' }
        }
    }
    Update-IdentityDisplay
}

function Invoke-ChangeIdentity {
    switch ($script:Identity.Source) {
        'Store' {
            $picked = Show-CertificatePicker -Owner $script:MainWindow
            if ($picked) {
                $script:Identity.Certificate = $picked
                $script:Settings.CertificateThumbprint = $picked.Thumbprint
            }
        }
        'ArtifactSigning' {
            $picked = Show-ToolIdentityDialog -Source ArtifactSigning -Owner $script:MainWindow
            if ($picked) {
                $script:Settings.ArtifactDlibPath = $picked.DlibPath
                $script:Settings.ArtifactMetadataPath = $picked.MetadataPath
                $script:Identity.DlibPath = $picked.DlibPath
                $script:Identity.MetadataPath = $picked.MetadataPath
                if ($script:ui.TimestampBox.Text.Trim() -eq 'http://timestamp.digicert.com') {
                    $answer = Show-Message -Icon Question -Buttons YesNo -Text 'Use the Artifact Signing timestamp server (http://timestamp.acs.microsoft.com) with RFC 3161 timestamps? Artifact Signing certificates are valid for three days, so signatures need a timestamp to stay valid.'
                    if ($answer -eq [System.Windows.MessageBoxResult]::Yes) {
                        $script:ui.TimestampBox.Text = 'http://timestamp.acs.microsoft.com'
                        Select-ComboTag -Combo $script:ui.TimestampModeCombo -Tag 'Rfc3161'
                    }
                }
            }
        }
        'Dlib' {
            $picked = Show-ToolIdentityDialog -Source Dlib -Owner $script:MainWindow
            if ($picked) {
                $script:Settings.DlibPath = $picked.DlibPath
                $script:Settings.DlibMetadataPath = $picked.MetadataPath
                $script:Settings.DlibCertificateFile = $picked.CertificateFile
                $script:Identity.DlibPath = $picked.DlibPath
                $script:Identity.MetadataPath = $picked.MetadataPath
                $script:Identity.CertificateFile = $picked.CertificateFile
            }
        }
    }
    Update-IdentityDisplay
}

function Update-SignToolState {
    $script:SignTool = Find-SignTool -ConfiguredPath $script:Settings.SignToolPath
    if ($script:SignTool) {
        $script:ui.SignToolBanner.Visibility = [System.Windows.Visibility]::Collapsed
    }
    else {
        $script:ui.SignToolText.Text = 'signtool.exe was not found. Install the Windows SDK signing tools or choose signtool.exe. App packages, RFC 3161 timestamps, dual signing, Artifact Signing and digest signing libraries need it; other files sign with the PowerShell engine.'
        $script:ui.SignToolBanner.Visibility = [System.Windows.Visibility]::Visible
    }
    Update-EngineInfo
}

function Update-EngineInfo {
    if (-not $script:ui) {
        return
    }
    $requested = Get-ComboTag -Combo $script:ui.EngineCombo
    $toolText = if ($script:SignTool) { "SignTool $($script:SignTool.Version) ($($script:SignTool.Path))" } else { 'SignTool not found' }
    $script:ui.EngineInfoText.Text = switch ($requested) {
        'SignTool' { $toolText }
        'PowerShell' { 'PowerShell Set-AuthenticodeSignature: Authenticode timestamps only, one signature per file.' }
        default {
            if ($script:SignTool) { "Automatic: $toolText" } else { 'Automatic: PowerShell Set-AuthenticodeSignature, because signtool.exe was not found.' }
        }
    }
}

function Show-SipStatus {
    $hasOffice = $false
    foreach ($row in $script:Rows) {
        if ($row.ProviderId -eq 'OfficeVba') {
            $hasOffice = $true
            break
        }
    }
    if (-not $hasOffice) {
        $script:SipAction = $null
        $script:ui.SipBanner.Visibility = [System.Windows.Visibility]::Collapsed
        return
    }

    $processIs64 = [Environment]::Is64BitProcess
    $registrations = @(Get-OfficeSipStatus)
    $current = $registrations | Where-Object { $_.Is64Bit -eq $processIs64 } | Select-Object -First 1
    $other = $registrations | Where-Object { $_.Is64Bit -ne $processIs64 } | Select-Object -First 1
    $bits = if ($processIs64) { '64-bit' } else { '32-bit' }
    $currentAny = $current -and ($current.OpenXml -or $current.Legacy)
    $otherAny = $other -and ($other.OpenXml -or $other.Legacy)

    if ($current -and $current.OpenXml -and $current.Legacy) {
        $script:SipAction = $null
        $script:ui.SipBanner.Visibility = [System.Windows.Visibility]::Collapsed
        return
    }
    if (-not $currentAny -and $otherAny) {
        $otherBits = if ($other.Is64Bit) { '64-bit' } else { '32-bit' }
        $script:SipAction = 'Relaunch'
        $script:ui.SipText.Text = "The Office signing add-in (SIP) is registered for $otherBits processes only, and this is $bits PowerShell. Office files fail to sign until the tool runs in $otherBits Windows PowerShell."
        $script:ui.SipActionButton.Content = "Restart as $otherBits"
    }
    elseif (-not $currentAny) {
        $script:SipAction = 'Download'
        $script:ui.SipText.Text = "The Office signing add-in (SIP) is not registered for $bits processes on this PC. Install 'Microsoft Office Subject Interface Packages for Digitally Signing VBA Projects' ($bits build) and register msosipx.dll and msosip.dll with regsvr32 as its readme describes."
        $script:ui.SipActionButton.Content = 'Open download page'
    }
    else {
        $missing = if (-not $current.OpenXml) { 'msosipx.dll (.xlsm, .docm, .pptm and other macro-enabled Open XML files)' } else { 'msosip.dll (.xls, .doc, .ppt and other binary Office files)' }
        $script:SipAction = 'Download'
        $script:ui.SipText.Text = "Part of the Office signing add-in (SIP) is not registered for $bits processes: $missing. Files of those types fail to sign."
        $script:ui.SipActionButton.Content = 'Open download page'
    }
    $script:ui.SipBanner.Visibility = [System.Windows.Visibility]::Visible
}

function Invoke-BitnessRelaunch {
    if (-not $script:ScriptPath) {
        [void](Show-Message -Icon Warning -Text 'Start the tool from its .ps1 file to use Restart.')
        return
    }
    $folder = if ([Environment]::Is64BitProcess) { 'SysWOW64' } else { 'Sysnative' }
    $powershellExe = Join-Path -Path $env:windir -ChildPath "$folder\WindowsPowerShell\v1.0\powershell.exe"
    $arguments = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File') +
        @(@($script:ScriptPath) + @($script:Rows | ForEach-Object { $_.Path }) | ForEach-Object { ConvertTo-CommandLineArgument -Value $_ })
    Save-CurrentSettings
    Start-Process -FilePath $powershellExe -ArgumentList $arguments
    $script:MainWindow.Close()
}

function Add-InputPath {
    param([string[]]$Path)

    $paths = @($Path | Where-Object { $_ })
    if ($script:Job -or $paths.Count -eq 0) {
        return
    }
    Start-Scan -Paths $paths -Replace $false
}

function Start-Scan {
    param(
        [string[]]$Paths,
        [bool]$Replace
    )

    $script:ScanStats = @{ Added = 0; Updated = 0; Total = 0; Unreadable = 0; Replace = $Replace }
    Switch-BusyState -Busy $true
    $script:ui.SummaryText.Text = 'Searching for signable files...'

    Invoke-BackgroundJob -Worker $script:ScanWorker -Parameters @{
        Paths          = [string[]]$Paths
        ModuleManifest = $script:ModuleManifest
    } -OnMessage {
        param($Message)

        $stats = $script:ScanStats
        switch ($Message.Kind) {
            'ScanTotal' {
                $stats.Total = $Message.Total
                $script:ui.Progress.IsIndeterminate = $false
                $script:ui.Progress.Maximum = [Math]::Max(1, $Message.Total)
            }
            'File' {
                $row = ConvertTo-FileRow -Info $Message.Info
                if ($script:RowIndex.ContainsKey($row.Path)) {
                    if ($stats.Replace) {
                        Set-FileRow -Row $row
                        $stats.Updated++
                    }
                }
                else {
                    Set-FileRow -Row $row
                    $stats.Added++
                }
                $script:ui.Progress.Value = $stats.Added + $stats.Updated
                $script:ui.SummaryText.Text = "Examining files... $($stats.Added + $stats.Updated) of $($stats.Total)"
            }
            'ScanDone' {
                $stats.Unreadable = $Message.Unreadable
            }
        }
    } -OnComplete {
        param($Failure, $Cancelled)

        Switch-BusyState -Busy $false
        $stats = $script:ScanStats
        $notes = @()
        if (-not $stats.Replace -and $stats.Added -eq 0 -and -not $Cancelled -and -not $Failure) {
            $notes += 'No new signable files were found.'
        }
        if ($stats.Unreadable -gt 0) {
            $notes += "$($stats.Unreadable) items could not be read (access denied, missing, or path too long)."
        }
        if ($Failure) {
            $notes += "Search error: $Failure"
        }
        if ($notes.Count -gt 0) {
            [void](Show-Message -Icon Warning -Text ($notes -join "`n"))
        }
    }
}

function Get-SigningOptions {
    $source = $script:Identity.Source
    $timestampMode = Get-ComboTag -Combo $script:ui.TimestampModeCombo
    $timestamp = $script:ui.TimestampBox.Text.Trim()
    if ($timestampMode -eq 'None') {
        $timestamp = ''
    }
    $offClear = $null
    $sip = Get-OfficeSipStatus | Where-Object { $_.Is64Bit -eq [Environment]::Is64BitProcess } | Select-Object -First 1
    if ($sip) {
        $offClear = $sip.OffClearSigPath
    }
    @{
        Source             = $source
        DigestAlgorithm    = Get-ComboTag -Combo $script:ui.DigestCombo
        TimestampMode      = $timestampMode
        TimestampServer    = $timestamp
        DualSign           = [bool]$script:ui.DualSignCheck.IsChecked
        ClearVbaSignatures = [bool]$script:ui.ClearVbaCheck.IsChecked
        OffClearSigPath    = $offClear
        Description        = $script:ui.DescriptionBox.Text.Trim()
        DescriptionUrl     = $script:ui.DescriptionUrlBox.Text.Trim()
        SignToolPath       = if ($script:SignTool) { $script:SignTool.Path } else { '' }
        DlibPath           = if ($source -ne 'Store') { $script:Identity.DlibPath } else { '' }
        MetadataPath       = if ($source -ne 'Store') { $script:Identity.MetadataPath } else { '' }
        CertificateFile    = if ($source -eq 'Dlib') { $script:Identity.CertificateFile } else { '' }
    }
}

function Invoke-Signing {
    if ($script:Job -or -not (Test-IdentityReady)) {
        return
    }

    $options = Get-SigningOptions
    if ($options.Source -eq 'Store' -and $script:Identity.Certificate.NotAfter -le (Get-Date)) {
        [void](Show-Message -Icon Warning -Text 'The selected certificate has expired. Choose Change... to select another one.')
        return
    }
    if ($options.TimestampMode -ne 'None' -and $options.TimestampServer -notmatch $script:TimestampPattern) {
        [void](Show-Message -Icon Warning -Text 'The timestamp server must start with http:// or https://, or choose None as the timestamp type.')
        return
    }
    if ($options.DescriptionUrl -and $options.DescriptionUrl -notmatch $script:TimestampPattern) {
        [void](Show-Message -Icon Warning -Text 'The description URL must start with http:// or https://.')
        return
    }

    $candidates = Get-SigningCandidates
    $rows = @($candidates.Rows)
    if ($rows.Count -eq 0) {
        return
    }

    $requested = Get-ComboTag -Combo $script:ui.EngineCombo
    $items = [System.Collections.Generic.List[object]]::new()
    $notAttempted = 0
    $officeCount = 0
    foreach ($row in $rows) {
        $provider = if ($row.ProviderId) { Get-FormatProvider -Id $row.ProviderId } else { $null }
        if (-not $provider) {
            Update-FileRow -Path $row.Path -Changes @{ Status = 'Skipped'; Detail = 'Not a signable file type.' }
            $notAttempted++
            continue
        }
        $engine = Resolve-SigningEngine -Provider $provider -Requested $requested -SignToolAvailable ([bool]$script:SignTool) -Source $options.Source -TimestampMode $options.TimestampMode
        if (-not $engine.Engine) {
            Update-FileRow -Path $row.Path -Changes @{ Status = 'Failed'; Detail = "Not signed: $($engine.Reason)" }
            $notAttempted++
            continue
        }
        if ($provider.Id -eq 'OfficeVba') {
            $officeCount++
        }
        $items.Add([pscustomobject]@{ Path = $row.Path; Engine = $engine.Engine })
    }

    if ($items.Count -eq 0) {
        Sync-Controls
        [void](Show-Message -Icon Warning -Text 'No files were signed; the Details column shows why.')
        return
    }
    if ($options.ClearVbaSignatures -and $officeCount -gt 0) {
        $answer = Show-Message -Icon Warning -Buttons YesNo -Text "Existing VBA signatures in $officeCount Office file(s) will be removed before signing. Files that fail to sign afterwards are left without a VBA signature. Continue?"
        if ($answer -ne [System.Windows.MessageBoxResult]::Yes) {
            Sync-Controls
            return
        }
    }

    $script:SignStats = @{
        Total        = $rows.Count
        Done         = $notAttempted
        Signed       = 0
        Failed       = 0
        Skipped      = 0
        NotAttempted = $notAttempted
        SkippedValid = $candidates.SkippedValid
        Timestamp    = $options.TimestampServer
    }
    Switch-BusyState -Busy $true -Maximum $rows.Count
    $script:ui.Progress.Value = $notAttempted
    $script:ui.SummaryText.Text = "Signing $notAttempted of $($rows.Count)..."
    $certificate = if ($options.Source -eq 'Store') { $script:Identity.Certificate } else { $null }

    Invoke-BackgroundJob -Worker $script:SignWorker -Parameters @{
        Items          = $items.ToArray()
        Options        = $options
        Certificate    = $certificate
        ModuleManifest = $script:ModuleManifest
    } -OnMessage {
        param($Message)

        $result = $Message.Result
        Update-FileRow -Path $result.Path -Changes @{
            Status           = $result.Status
            Detail           = $result.Detail
            SignatureState   = if ($result.SignatureState) { $result.SignatureState } else { $script:Rows[$script:RowIndex[$result.Path]].SignatureState }
            Signer           = if ($result.SignatureState) { $result.Signer } else { $script:Rows[$script:RowIndex[$result.Path]].Signer }
            SignerThumbprint = if ($result.SignatureState) { $result.SignerThumbprint } else { $script:Rows[$script:RowIndex[$result.Path]].SignerThumbprint }
            Timestamped      = if ($result.SignatureState) { [bool]$result.Timestamped } else { [bool]$script:Rows[$script:RowIndex[$result.Path]].Timestamped }
        }
        $stats = $script:SignStats
        $stats.Done++
        switch ($result.Status) {
            'Signed' { $stats.Signed++ }
            'Skipped' { $stats.Skipped++ }
            default { $stats.Failed++ }
        }
        $script:ui.Progress.Value = $stats.Done
        $script:ui.SummaryText.Text = "Signing $($stats.Done) of $($stats.Total)..."
    } -OnComplete {
        param($Failure, $Cancelled)

        Switch-BusyState -Busy $false
        $stats = $script:SignStats
        $failed = $stats.Failed + $stats.NotAttempted
        $text = "Signed $($stats.Signed) of $($stats.Total) files."
        $icon = [System.Windows.MessageBoxImage]::Information
        if ($stats.Skipped -gt 0) {
            $text += " $($stats.Skipped) skipped."
        }
        if ($stats.SkippedValid -gt 0) {
            $text += " $($stats.SkippedValid) already had a valid signature and were left alone."
        }
        if ($failed -gt 0) {
            $icon = [System.Windows.MessageBoxImage]::Warning
            $text += " $failed failed; the Details column shows why."
            if ($stats.Signed -eq 0 -and $stats.Failed -gt 0 -and $stats.Timestamp) {
                $text += "`n`nIf this PC cannot reach $($stats.Timestamp), choose None as the timestamp type and sign again."
            }
        }
        if ($Cancelled) {
            $icon = [System.Windows.MessageBoxImage]::Warning
            $text += "`n`nSigning was cancelled; $($stats.Total - $stats.Done) file(s) were not processed."
        }
        if ($Failure) {
            $icon = [System.Windows.MessageBoxImage]::Error
            $text += "`n`nSigning stopped early: $Failure"
        }
        if (-not $script:CloseWhenIdle) {
            [void](Show-Message -Icon $icon -Text $text)
        }
    }
}

function Invoke-Verify {
    if ($script:Job) {
        return
    }
    $paths = @(Get-VisibleRows | Where-Object { $_.ProviderId } | ForEach-Object { $_.Path })
    if ($paths.Count -eq 0) {
        return
    }
    $script:SignStats = @{ Total = $paths.Count; Done = 0; States = @{} }
    Switch-BusyState -Busy $true -Maximum $paths.Count
    $script:ui.SummaryText.Text = "Verifying 0 of $($paths.Count)..."

    Invoke-BackgroundJob -Worker $script:VerifyWorker -Parameters @{
        Paths          = [string[]]$paths
        SignToolPath   = if ($script:SignTool) { $script:SignTool.Path } else { '' }
        ModuleManifest = $script:ModuleManifest
    } -OnMessage {
        param($Message)

        $verification = $Message.Verification
        Update-FileRow -Path $verification.Path -Changes @{
            SignatureState   = $verification.State
            Signer           = $verification.Signer
            SignerThumbprint = $verification.SignerThumbprint
            Timestamped      = [bool]$verification.Timestamped
            Detail           = $verification.Detail
        }
        $stats = $script:SignStats
        $stats.Done++
        $stats.States[$verification.State] = 1 + [int]$stats.States[$verification.State]
        $script:ui.Progress.Value = $stats.Done
        $script:ui.SummaryText.Text = "Verifying $($stats.Done) of $($stats.Total)..."
    } -OnComplete {
        param($Failure, $Cancelled)

        Switch-BusyState -Busy $false
        $stats = $script:SignStats
        $parts = foreach ($state in 'Valid', 'Untrusted', 'Invalid', 'NotSigned', 'Unknown') {
            if ($stats.States[$state]) {
                $label = switch ($state) { 'NotSigned' { 'not signed' } 'Unknown' { 'unreadable' } default { $state.ToLowerInvariant() } }
                "$($stats.States[$state]) $label"
            }
        }
        $text = "Verified $($stats.Done) of $($stats.Total) files: $(@($parts) -join ', ')."
        if ($Failure) {
            $text += "`n`nVerification stopped early: $Failure"
        }
        if (-not $script:CloseWhenIdle) {
            [void](Show-Message -Text $text)
        }
    }
}

function Export-Results {
    $rows = @(Get-VisibleRows)
    if ($rows.Count -eq 0) {
        return
    }
    $dialog = [Microsoft.Win32.SaveFileDialog]::new()
    $dialog.Title = 'Export results'
    $dialog.Filter = 'CSV (*.csv)|*.csv'
    $dialog.FileName = 'signing-suite-{0:yyyyMMdd-HHmmss}.csv' -f (Get-Date)
    if ($dialog.ShowDialog($script:MainWindow) -ne $true) {
        return
    }
    $rows | Select-Object Status,
        @{ Name = 'Name'; Expression = { ConvertTo-SafeCsvField $_.Name } },
        Format,
        @{ Name = 'Signature'; Expression = { ConvertTo-SafeCsvField $_.SignatureText } },
        SignerThumbprint,
        @{ Name = 'Detail'; Expression = { ConvertTo-SafeCsvField $_.Detail } },
        @{ Name = 'Folder'; Expression = { ConvertTo-SafeCsvField $_.Folder } },
        @{ Name = 'Path'; Expression = { ConvertTo-SafeCsvField $_.Path } } |
        Export-Csv -LiteralPath $dialog.FileName -NoTypeInformation -Encoding UTF8
    $script:ui.SummaryText.Text = "Exported $($rows.Count) rows to $($dialog.FileName)"
}

function Remove-SelectedRows {
    if ($script:Job) {
        return
    }
    $selected = @($script:ui.FileGrid.SelectedItems)
    foreach ($row in $selected) {
        [void]$script:Rows.Remove($row)
    }
    Reset-RowIndex
    Sync-Controls
}

function Get-KeyCommand {
    <#
    .SYNOPSIS
        Maps a key press to a window command name, or returns nothing when the key is not a shortcut.
    #>
    param(
        [System.Windows.Input.Key]$Key,
        [System.Windows.Input.ModifierKeys]$Modifiers,
        [bool]$GridFocused,
        [bool]$Busy
    )

    $control = ($Modifiers -band [System.Windows.Input.ModifierKeys]::Control) -ne 0
    $shift = ($Modifiers -band [System.Windows.Input.ModifierKeys]::Shift) -ne 0
    $alt = ($Modifiers -band [System.Windows.Input.ModifierKeys]::Alt) -ne 0
    if ($alt) {
        return
    }
    # Key.Enter and Key.Return share one value whose name is Return, so keys are compared as enum values, not names.
    $keys = [System.Windows.Input.Key]
    if ($control) {
        if ($Key -eq $keys::O) {
            if ($shift) { return 'AddFolder' }
            return 'AddFiles'
        }
        if ($shift) {
            return
        }
        if ($Key -eq $keys::Enter) { return 'Sign' }
        if ($Key -eq $keys::E) { return 'Export' }
        if ($Key -eq $keys::F) { return 'Search' }
        return
    }
    if ($shift) {
        return
    }
    if ($Key -eq $keys::F5) { return 'Rescan' }
    if ($Key -eq $keys::Delete -and $GridFocused) { return 'Remove' }
    if ($Key -eq $keys::Escape -and $Busy) { return 'Cancel' }
}

function Save-CurrentSettings {
    $settings = $script:Settings
    $settings.Source = $script:Identity.Source
    if ($script:Identity.Certificate) {
        $settings.CertificateThumbprint = $script:Identity.Certificate.Thumbprint
    }
    $settings.Engine = Get-ComboTag -Combo $script:ui.EngineCombo
    $settings.DigestAlgorithm = Get-ComboTag -Combo $script:ui.DigestCombo
    $settings.TimestampMode = Get-ComboTag -Combo $script:ui.TimestampModeCombo
    $settings.TimestampServer = $script:ui.TimestampBox.Text.Trim()
    $settings.DualSign = [bool]$script:ui.DualSignCheck.IsChecked
    $settings.SkipValid = [bool]$script:ui.SkipValidCheck.IsChecked
    $settings.ClearVbaSignatures = [bool]$script:ui.ClearVbaCheck.IsChecked
    $settings.Description = $script:ui.DescriptionBox.Text
    $settings.DescriptionUrl = $script:ui.DescriptionUrlBox.Text
    $settings.OptionsExpanded = [bool]$script:ui.OptionsExpander.IsExpanded
    if ($script:MainWindow.WindowState -eq [System.Windows.WindowState]::Normal) {
        $settings.WindowWidth = [int]$script:MainWindow.ActualWidth
        $settings.WindowHeight = [int]$script:MainWindow.ActualHeight
    }
    try {
        Save-SigningSuiteSettings -Settings $settings
    }
    catch {
        Write-Verbose "Settings were not saved: $($_.Exception.Message)"
    }
}

#endregion

#region Startup

$window = [System.Windows.Markup.XamlReader]::Parse($script:MainXaml)
$script:MainWindow = $window
$script:ui = @{}
foreach ($match in [regex]::Matches($script:MainXaml, 'x:Name="(\w+)"')) {
    $script:ui[$match.Groups[1].Value] = $window.FindName($match.Groups[1].Value)
}

$script:ui.FileGrid.ItemsSource = $script:Rows
$script:View = [System.Windows.Data.CollectionViewSource]::GetDefaultView($script:Rows)
$script:View.Filter = [Predicate[object]] { param($row) Test-RowVisible -Row $row }
$script:ui.VersionText.Text = "Version $script:AppVersion"
$window.Title = "$script:AppTitle $script:AppVersion"

$allFormats = [System.Windows.Controls.ComboBoxItem]::new()
$allFormats.Content = 'All formats'
$allFormats.Tag = 'All'
[void]$script:ui.FormatFilter.Items.Add($allFormats)
foreach ($provider in Get-FormatProvider) {
    $item = [System.Windows.Controls.ComboBoxItem]::new()
    $item.Content = $provider.Name
    $item.Tag = $provider.Id
    $item.ToolTip = "$($provider.Description): $($provider.Extensions -join ' ')"
    [void]$script:ui.FormatFilter.Items.Add($item)
}
$script:ui.FormatFilter.SelectedIndex = 0
foreach ($status in 'All', 'Ready', 'Signed', 'Failed', 'Skipped') {
    $item = [System.Windows.Controls.ComboBoxItem]::new()
    $item.Content = if ($status -eq 'All') { 'All' } else { $status }
    $item.Tag = $status
    [void]$script:ui.StatusFilter.Items.Add($item)
}
$script:ui.StatusFilter.SelectedIndex = 0

$settings = $script:Settings
Select-ComboTag -Combo $script:ui.EngineCombo -Tag $settings.Engine
Select-ComboTag -Combo $script:ui.DigestCombo -Tag $settings.DigestAlgorithm
Select-ComboTag -Combo $script:ui.TimestampModeCombo -Tag $settings.TimestampMode
$script:ui.TimestampBox.Text = $settings.TimestampServer
$script:ui.DualSignCheck.IsChecked = $settings.DualSign
$script:ui.SkipValidCheck.IsChecked = $settings.SkipValid
$script:ui.ClearVbaCheck.IsChecked = $settings.ClearVbaSignatures
$script:ui.DescriptionBox.Text = $settings.Description
$script:ui.DescriptionUrlBox.Text = $settings.DescriptionUrl
$script:ui.OptionsExpander.IsExpanded = $settings.OptionsExpanded
if ($settings.WindowWidth -ge 860 -and $settings.WindowHeight -ge 560) {
    $window.Width = $settings.WindowWidth
    $window.Height = $settings.WindowHeight
}

$script:ui.DropHint.Text = 'Scripts, executables, installers, cabinets, catalogs, app packages and Office files with macros. Folders are searched recursively.'
if (Test-IsElevated) {
    # UIPI drops OLE drag-and-drop from medium-integrity Explorer into an elevated window.
    $script:ui.DropHint.Text += "`nRunning as administrator: Windows blocks drag-and-drop from Explorer into elevated windows. Use the buttons, or start the tool without elevation."
    $script:ui.DropHint.Foreground = [System.Windows.Media.Brushes]::Firebrick
}

Update-SignToolState
Select-ComboTag -Combo $script:ui.SourceCombo -Tag $settings.Source
Set-IdentitySource -Source (Get-ComboTag -Combo $script:ui.SourceCombo)

# Handlers resolve script-scope functions and $script: state when they run; .GetNewClosure() rebinds them to a new module scope where neither exists.
$dragFeedback = {
    $dragArgs = [System.Windows.DragEventArgs]$args[1]
    if ($null -eq $script:Job -and $dragArgs.Data.GetDataPresent([System.Windows.DataFormats]::FileDrop)) {
        $dragArgs.Effects = [System.Windows.DragDropEffects]::Copy
    }
    else {
        $dragArgs.Effects = [System.Windows.DragDropEffects]::None
    }
    $dragArgs.Handled = $true
}
$window.Add_PreviewDragEnter($dragFeedback)
$window.Add_PreviewDragOver($dragFeedback)
$window.Add_PreviewDrop({
        $dropArgs = [System.Windows.DragEventArgs]$args[1]
        $dropArgs.Handled = $true
        if ($dropArgs.Data.GetDataPresent([System.Windows.DataFormats]::FileDrop)) {
            $dropped = [string[]]$dropArgs.Data.GetData([System.Windows.DataFormats]::FileDrop)
            Invoke-Safely { Add-InputPath -Path $dropped }
        }
    })

$addFiles = {
    Invoke-Safely {
        if ($script:Job) { return }
        $dialog = [Microsoft.Win32.OpenFileDialog]::new()
        $dialog.Title = 'Select files to sign'
        $dialog.Multiselect = $true
        $patterns = (Get-SupportedExtension | ForEach-Object { "*$_" }) -join ';'
        $dialog.Filter = "Signable files|$patterns|All files (*.*)|*.*"
        if ($dialog.ShowDialog($script:MainWindow) -eq $true) {
            Add-InputPath -Path $dialog.FileNames
        }
    }
}
$addFolder = {
    Invoke-Safely {
        if ($script:Job) { return }
        $dialog = [System.Windows.Forms.FolderBrowserDialog]::new()
        try {
            $dialog.Description = 'Select a folder to search for signable files (subfolders included)'
            $dialog.ShowNewFolderButton = $false
            if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                Add-InputPath -Path @($dialog.SelectedPath)
            }
        }
        finally {
            $dialog.Dispose()
        }
    }
}
$rescan = {
    Invoke-Safely {
        if ($script:Job -or $script:Rows.Count -eq 0) { return }
        Start-Scan -Paths @($script:Rows | ForEach-Object { $_.Path }) -Replace $true
    }
}
$sign = { Invoke-Safely { Invoke-Signing } }
$export = { Invoke-Safely { Export-Results } }

$script:ui.AddFilesButton.Add_Click($addFiles)
$script:ui.AddFolderButton.Add_Click($addFolder)
$script:ui.RescanButton.Add_Click($rescan)
$script:ui.SignButton.Add_Click($sign)
$script:ui.ExportButton.Add_Click($export)
$script:ui.VerifyButton.Add_Click({ Invoke-Safely { Invoke-Verify } })
$script:ui.CancelButton.Add_Click({ Stop-BackgroundJob })
$script:ui.RemoveButton.Add_Click({ Invoke-Safely { Remove-SelectedRows } })
$script:ui.RemoveMenu.Add_Click({ Invoke-Safely { Remove-SelectedRows } })
$script:ui.ClearButton.Add_Click({
        if ($script:Job) { return }
        $script:Rows.Clear()
        $script:RowIndex.Clear()
        Sync-Controls
    })
$script:ui.CopyPathMenu.Add_Click({
        $paths = @($script:ui.FileGrid.SelectedItems | ForEach-Object { $_.Path })
        if ($paths.Count -gt 0) {
            [System.Windows.Clipboard]::SetText(($paths -join [Environment]::NewLine))
        }
    })
$script:ui.OpenFolderMenu.Add_Click({
        $row = $script:ui.FileGrid.SelectedItem
        if ($row) {
            Start-Process -FilePath (Join-Path $env:windir 'explorer.exe') -ArgumentList "/select,`"$($row.Path)`""
        }
    })
$script:ui.FileGrid.Add_SelectionChanged({ Sync-Controls })
$script:ui.ChangeIdentityButton.Add_Click({ Invoke-Safely { Invoke-ChangeIdentity } })
$script:ui.SourceCombo.Add_SelectionChanged({
        if ($script:StartupDone) {
            Invoke-Safely { Set-IdentitySource -Source (Get-ComboTag -Combo $script:ui.SourceCombo) }
        }
    })
$script:ui.EngineCombo.Add_SelectionChanged({ Update-EngineInfo })
$script:ui.SkipValidCheck.Add_Click({ Sync-Controls })
$filterChanged = {
    if ($script:View) {
        $script:View.Refresh()
    }
    Sync-Controls
}
$script:ui.FormatFilter.Add_SelectionChanged($filterChanged)
$script:ui.StatusFilter.Add_SelectionChanged($filterChanged)
$script:ui.SearchBox.Add_TextChanged($filterChanged)

$script:ui.SipActionButton.Add_Click({
        Invoke-Safely {
            switch ($script:SipAction) {
                'Relaunch' { Invoke-BitnessRelaunch }
                'Download' { Start-Process -FilePath $script:SipDownloadUrl }
            }
        }
    })
$script:ui.SignToolActionButton.Add_Click({
        Invoke-Safely {
            $picked = Select-OpenFile -Title 'Select signtool.exe' -Filter 'signtool.exe|signtool.exe'
            if ($picked) {
                $script:Settings.SignToolPath = $picked
                Update-SignToolState
                Sync-Controls
            }
        }
    })

$window.Add_PreviewKeyDown({
        $keyArgs = [System.Windows.Input.KeyEventArgs]$args[1]
        $key = if ($keyArgs.Key -eq [System.Windows.Input.Key]::System) { $keyArgs.SystemKey } else { $keyArgs.Key }
        $command = Get-KeyCommand -Key $key -Modifiers ([System.Windows.Input.Keyboard]::Modifiers) -GridFocused $script:ui.FileGrid.IsKeyboardFocusWithin -Busy ($null -ne $script:Job)
        if (-not $command) {
            return
        }
        $keyArgs.Handled = $true
        switch ($command) {
            'AddFiles' { & $addFiles }
            'AddFolder' { & $addFolder }
            'Sign' { if ($script:ui.SignButton.IsEnabled) { & $sign } }
            'Export' { if ($script:ui.ExportButton.IsEnabled) { & $export } }
            'Search' { [void]$script:ui.SearchBox.Focus(); $script:ui.SearchBox.SelectAll() }
            'Rescan' { & $rescan }
            'Remove' { Invoke-Safely { Remove-SelectedRows } }
            'Cancel' { Stop-BackgroundJob }
        }
    })

$window.Add_ContentRendered({
        if ($script:StartupDone) {
            return
        }
        $script:StartupDone = $true
        if ($Path) {
            Invoke-Safely { Add-InputPath -Path $Path }
        }
    })

$window.Add_Closing({
        $closingArgs = [System.ComponentModel.CancelEventArgs]$args[1]
        if ($script:Job) {
            $closingArgs.Cancel = $true
            if ($script:CloseWhenIdle) {
                return
            }
            $answer = Show-Message -Icon Warning -Buttons YesNo -Text 'A search, signing or verification run is still working. Stop it after the current file and close?'
            if ($answer -eq [System.Windows.MessageBoxResult]::Yes) {
                $script:CloseWhenIdle = $true
                Stop-BackgroundJob
            }
            return
        }
        Save-CurrentSettings
    })

Sync-Controls
[void]$window.ShowDialog()

#endregion
