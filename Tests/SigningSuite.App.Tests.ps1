#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeDiscovery {
    $script:isSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq [System.Threading.ApartmentState]::STA
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

    $script:repoRoot = Split-Path -Parent $PSScriptRoot
    $script:entryPath = Join-Path $repoRoot 'start-signingsuite.ps1'
    $script:entryText = [System.IO.File]::ReadAllText($script:entryPath)
    $script:mainXamlPath = Join-Path $repoRoot 'MainWindow.xaml'
    $script:manifestPath = Join-Path $repoRoot 'Module\SigningSuite\SigningSuite.psd1'

    function Get-AppDefinitions {
        # Only definitions sit above the startup region; the startup region builds and shows the window.
        $startupIndex = $script:entryText.IndexOf('#region Startup')
        $definitions = ($script:entryText.Substring(0, $startupIndex) -split "`r?`n" | Where-Object { $_ -notmatch '^#Requires' }) -join "`n"
        $definitions = $definitions.Replace('$PSScriptRoot', "'$($script:repoRoot.Replace("'", "''"))'").Replace('$PSCommandPath', "'$($script:entryPath.Replace("'", "''"))'")
        [scriptblock]::Create($definitions)
    }

    function New-AppWindow {
        $script:MainWindow = [System.Windows.Markup.XamlReader]::Parse($script:MainXaml)
        $script:ui = @{}
        foreach ($match in [regex]::Matches($script:MainXaml, 'x:Name="(\w+)"')) {
            $script:ui[$match.Groups[1].Value] = $script:MainWindow.FindName($match.Groups[1].Value)
        }
        foreach ($status in 'All', 'Ready', 'Signed', 'Failed', 'Skipped') {
            $item = [System.Windows.Controls.ComboBoxItem]::new()
            $item.Content = $status
            $item.Tag = $status
            [void]$script:ui.StatusFilter.Items.Add($item)
        }
        $all = [System.Windows.Controls.ComboBoxItem]::new()
        $all.Content = 'All formats'
        $all.Tag = 'All'
        [void]$script:ui.FormatFilter.Items.Add($all)
        foreach ($provider in Get-FormatProvider) {
            $item = [System.Windows.Controls.ComboBoxItem]::new()
            $item.Content = $provider.Name
            $item.Tag = $provider.Id
            [void]$script:ui.FormatFilter.Items.Add($item)
        }
        $script:ui.FormatFilter.SelectedIndex = 0
        $script:ui.StatusFilter.SelectedIndex = 0
        $script:ui.EngineCombo.SelectedIndex = 0
        $script:ui.DigestCombo.SelectedIndex = 0
        $script:ui.SkipValidCheck.IsChecked = $true
        $script:ui.FileGrid.ItemsSource = $script:Rows
        $script:Rows.Clear()
        $script:RowIndex.Clear()
        $script:shownMessages.Clear()
        $script:Identity.Source = 'Store'
        $script:Identity.Certificate = $null
    }
}

Describe 'Source files' {

    It 'parses <Name> without errors' -ForEach @(
        Get-ChildItem -Path (Split-Path -Parent $PSScriptRoot) -Recurse -Include *.ps1, *.psm1, *.psd1 |
            Where-Object { $_.FullName -notmatch '\\(\.git|out|dist)\\' } |
            ForEach-Object { @{ Name = $_.FullName.Substring((Split-Path -Parent $PSScriptRoot).Length + 1); Path = $_.FullName } }
    ) {
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It 'keeps shipped files ASCII: <Name>' -ForEach @(
        Get-ChildItem -Path (Split-Path -Parent $PSScriptRoot) -Recurse -Include *.ps1, *.psm1, *.psd1, *.xaml, *.md |
            Where-Object { $_.FullName -notmatch '\\(\.git|out|dist|Tests)\\' -and $_.Name -notlike '*.local.md' } |
            ForEach-Object { @{ Name = $_.FullName.Substring((Split-Path -Parent $PSScriptRoot).Length + 1); Path = $_.FullName } }
    ) {
        [System.IO.File]::ReadAllText($Path) | Should -Not -Match '[^\x00-\x7F]'
    }

    It 'does not rebind scriptblocks with GetNewClosure' {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:entryText, [ref]$null, [ref]$null)
        $closures = $ast.FindAll({ param($node)
                $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Extent.Text -eq 'GetNewClosure'
            }, $true)
        @($closures).Count | Should -Be 0
    }

    It 'names one version in the entry header, the module manifest and the changelog' {
        $manifestVersion = (Import-PowerShellDataFile -LiteralPath $script:manifestPath).PrivateData.SigningSuiteVersion
        $headerVersion = [regex]::Match($script:entryText, '(?m)^\s*Version\s*:\s*(\S+)').Groups[1].Value
        $changelog = [System.IO.File]::ReadAllText((Join-Path $script:repoRoot 'CHANGELOG.md'))
        $changelogVersion = [regex]::Match($changelog, '(?m)^## \[?v?(\d{4}\.\d{2}\.\d{2}\.\d{4})').Groups[1].Value
        $headerVersion | Should -Be $manifestVersion
        $changelogVersion | Should -Be $manifestVersion
    }

    It 'repairs a PSModulePath inherited from PowerShell 7 in <Name>' -ForEach @(
        @{ Name = 'start-signingsuite.ps1' }
        @{ Name = 'Invoke-SigningSuite.ps1' }
    ) {
        $text = [System.IO.File]::ReadAllText((Join-Path $script:repoRoot $Name))
        $region = [regex]::Match($text, '(?s)#region Environment\r?\n(.*?)#endregion')
        $region.Success | Should -BeTrue
        $probe = Join-Path $TestDrive "probe-$Name"
        [System.IO.File]::WriteAllText($probe, $region.Groups[1].Value + @'
try { Import-Module Microsoft.PowerShell.Security -ErrorAction Stop; 'security-ok' } catch { 'security-failed' }
if (Get-Command Import-PowerShellDataFile -ErrorAction SilentlyContinue) { 'datafile-ok' } else { 'datafile-missing' }
'@)
        $inherited = @(
            (Join-Path $env:USERPROFILE 'Documents\PowerShell\Modules')
            'C:\Program Files\PowerShell\Modules'
            'c:\program files\windowsapps\microsoft.powershell_7.6.6.0_x64__8wekyb3d8bbwe\Modules'
            'C:\Program Files\PowerShell\7\Modules'
            $env:PSModulePath
        ) -join ';'
        $saved = $env:PSModulePath
        try {
            $env:PSModulePath = $inherited
            $output = & (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $probe 2>&1
        }
        finally {
            $env:PSModulePath = $saved
        }
        $output | Should -Contain 'security-ok'
        $output | Should -Contain 'datafile-ok'
    }

    It 'keeps tests, native test sources and release tooling out of the release archive' {
        $attributes = [System.IO.File]::ReadAllText((Join-Path $script:repoRoot '.gitattributes'))
        foreach ($pattern in '/Tests', '/tools', '/RELEASING.md', '/.gitattributes', '/.gitignore') {
            $attributes | Should -Match ([regex]::Escape($pattern) + '\s+export-ignore')
        }
    }
}

Describe 'Window markup' {

    It 'loads the main window and resolves every named control' {
        $xaml = [System.IO.File]::ReadAllText($script:mainXamlPath)
        $window = [System.Windows.Markup.XamlReader]::Parse($xaml)
        $names = @([regex]::Matches($xaml, 'x:Name="(\w+)"') | ForEach-Object { $_.Groups[1].Value })
        $names.Count | Should -BeGreaterThan 30
        foreach ($name in $names) {
            $window.FindName($name) | Should -Not -BeNullOrEmpty -Because "the window names $name"
        }
    }

    It 'loads the dialog markup embedded in the entry script: <Name>' -ForEach @(
        @{ Name = 'PasswordXaml' }
        @{ Name = 'PickerXaml' }
        @{ Name = 'ToolIdentityXaml' }
    ) {
        $match = [regex]::Match($script:entryText, "(?s)\`$script:$Name = @'\r?\n(.*?)\r?\n'@")
        $match.Success | Should -BeTrue
        { [void][System.Windows.Markup.XamlReader]::Parse($match.Groups[1].Value) } | Should -Not -Throw
    }

    It 'names every control the code looks up through the ui table' {
        $xaml = [System.IO.File]::ReadAllText($script:mainXamlPath)
        $names = @([regex]::Matches($xaml, 'x:Name="(\w+)"') | ForEach-Object { $_.Groups[1].Value })
        $used = @([regex]::Matches($script:entryText, '\$script:ui\.(\w+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
        $used += @([regex]::Matches($script:entryText, "'(\w+)'(?=[,\s]*(?:'\w+'[,\s]*)*\)\s*\{\s*\r?\n\s*\`$script:ui\[)") | ForEach-Object { $_.Groups[1].Value })
        foreach ($name in $used) {
            $names | Should -Contain $name
        }
    }
}

Describe 'Window behavior' -Skip:(-not $script:isSta) {

    BeforeAll {
        . (Get-AppDefinitions)
        # A modal message box would block the run; messages are recorded instead.
        $script:shownMessages = [System.Collections.Generic.List[string]]::new()
        function Show-Message {
            param($Text, $Icon, $Buttons, $Owner)
            $script:shownMessages.Add([string]$Text)
            if ($Buttons -eq [System.Windows.MessageBoxButton]::YesNo) {
                return [System.Windows.MessageBoxResult]::Yes
            }
            [System.Windows.MessageBoxResult]::OK
        }
        $script:listRoot = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'list [x]')).FullName
        [System.IO.File]::WriteAllText((Join-Path $listRoot 'one.ps1'), "Write-Output 1`r`n")
        [System.IO.File]::WriteAllText((Join-Path $listRoot 'two.vbs'), "WScript.Echo 1`r`n")
        [System.IO.File]::WriteAllText((Join-Path $listRoot 'notes.txt'), 'x')
        New-TestZip -Path (Join-Path $listRoot 'NoMacros.xlsm') -Entries @{ 'xl/workbook.xml' = '<x/>' }
        New-TestZip -Path (Join-Path $listRoot 'app.msix') -Entries @{ 'AppxManifest.xml' = '<Package><Identity Publisher="CN=Signing Suite Test"/></Package>' }

        New-AppWindow
        $script:SignTool = $null
        Add-InputPath -Path @($listRoot, (Join-Path $listRoot 'one.ps1'), (Join-Path $listRoot 'notes.txt'))
        $script:listCompleted = Wait-TestBackgroundJob
    }

    It 'lists each file once, even when dropped twice' {
        $script:listCompleted | Should -BeTrue
        @($script:Rows | ForEach-Object Name) | Sort-Object | Should -Be @('app.msix', 'NoMacros.xlsm', 'notes.txt', 'one.ps1', 'two.vbs')
        $script:shownMessages.Count | Should -Be 0
    }

    It 'counts pending files and stays disabled without a signing identity' {
        $script:ui.SignButton.Content | Should -Be 'Sign 3 files'
        $script:ui.SignButton.IsEnabled | Should -BeFalse
        $script:ui.AddFilesButton.IsEnabled | Should -BeTrue
    }

    It 'filters the pending count by format and by search text' {
        Select-ComboTag -Combo $script:ui.FormatFilter -Tag 'PowerShell'
        Sync-Controls
        $script:ui.SignButton.Content | Should -Be 'Sign 1 file'
        $script:ui.FilterCountText.Text | Should -Be '1 of 5 files shown'
        Select-ComboTag -Combo $script:ui.FormatFilter -Tag 'All'
        $script:ui.SearchBox.Text = 'two'
        Sync-Controls
        $script:ui.SignButton.Content | Should -Be 'Sign 1 file'
        $script:ui.SearchBox.Text = ''
        Sync-Controls
    }

    It 'enables signing once a certificate is selected' {
        $certificate = New-TestCertificate
        try {
            $script:Identity.Certificate = $certificate
            Update-IdentityDisplay
            $script:ui.SignButton.IsEnabled | Should -BeTrue
            $script:ui.IdentityText.Text | Should -Be 'Signing Suite Test'
        }
        finally {
            $script:Identity.Certificate = $null
            Update-IdentityDisplay
            $certificate.Dispose()
        }
    }

    It 'signs with the PowerShell engine and explains the files it cannot sign' {
        $pfx = Join-Path $TestDrive 'window.pfx'
        New-TestPfx -Path $pfx
        $certificate = Import-TestSigningCertificate -Path $pfx
        try {
            $script:Identity.Certificate = $certificate
            Select-ComboTag -Combo $script:ui.EngineCombo -Tag 'Auto'
            Select-ComboTag -Combo $script:ui.TimestampModeCombo -Tag 'None'
            Update-IdentityDisplay
            Invoke-Signing
            Wait-TestBackgroundJob | Should -BeTrue

            $byName = @{}
            foreach ($row in $script:Rows) {
                $byName[$row.Name] = $row
            }
            $byName['one.ps1'].Status | Should -Be 'Signed'
            $byName['two.vbs'].Status | Should -Be 'Signed'
            $byName['one.ps1'].SignatureText | Should -Be 'Untrusted: Signing Suite Test'
            $byName['app.msix'].Status | Should -Be 'Failed'
            $byName['app.msix'].Detail | Should -BeLike 'Not signed: signtool.exe was not found*App package files*'
            $script:shownMessages[-1] | Should -BeLike 'Signed 2 of 3 files.*1 failed*'
            $script:ui.SignButton.Content | Should -Be 'Sign 1 file'
        }
        finally {
            $script:Identity.Certificate = $null
            Remove-TestKey -Certificate $certificate
        }
    }

    It 'verifies the listed files' {
        Invoke-Verify
        Wait-TestBackgroundJob | Should -BeTrue
        $row = $script:Rows | Where-Object Name -eq 'one.ps1'
        $row.SignatureState | Should -Be 'Untrusted'
        $script:shownMessages[-1] | Should -BeLike 'Verified 4 of 4 files:*'
    }

    It 'removes selected rows and keeps the index consistent' {
        $target = $script:Rows | Where-Object Name -eq 'notes.txt'
        $script:ui.FileGrid.SelectedItems.Clear()
        [void]$script:ui.FileGrid.SelectedItems.Add($target)
        Remove-SelectedRows
        @($script:Rows | ForEach-Object Name) | Should -Not -Contain 'notes.txt'
        foreach ($key in $script:RowIndex.Keys) {
            $script:Rows[$script:RowIndex[$key]].Path | Should -Be $key
        }
    }

    It 'exports the visible rows to CSV' {
        $csv = Join-Path $TestDrive 'export.csv'
        $rows = @(Get-VisibleRows) | Select-Object Status, Name, Format, @{ Name = 'Signature'; Expression = { $_.SignatureText } }, SignerThumbprint, Detail, Folder, Path
        $rows | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
        @(Import-Csv -LiteralPath $csv).Count | Should -Be @(Get-VisibleRows).Count
    }

    It 'stops a running job when cancel is requested' {
        $script:ui.SkipValidCheck.IsChecked = $false
        $many = [System.IO.Directory]::CreateDirectory((Join-Path $TestDrive 'many')).FullName
        foreach ($i in 1..40) {
            [System.IO.File]::WriteAllText((Join-Path $many "file$i.ps1"), "Write-Output $i`r`n")
        }
        Add-InputPath -Path @($many)
        Stop-BackgroundJob
        Wait-TestBackgroundJob | Should -BeTrue
        @($script:Rows | Where-Object { $_.Path -like "$many*" }).Count | Should -BeLessThan 40
    }
}
