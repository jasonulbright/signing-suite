; Signing Suite setup. Build with tools\Build-Installer.ps1, which passes AppVersion, FileVersion and StageDir.
; Prerequisites download from Microsoft during setup; each download is checked against the SHA256 pinned below.

#ifndef AppVersion
  #define AppVersion "0000.00.00.0000"
#endif
#ifndef FileVersion
  #define FileVersion "0.0.0.0"
#endif
#ifndef StageDir
  #define StageDir ".."
#endif

[Setup]
AppId={{6B7F2C1E-4D8A-4F3B-9E21-5A0C7D3B8E64}
AppName=Signing Suite
AppVersion={#AppVersion}
AppVerName=Signing Suite {#AppVersion}
AppPublisher=Jason Ulbright
AppPublisherURL=https://github.com/jasonulbright/signing-suite
AppSupportURL=https://github.com/jasonulbright/signing-suite/issues
AppUpdatesURL=https://github.com/jasonulbright/signing-suite/releases
VersionInfoVersion={#FileVersion}
DefaultDirName={autopf}\Signing Suite
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
WizardStyle=modern
LicenseFile={#StageDir}\LICENSE
OutputBaseFilename=SigningSuiteSetup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
SetupLogging=yes
ChangesEnvironment=yes
#ifdef SignCommand
; tools\Build-Installer.ps1 passes /DSignCommand and /Ssigningsuite=<signtool command>; Inno Setup then signs the
; uninstaller it embeds and the finished setup file.
SignTool=signingsuite
SignedUninstaller=yes
#endif
UninstallDisplayName=Signing Suite
UninstallDisplayIcon={sys}\WindowsPowerShell\v1.0\powershell.exe

[Types]
Name: "full"; Description: "Full installation"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "app"; Description: "Signing Suite"; Types: full custom; Flags: fixed
Name: "officesips"; Description: "Office signing add-in for VBA macros (Office SIPs and Visual C++ runtime)"; Types: full custom
Name: "sdktools"; Description: "Windows SDK signing tools (signtool.exe)"; Types: full custom
Name: "artifactsigning"; Description: "Artifact Signing Client Tools"; Types: full custom
Name: "azurecli"; Description: "Azure CLI"; Types: full custom

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Components: app; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{autoprograms}\Signing Suite"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\start-signingsuite.ps1"""; WorkingDir: "{app}"; Comment: "Sign scripts, executables, installers, app packages and Office macros"
Name: "{autodesktop}\Signing Suite"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\start-signingsuite.ps1"""; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\start-signingsuite.ps1"""; WorkingDir: "{app}"; Description: "Start Signing Suite"; Flags: postinstall nowait skipifsilent runasoriginaluser

[Code]
const
  OpenXmlSipKey = 'SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllIsMyFileType2\{6E64D5BD-CEB0-4B66-B4A0-15AC71775C48}';
  LegacySipKey = 'SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllIsMyFileType2\{01F45160-3E3E-11D3-B49A-00104B2CF645}';

  OfficeSipsX64Url = 'https://download.microsoft.com/download/c53e473c-3060-4ee9-ac5c-0ddbbeced4e5/OfficeSips_x64_16-0-19416-43425.exe';
  OfficeSipsX64Sha256 = '96335d8afbed13919e6bd31cf38974fb4ee2a534734a5e5736e1a40d032d2456';
  OfficeSipsX86Url = 'https://download.microsoft.com/download/c53e473c-3060-4ee9-ac5c-0ddbbeced4e5/OfficeSips_x86_16-0-19416-43425.exe';
  OfficeSipsX86Sha256 = 'e11f38d3ebc64bf3fd7be40b507d051dd703b6896ef2ba9d8fa71b462c868350';
  VCRedistX64Url = 'https://download.visualstudio.microsoft.com/download/pr/ebdab8e5-1d7b-4d9f-a11b-cbb1720c3b12/843068991DAAA1F73AD9F6239BCE4D0F6A07A51F18C37EA2A867E9BECA71295C/VC_redist.x64.exe';
  VCRedistX64Sha256 = '843068991daaa1f73ad9f6239bce4d0f6a07a51f18c37ea2a867e9beca71295c';
  VCRedistX86Url = 'https://download.visualstudio.microsoft.com/download/pr/57eef8ae-a341-46c3-b0bc-c041027b54cd/F0BAB33A302B3CDB2E11113760D016F54FD3D2632C65BA7834FAC4F0ABD7F1A3/VC_redist.x86.exe';
  VCRedistX86Sha256 = 'f0bab33a302b3cdb2e11113760d016f54fd3d2632c65ba7834fac4f0abd7f1a3';
  WindowsSdkUrl = 'https://download.microsoft.com/download/f4b30f2a-4fc3-430e-9b03-c842b5f5f9f1/KIT_BUNDLE_WINDOWSSDK_MEDIACREATION/winsdksetup.exe';
  WindowsSdkSha256 = '6fa0fa27db77a909f5ecb35183cb26a969a6775936780936fe239e4f9c66b458';
  ArtifactSigningUrl = 'https://download.microsoft.com/download/a3c24ba9-ff1f-444f-b626-eff710f345c3/ArtifactSigningClientTools.msi';
  ArtifactSigningSha256 = '93807bb270e63416912faddcecf21e0165fc8eb8ae444b01458c7849679e0e4f';
  ArtifactSigningProductCode = '{2EF3A45E-5812-4982-A0EB-1A3609722F99}';
  AzureCliUrl = 'https://azcliprod.blob.core.windows.net/msi/azure-cli-2.90.0-x64.msi';
  AzureCliSha256 = 'd5c1918eab32063219bea575e0d545149969c24751cb5f90ad2388b5df72222f';

var
  DownloadPage: TDownloadWizardPage;
  UseDownloadPage: Boolean;
  DownloadError: String;

function VCRedistInstalled(Is64Bit: Boolean): Boolean;
var
  Installed: Cardinal;
begin
  if Is64Bit then
    Result := RegQueryDWordValue(HKLM64, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Installed', Installed) and (Installed = 1)
  else
    Result := RegQueryDWordValue(HKLM32, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x86', 'Installed', Installed) and (Installed = 1);
end;

function OfficeSipsRegistered(RootKey: Integer): Boolean;
begin
  Result := RegKeyExists(RootKey, OpenXmlSipKey) and RegKeyExists(RootKey, LegacySipKey);
end;

function SignToolInstalled: Boolean;
var
  KitsRoot: String;
  FindRec: TFindRec;
begin
  Result := False;
  if not RegQueryStringValue(HKLM32, 'SOFTWARE\Microsoft\Windows Kits\Installed Roots', 'KitsRoot10', KitsRoot) then
    KitsRoot := ExpandConstant('{commonpf32}\Windows Kits\10\');
  KitsRoot := AddBackslash(KitsRoot) + 'bin\';
  if FindFirst(KitsRoot + '*', FindRec) then
  begin
    try
      repeat
        if ((FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0) and FileExists(KitsRoot + FindRec.Name + '\x64\signtool.exe') then
          Result := True;
      until Result or not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

function ArtifactSigningInstalled: Boolean;
begin
  { A registered product whose files sit in another account's profile counts as installed: running the MSI again
    starts a repair that fails with 1603. }
  Result := FileExists(ExpandConstant('{localappdata}\Microsoft\MicrosoftArtifactSigningClientTools\Azure.CodeSigning.Dlib.dll')) or
    RegKeyExists(HKLM64, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' + ArtifactSigningProductCode) or
    RegKeyExists(HKLM32, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' + ArtifactSigningProductCode);
end;

function AzureCliInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{commonpf64}\Microsoft SDKs\Azure\CLI2\wbin\az.cmd')) or
    FileExists(ExpandConstant('{commonpf32}\Microsoft SDKs\Azure\CLI2\wbin\az.cmd'));
end;

procedure QueueDownload(const Url, BaseName, Sha256: String);
begin
  if FileExists(ExpandConstant('{tmp}\') + BaseName) then
    Exit;
  if UseDownloadPage then
    DownloadPage.Add(Url, BaseName, Sha256)
  else if DownloadError = '' then
  begin
    try
      Log('Downloading ' + Url);
      DownloadTemporaryFile(Url, BaseName, Sha256, nil);
    except
      DownloadError := Format('%s: %s', [BaseName, GetExceptionMessage]);
    end;
  end;
end;

procedure QueueDownloads;
begin
  if WizardIsComponentSelected('officesips') then
  begin
    if not VCRedistInstalled(True) then
      QueueDownload(VCRedistX64Url, 'VC_redist.x64.exe', VCRedistX64Sha256);
    if not VCRedistInstalled(False) then
      QueueDownload(VCRedistX86Url, 'VC_redist.x86.exe', VCRedistX86Sha256);
    if not OfficeSipsRegistered(HKLM64) then
      QueueDownload(OfficeSipsX64Url, 'OfficeSips_x64.exe', OfficeSipsX64Sha256);
    if not OfficeSipsRegistered(HKLM32) then
      QueueDownload(OfficeSipsX86Url, 'OfficeSips_x86.exe', OfficeSipsX86Sha256);
  end;
  if WizardIsComponentSelected('sdktools') and not SignToolInstalled then
    QueueDownload(WindowsSdkUrl, 'winsdksetup.exe', WindowsSdkSha256);
  if WizardIsComponentSelected('artifactsigning') and not ArtifactSigningInstalled then
    QueueDownload(ArtifactSigningUrl, 'ArtifactSigningClientTools.msi', ArtifactSigningSha256);
  if WizardIsComponentSelected('azurecli') and not AzureCliInstalled then
    QueueDownload(AzureCliUrl, 'azure-cli-2.90.0-x64.msi', AzureCliSha256);
end;

procedure InitializeWizard;
begin
  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing), 'Downloading prerequisites from Microsoft.', nil);
  DownloadPage.ShowBaseNameInsteadOfUrl := True;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID <> wpReady then
    Exit;
  UseDownloadPage := True;
  DownloadPage.Clear;
  QueueDownloads;
  DownloadPage.Show;
  try
    try
      DownloadPage.Download;
    except
      if not DownloadPage.AbortedByUser then
        SuppressibleMsgBox(AddPeriod(Format('%s: %s', [DownloadPage.LastBaseNameOrUrl, GetExceptionMessage])), mbCriticalError, MB_OK, IDOK);
      Result := False;
    end;
  finally
    DownloadPage.Hide;
  end;
end;

function RunInstaller(const Description, FileName, Params: String; var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  Log(Format('Running %s: "%s" %s', [Description, FileName, Params]));
  if not Exec(FileName, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Result := Format('%s could not start: %s', [Description, SysErrorMessage(ResultCode)])
  else
  begin
    Log(Format('%s exit code %d', [Description, ResultCode]));
    if (ResultCode = 3010) or (ResultCode = 1641) then
      NeedsRestart := True
    else if (ResultCode <> 0) and (ResultCode <> 1638) then
      Result := Format('%s failed with exit code %d.', [Description, ResultCode]);
  end;
end;

function InstallOfficeSips(const Arch, Package, RegSvr32: String; var NeedsRestart: Boolean): String;
var
  Folder: String;
begin
  Folder := ExpandConstant('{commonpf64}\Microsoft Office SIPs\') + Arch;
  if not ForceDirectories(Folder) then
  begin
    Result := 'Could not create ' + Folder + '.';
    Exit;
  end;
  { tar.exe ships with Windows and reads the cabinet inside the Microsoft self-extractor without showing its dialog. }
  Result := RunInstaller('Office SIP extraction (' + Arch + ')', ExpandConstant('{sys}\tar.exe'),
    '-xf "' + ExpandConstant('{tmp}\') + Package + '" -C "' + Folder + '"', NeedsRestart);
  if Result = '' then
    Result := RunInstaller('msosip.dll registration (' + Arch + ')', RegSvr32, '/s "' + Folder + '\msosip.dll"', NeedsRestart);
  if Result = '' then
    Result := RunInstaller('msosipx.dll registration (' + Arch + ')', RegSvr32, '/s "' + Folder + '\msosipx.dll"', NeedsRestart);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  { Silent installs skip the wizard pages, so any download the download page did not fetch happens here. }
  UseDownloadPage := False;
  DownloadError := '';
  QueueDownloads;
  if DownloadError <> '' then
  begin
    Result := 'A prerequisite download failed. ' + DownloadError;
    Exit;
  end;

  Result := '';
  if WizardIsComponentSelected('officesips') then
  begin
    if not VCRedistInstalled(True) then
      Result := RunInstaller('Visual C++ runtime (x64)', ExpandConstant('{tmp}\VC_redist.x64.exe'), '/install /quiet /norestart', NeedsRestart);
    if (Result = '') and not VCRedistInstalled(False) then
      Result := RunInstaller('Visual C++ runtime (x86)', ExpandConstant('{tmp}\VC_redist.x86.exe'), '/install /quiet /norestart', NeedsRestart);
    if (Result = '') and not OfficeSipsRegistered(HKLM64) then
      Result := InstallOfficeSips('x64', 'OfficeSips_x64.exe', ExpandConstant('{sys}\regsvr32.exe'), NeedsRestart);
    if (Result = '') and not OfficeSipsRegistered(HKLM32) then
      Result := InstallOfficeSips('x86', 'OfficeSips_x86.exe', ExpandConstant('{syswow64}\regsvr32.exe'), NeedsRestart);
    if (Result = '') and not (OfficeSipsRegistered(HKLM64) and OfficeSipsRegistered(HKLM32)) then
      Result := 'The Office signing add-in did not register.';
  end;

  if (Result = '') and WizardIsComponentSelected('sdktools') and not SignToolInstalled then
  begin
    Result := RunInstaller('Windows SDK signing tools', ExpandConstant('{tmp}\winsdksetup.exe'), '/features OptionId.SigningTools /quiet /norestart /ceip off', NeedsRestart);
    if (Result = '') and not SignToolInstalled then
      Result := 'signtool.exe was not found after the Windows SDK signing tools installed.';
  end;

  if (Result = '') and WizardIsComponentSelected('artifactsigning') and not ArtifactSigningInstalled then
  begin
    { The Artifact Signing MSI installs into the profile of the account that runs it. }
    Result := RunInstaller('Artifact Signing Client Tools', ExpandConstant('{sys}\msiexec.exe'),
      '/i "' + ExpandConstant('{tmp}\ArtifactSigningClientTools.msi') + '" /qn /norestart', NeedsRestart);
    if (Result = '') and not ArtifactSigningInstalled then
      Log('Azure.CodeSigning.Dlib.dll is not in this account''s profile; the MSI installed for the account that ran it.');
  end;

  if (Result = '') and WizardIsComponentSelected('azurecli') and not AzureCliInstalled then
  begin
    Result := RunInstaller('Azure CLI', ExpandConstant('{sys}\msiexec.exe'),
      '/i "' + ExpandConstant('{tmp}\azure-cli-2.90.0-x64.msi') + '" /qn /norestart', NeedsRestart);
    if (Result = '') and not AzureCliInstalled then
      Result := 'az.cmd was not found after Azure CLI installed.';
  end;
end;
