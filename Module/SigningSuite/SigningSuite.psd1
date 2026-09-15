@{
    RootModule           = 'SigningSuite.psm1'
    ModuleVersion        = '2026.9.15.1'
    GUID                 = '4f1c7a2e-9b3d-4e8a-a6f1-2c5d8e9b7a31'
    Author               = 'Jason Ulbright'
    Copyright            = '(c) Jason Ulbright. All rights reserved.'
    Description          = 'Authenticode signing for scripts, executables, installers, catalogs, app packages and Office VBA projects.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @(
        'Clear-OfficeVbaSignature'
        'ConvertFrom-SignToolOutput'
        'ConvertTo-CommandLineArgument'
        'ConvertTo-SafeCsvField'
        'ConvertTo-SignatureText'
        'Find-ArtifactSigningDlib'
        'Find-SignableFile'
        'Find-SignTool'
        'Get-AppPackageIdentity'
        'Get-CertificateKeyProvider'
        'Get-CertificateLabel'
        'Get-FileSignatureState'
        'Get-FormatProvider'
        'Get-OfficeSipStatus'
        'Get-SignableFileInfo'
        'Get-SigningCertificate'
        'Get-SigningSuiteSettings'
        'Get-SigningSuiteSettingsPath'
        'Get-SipGapMessage'
        'Get-SipSubject'
        'Get-SupportedExtension'
        'Import-PfxToUserStore'
        'Invoke-ExternalProcess'
        'Invoke-FileSigning'
        'Invoke-SigningBatch'
        'Invoke-SignTool'
        'New-ArtifactSigningMetadata'
        'New-SignToolSignArgument'
        'Resolve-SigningEngine'
        'Save-SigningSuiteSettings'
        'Test-CertificateMatchesPublisher'
        'Test-CodeSigningUsage'
        'Test-FileSignature'
        'Test-OfficeVbaProject'
        'Test-SipRegistered'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        SigningSuiteVersion = '2026.09.15.0001'
        PSData              = @{
            Tags = @('Authenticode', 'CodeSigning', 'SignTool', 'VBA', 'MSIX')
        }
    }
}
