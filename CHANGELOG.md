# Changelog

## [2026.09.27.0007] - 2026-09-27

### Security

- Run signtool.exe only when it carries a valid Microsoft signature.

### Fixes

- Sign macros that another publisher validly signed instead of skipping them.
- Name the skipped signers in the signing confirmation.
- Check revocation during Verify and report revoked signers as Revoked.
- Keep existing VBA signatures when a signing precondition fails.

## [2026.09.25.0006] - 2026-09-25

### Features

- Confirm every signing run in a dialog that shows the signing identity, files and options.
- Warn before signing files that carry another signer's signature or would lack a timestamp.
- Remove signatures from scripts, executables, installers, app packages and Office files.
- Remove signatures from the command line with -RemoveSignature.
- Pass Windows Installer properties to the Artifact Signing and Azure CLI prerequisites during setup.

### Fixes

- Keep the file list unchanged when a signing run is cancelled before it starts.

## [2026.09.15.0005] - 2026-09-15

### Delivery

- Install with SigningSuiteSetup.exe and choose optional components.
- Download and verify prerequisites from Microsoft during setup.
- Install every component silently with /VERYSILENT.
- Start the portable zip with SigningSuite.cmd.

## [2026.09.15.0004] - 2026-09-15

### Fixes

- Offer a certificate import at startup when no valid certificate exists.
- Open the certificate picker at startup when several valid certificates exist.

## [2026.09.15.0003] - 2026-09-15

### Fixes

- Explain signing service sign-in, permission and not-found errors in Details.
- Suggest the timestamp server only when a timestamp failed.

## [2026.09.15.0002] - 2026-09-15

### Fixes

- Keep folder paths ending in a backslash when restarting from PowerShell 7.
- Keep user modules ahead of system modules after the module path repair.

## [2026.09.15.0001] - 2026-09-15

### Platform

- Run on Windows PowerShell 5.1.
- Restart in Windows PowerShell when started from PowerShell 7.

### Formats

- Sign PowerShell scripts, modules, manifests, formatting and type files.
- Sign VBScript, JScript and Windows Script Files.
- Sign executables, libraries, drivers, installers, patches, cabinets and catalogs.
- Sign VBA projects in Excel, Word, PowerPoint, Visio, Project and Publisher files.
- Sign MSIX and APPX packages and bundles.

### Signing

- Sign with store certificates, smart cards, tokens, Artifact Signing or digest signing libraries.
- Choose SignTool or PowerShell as the signing engine, or let the tool choose.
- Add RFC 3161 or Authenticode timestamps.
- Dual sign executables and cabinets with SHA1 and SHA256.
- Apply all three Office VBA signatures in one run.
- Remove existing VBA signatures before re-signing Office files.
- Stop app packages whose Publisher differs from the certificate subject.

### Files

- Show each file's format, current signature and signer before signing.
- Filter the list by format, status and file name.
- Skip files that already carry a valid signature.
- Verify signatures, including signature and timestamp counts.
- Export results to CSV.
- Cancel scans, signing and verification between files.

### Command line

- Sign or verify from a build pipeline, failing the step when a file fails.
- Preview what would be signed with -WhatIf.
