# Releasing Signing Suite

A release ships `SigningSuite-<version>.zip` and `checksums.txt`. The scripts are not signed.

## 1. Pick the version

The version is the release date plus a four-digit sequence: `YYYY.MM.DD.####`. The sequence starts at `0001` each day and is one more than the highest release already published for that date:

```bash
gh release list -R jasonulbright/signing-suite
```

## 2. Bump

1. `Module/SigningSuite/SigningSuite.psd1`: set `PrivateData.SigningSuiteVersion` to the version and `ModuleVersion` to the same numbers without leading zeros (`2026.09.15.0002` becomes `2026.9.15.2`).
2. `start-signingsuite.ps1`: set `Version` in the comment header.
3. `CHANGELOG.md`: add `## [<version>] - <date>` at the top, grouped by kind of change, one verb-first line per change.

## 3. Test

Run both hosts with Pester 5. Any failure stops the release.

```powershell
powershell.exe -NoProfile -STA -Command "Invoke-Pester -Path .\Tests"
pwsh -NoProfile -Command "Invoke-Pester -Path .\Tests"
```

Office VBA signing tests need the Office SIPs registered and a folder of macro-enabled files named in `SIGNINGSUITE_OFFICE_FIXTURES` (`Macro.xlsm`, `Macro.xls`, `Macro.docm`, `Macro.pptm`, `Macro.ppt`, `NoMacro.xlsm`). `Tests/Tools/New-OfficeFixtures.ps1` creates them with Office. Digest signing and app package tests build `Tests/Native/TestDigestSign.dll` with the Visual Studio C++ tools.

## 4. Commit, tag, build, publish

```bash
git commit -am "Release <version>"
git tag -a v<version> -m v<version>
git push origin main v<version>
```

```powershell
.\tools\Build-Release.ps1 -Version <version>
```

The build archives the tag with `git archive`, refuses a version that differs from the manifest, and fails if tests or release tooling reach the zip.

Release notes: title is the tag. The first line is the download link, then a `##` headline with one concrete outcome, `###` sections by kind of change, and the footer `Full changelog: CHANGELOG.md`.

```bash
gh release create v<version> --title v<version> --notes-file notes.md
gh release upload v<version> dist/SigningSuite-<version>.zip dist/checksums.txt
gh api repos/jasonulbright/signing-suite/releases/tags/v<version> --jq '.assets[].name'
```

Update the download link in `README.md` to the new asset in the release commit.
