<#
.SYNOPSIS
    Builds a ThermoForge release: tests, self-contained publish, signing, installer, portable zip.

.EXAMPLE
    .\build\release.ps1
    Uses the <Version> from src\ThermoForge.UI\ThermoForge.UI.csproj; output goes to artifacts\.

.EXAMPLE
    .\build\release.ps1 -Publish
    Also creates the GitHub release v<Version> with the installer, portable zip and checksums,
    using the version's section of CHANGELOG.md as release notes. Installed copies of ThermoForge
    find it within a day (or at once with "Check now").
#>
param(
    [string]$Version,
    [switch]$SkipTests,
    [switch]$Publish
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$project = Join-Path $root 'src\ThermoForge.UI\ThermoForge.UI.csproj'
$artifacts = Join-Path $root 'artifacts'
$publishDir = Join-Path $artifacts 'publish'
$sign = Join-Path $PSScriptRoot 'sign.ps1'

function Invoke-Checked([string]$what, [scriptblock]$command) {
    Write-Host "==> $what" -ForegroundColor Cyan
    & $command
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit code $LASTEXITCODE)." }
}

if (-not $Version) {
    $Version = (Select-Xml -Path $project -XPath '//Version').Node.InnerText
    if (-not $Version) { throw "No <Version> in $project; pass -Version." }
}
Write-Host "ThermoForge $Version" -ForegroundColor Green
& $sign -Check

if (Test-Path $artifacts) { Remove-Item $artifacts -Recurse -Force }
New-Item -ItemType Directory $artifacts | Out-Null

if (-not $SkipTests) {
    Invoke-Checked 'Tests' { dotnet test (Join-Path $root 'ThermoForge.slnx') -c Release --nologo -v q }
}

# Self-contained: users don't need to install .NET.
Invoke-Checked 'Publish' {
    dotnet publish $project -c Release -r win-x64 --self-contained true -p:Version=$Version -o $publishDir --nologo -v q
}

Write-Host '==> Sign app' -ForegroundColor Cyan
& $sign -Files (Join-Path $publishDir 'ThermoForge.exe'), (Join-Path $publishDir 'ThermoForge.Core.dll')

$zip = Join-Path $artifacts "ThermoForge-$Version-portable-win-x64.zip"
Write-Host '==> Portable zip' -ForegroundColor Cyan
Compress-Archive -Path (Join-Path $publishDir '*') -DestinationPath $zip

$iscc = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup 6 not found. Install it: winget install JRSoftware.InnoSetup' }

$isccArgs = @("/DAppVersion=$Version", "/DSourceDir=$publishDir", "/DOutputDir=$artifacts", '/Q')
if (($env:THERMOFORGE_SIGN_DLIB -and $env:THERMOFORGE_SIGN_METADATA) -or $env:THERMOFORGE_SIGN_THUMBPRINT -or $env:THERMOFORGE_SIGN_PFX) {
    # Inno Setup signs the installer and its uninstaller through this command ($f = file).
    $isccArgs += @('/DSign', "/Sforgesign=powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$sign`" -Files `$f")
}
Invoke-Checked 'Installer' { & $iscc @isccArgs (Join-Path $root 'installer\ThermoForge.iss') }

$hashes = Get-ChildItem $artifacts -File | Where-Object { $_.Extension -in '.exe', '.zip' } | ForEach-Object {
    "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name
}
$hashes | Set-Content (Join-Path $artifacts 'SHA256SUMS.txt') -Encoding ascii

Write-Host "`nDone:" -ForegroundColor Green
Get-ChildItem $artifacts -File | ForEach-Object { "  {0,-45} {1,8:N1} MB" -f $_.Name, ($_.Length / 1MB) }

if ($Publish) {
    $tag = "v$Version"
    $changelog = Get-Content (Join-Path $root 'CHANGELOG.md') -Raw -Encoding UTF8
    $match = [regex]::Match($changelog, '(?ms)^## ' + [regex]::Escape($Version) + '\s*$(.+?)(?=^## |\z)')
    if (-not $match.Success) { throw "CHANGELOG.md has no '## $Version' section for the release notes." }
    $notes = Join-Path $artifacts 'release-notes.md'
    # UTF-8 without a BOM, or GitHub shows the BOM as a stray character.
    [IO.File]::WriteAllText($notes, $match.Groups[1].Value.Trim(), (New-Object Text.UTF8Encoding $false))

    $assets = Get-ChildItem $artifacts -File | Where-Object { $_.Name -ne 'release-notes.md' } | ForEach-Object FullName
    Invoke-Checked "GitHub release $tag" {
        gh release create $tag @assets --repo gaaloulv36/thermoforge --target main --title "ThermoForge $Version" --notes-file $notes
    }
}
