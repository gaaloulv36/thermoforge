<#
.SYNOPSIS
    Signs files with Authenticode, if a certificate is configured. See docs/SIGNING.md.

.DESCRIPTION
    Configure ONE of these with environment variables (never commit secrets):

      Azure Trusted Signing
        THERMOFORGE_SIGN_DLIB       Path to Azure.CodeSigning.Dlib.dll (from the Microsoft.Trusted.Signing.Client package)
        THERMOFORGE_SIGN_METADATA   Path to metadata.json (endpoint, account and certificate profile names)

      Certificate in the Windows certificate store (including USB tokens)
        THERMOFORGE_SIGN_THUMBPRINT SHA-1 thumbprint of the code-signing certificate

      Certificate file
        THERMOFORGE_SIGN_PFX        Path to the .pfx file
        THERMOFORGE_SIGN_PASSWORD   Its password

    Without any of them, files are left unsigned and the script exits successfully, so
    unsigned development builds keep working. Use -Check to see what is configured.
#>
param(
    [string[]]$Files,
    [switch]$Check
)

$ErrorActionPreference = 'Stop'

function Get-SigningMode {
    if ($env:THERMOFORGE_SIGN_DLIB -and $env:THERMOFORGE_SIGN_METADATA) { return 'Azure Trusted Signing' }
    if ($env:THERMOFORGE_SIGN_THUMBPRINT) { return 'Certificate store' }
    if ($env:THERMOFORGE_SIGN_PFX) { return 'PFX file' }
    return $null
}

function Find-SignTool {
    $found = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $tool = Get-ChildItem $kits -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if (-not $tool) { throw 'signtool.exe not found. Install the Windows SDK (Signing Tools for Desktop Apps).' }
    return $tool.FullName
}

$mode = Get-SigningMode
if ($Check) {
    if ($mode) { Write-Host "Signing is configured: $mode" } else { Write-Host 'Signing is not configured; builds will be unsigned.' }
    exit 0
}
if (-not $mode) {
    Write-Host "Not signing (no certificate configured): $($Files -join ', ')"
    exit 0
}
if (-not $Files) { throw 'No files given to sign.' }

$signtool = Find-SignTool
$arguments = @('sign', '/v', '/fd', 'SHA256', '/td', 'SHA256', '/d', 'ThermoForge', '/du', 'https://github.com/gaaloulv36/thermoforge')
switch ($mode) {
    'Azure Trusted Signing' {
        $arguments += @('/tr', 'http://timestamp.acs.microsoft.com', '/dlib', $env:THERMOFORGE_SIGN_DLIB, '/dmdf', $env:THERMOFORGE_SIGN_METADATA)
    }
    'Certificate store' {
        $arguments += @('/tr', 'http://timestamp.digicert.com', '/sha1', $env:THERMOFORGE_SIGN_THUMBPRINT)
    }
    'PFX file' {
        $arguments += @('/tr', 'http://timestamp.digicert.com', '/f', $env:THERMOFORGE_SIGN_PFX)
        if ($env:THERMOFORGE_SIGN_PASSWORD) { $arguments += @('/p', $env:THERMOFORGE_SIGN_PASSWORD) }
    }
}

& $signtool @arguments @Files
if ($LASTEXITCODE -ne 0) { throw "signtool failed with exit code $LASTEXITCODE." }
Write-Host "Signed ($mode): $($Files -join ', ')"
