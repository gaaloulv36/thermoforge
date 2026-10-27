# Code signing

Unsigned, `ThermoForge-Setup.exe` triggers Windows SmartScreen ("Windows protected your PC")
and shows "Unknown publisher" in the UAC prompt. A security tool that isn't signed is also a hard
sell: ThermoForge itself flags unsigned programs. Signing fixes the publisher name and lets
SmartScreen reputation build up with downloads. A brand-new certificate can still trigger warnings
at first, until enough people have run the signed files.

`build/release.ps1` already signs everything (the app, its core DLL, the installer and the
uninstaller) as soon as one of the options below is configured. Until then, builds are unsigned.

## Options

| Option | Rough cost | Notes |
|---|---|---|
| **Azure Trusted Signing** | ~$10 / month | Microsoft-managed certificate, no hardware token. Requires identity validation; check Microsoft's current eligibility rules for individuals in your country. |
| **OV code-signing certificate** (Sectigo, SSL.com, Certum, …) | ~$100–300 / year | Since 2023 the private key must live on a hardware token or cloud HSM, so you get a USB token or a cloud signing service. Certum's open-source developer certificate is among the cheapest. |

## Configure it

Set environment variables (in your user profile, or as CI secrets). Never commit them.

**Azure Trusted Signing**

1. Create a Trusted Signing account and a certificate profile in the Azure portal.
2. Install the client tools (`Microsoft.Trusted.Signing.Client` NuGet package) and sign in with `az login`.
3. Create `metadata.json`:
   ```json
   { "Endpoint": "https://<region>.codesigning.azure.net", "CodeSigningAccountName": "<account>", "CertificateProfileName": "<profile>" }
   ```
4. Set:
   ```powershell
   $env:THERMOFORGE_SIGN_DLIB = 'C:\path\to\Azure.CodeSigning.Dlib.dll'
   $env:THERMOFORGE_SIGN_METADATA = 'C:\path\to\metadata.json'
   ```

**Certificate on a USB token or in the Windows certificate store**

```powershell
$env:THERMOFORGE_SIGN_THUMBPRINT = '<SHA-1 thumbprint of the code-signing certificate>'
```

**Certificate file (.pfx)**

```powershell
$env:THERMOFORGE_SIGN_PFX = 'C:\path\to\certificate.pfx'
$env:THERMOFORGE_SIGN_PASSWORD = '<password>'
```

Signing uses `signtool.exe` from the Windows SDK (install "Windows SDK Signing Tools for Desktop
Apps" if it's missing). Check the configuration with:

```powershell
.\build\sign.ps1 -Check
```

Then build a release as usual (`.\build\release.ps1`). Verify a signed file with
`Get-AuthenticodeSignature artifacts\ThermoForge-Setup-1.0.0.exe`.
