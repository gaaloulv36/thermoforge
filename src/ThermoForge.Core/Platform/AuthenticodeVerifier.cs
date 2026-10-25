using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using ThermoForge.Core.Processes;

namespace ThermoForge.Core.Platform;

/// <summary>
/// Verifies Authenticode signatures with WinVerifyTrust. Many Windows binaries carry no
/// embedded signature and are instead signed through a system catalog (.cat), so a file
/// without an embedded signature is looked up in the catalog database before being
/// reported as unsigned. Revocation is not checked (no network access).
/// </summary>
public static class AuthenticodeVerifier
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static readonly IntPtr NoUi = new(-1);

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    private const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
    private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
    private const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
    private const int CERT_E_CHAINING = unchecked((int)0x800B010A);
    private const int CERT_E_REVOKED = unchecked((int)0x800B010C);
    private const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
    private const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
    private const int TRUST_E_CERT_SIGNATURE = unchecked((int)0x80096004);

    private static readonly string[] CatalogHashAlgorithms = ["SHA256", "SHA1"];

    public static SignatureInfo Verify(string path)
    {
        var embedded = RunWinVerifyTrust(
            new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = path },
            WTD_CHOICE_FILE);

        if (embedded == 0)
            return new SignatureInfo(SignatureStatus.Signed, GetSigner(path), null);

        if (embedded is not (TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN))
            return Classify(embedded);

        return VerifyViaCatalog(path)
            ?? (IsInstalledPackageFile(path)
                ? new SignatureInfo(SignatureStatus.Signed, null, "Microsoft Store / MSIX package (signature verified by Windows at install)")
                : new SignatureInfo(SignatureStatus.Unsigned, null, null));
    }

    private static readonly string WindowsAppsDirectory =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps") + Path.DirectorySeparatorChar;

    /// <summary>
    /// MSIX apps are signed per package (AppxSignature.p7x), not per executable. Windows verifies
    /// the package at install, and only the system can write to WindowsApps, so its files are trusted.
    /// </summary>
    private static bool IsInstalledPackageFile(string path) =>
        path.StartsWith(WindowsAppsDirectory, StringComparison.OrdinalIgnoreCase);

    /// <returns>Null when the file is not listed in any system catalog.</returns>
    private static SignatureInfo? VerifyViaCatalog(string path)
    {
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            foreach (var algorithm in CatalogHashAlgorithms)
            {
                var result = VerifyViaCatalog(path, file.SafeFileHandle, algorithm);
                if (result is not null)
                    return result;
            }
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return SignatureInfo.Unknown($"File could not be read: {ex.Message}");
        }
    }

    private static SignatureInfo? VerifyViaCatalog(string path, SafeFileHandle file, string algorithm)
    {
        if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0))
            return null;

        try
        {
            uint hashSize = 0;
            CryptCATAdminCalcHashFromFileHandle2(admin, file, ref hashSize, null, 0);
            var hash = new byte[hashSize];
            if (hashSize == 0 || !CryptCATAdminCalcHashFromFileHandle2(admin, file, ref hashSize, hash, 0))
                return null;

            var previous = IntPtr.Zero;
            var catalogContext = CryptCATAdminEnumCatalogFromHash(admin, hash, hashSize, 0, ref previous);
            if (catalogContext == IntPtr.Zero)
                return null;

            try
            {
                var catalog = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                if (!CryptCATCatalogInfoFromContext(catalogContext, ref catalog, 0))
                    return null;

                var hashPtr = Marshal.AllocHGlobal(hash.Length);
                try
                {
                    Marshal.Copy(hash, 0, hashPtr, hash.Length);
                    var result = RunWinVerifyTrust(
                        new WINTRUST_CATALOG_INFO
                        {
                            cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                            pcwszCatalogFilePath = catalog.wszCatalogFile,
                            pcwszMemberTag = Convert.ToHexString(hash),
                            pcwszMemberFilePath = path,
                            pbCalculatedFileHash = hashPtr,
                            cbCalculatedFileHash = (uint)hash.Length,
                            hCatAdmin = admin,
                        },
                        WTD_CHOICE_CATALOG);

                    return result == 0
                        ? new SignatureInfo(SignatureStatus.Signed, GetSigner(catalog.wszCatalogFile), "Signed via Windows catalog")
                        : Classify(result);
                }
                finally
                {
                    Marshal.FreeHGlobal(hashPtr);
                }
            }
            finally
            {
                CryptCATAdminReleaseCatalogContext(admin, catalogContext, 0);
            }
        }
        finally
        {
            CryptCATAdminReleaseContext(admin, 0);
        }
    }

    private static int RunWinVerifyTrust<T>(T union, uint unionChoice) where T : struct
    {
        var unionPtr = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
        Marshal.StructureToPtr(union, unionPtr, false);
        try
        {
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = unionChoice,
                pUnion = unionPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
            };
            var action = GenericVerifyV2;
            var result = WinVerifyTrust(NoUi, ref action, ref data);

            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NoUi, ref action, ref data);
            return result;
        }
        finally
        {
            Marshal.DestroyStructure<T>(unionPtr);
            Marshal.FreeHGlobal(unionPtr);
        }
    }

    private static SignatureInfo Classify(int result) => result switch
    {
        TRUST_E_BAD_DIGEST => Invalid("The file was modified after it was signed."),
        CERT_E_UNTRUSTEDROOT => Invalid("Signed with a certificate Windows does not trust (e.g. self-signed)."),
        CERT_E_CHAINING => Invalid("The signing certificate's chain could not be verified."),
        CERT_E_EXPIRED => Invalid("The signing certificate expired and the signature was not timestamped."),
        CERT_E_REVOKED => Invalid("The signing certificate was revoked."),
        TRUST_E_EXPLICIT_DISTRUST => Invalid("The signing certificate is explicitly distrusted."),
        TRUST_E_CERT_SIGNATURE => Invalid("The certificate signature is invalid."),
        // Anything else (access denied, policy blocks, ...) says nothing about the file itself.
        _ => SignatureInfo.Unknown($"Verification failed (0x{result:X8})."),
    };

    private static SignatureInfo Invalid(string detail) => new(SignatureStatus.Invalid, null, detail);

    private static string? GetSigner(string signedFile)
    {
        try
        {
#pragma warning disable SYSLIB0057 // No X509CertificateLoader equivalent for reading the signer of a PE/catalog file.
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(signedFile));
#pragma warning restore SYSLIB0057
            return certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin, SafeFileHandle hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }
}
