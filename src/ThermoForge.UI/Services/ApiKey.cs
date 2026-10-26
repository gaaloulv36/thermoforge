using System.Security.Cryptography;
using System.Text;

namespace ThermoForge.UI.Services;

/// <summary>
/// Encrypts secrets with DPAPI so only the same Windows user on the same PC can read them back;
/// settings.json never holds the key in plain text.
/// </summary>
public static class ApiKey
{
    private static readonly byte[] Entropy = "ThermoForge.VirusTotal"u8.ToArray();

    public static string Protect(string key) =>
        Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(key), Entropy, DataProtectionScope.CurrentUser));

    /// <summary>Null when there is no key or it can't be decrypted (e.g. settings copied from another PC).</summary>
    public static string? Unprotect(string? protectedKey)
    {
        if (string.IsNullOrEmpty(protectedKey))
            return null;
        try
        {
            return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(protectedKey), Entropy, DataProtectionScope.CurrentUser));
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return null;
        }
    }
}
