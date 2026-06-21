using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace BlazorApp2.Services;

/// <summary>
/// RSA asymmetric encryption handler ("RsaHandler" per the assignment).
/// Generates an RSA key pair on first run and persists it so the same public
/// key keeps working across restarts. The private key is never written to
/// disk in plaintext - it's wrapped with ASP.NET Core's Data Protection API
/// (AES + HMAC internally, per the assignment's background theory) before
/// being saved, and unwrapped on load.
/// </summary>
public class RsaHandler
{
    private const int KeySizeBits = 3072;
    private readonly RSA _rsa;

    public RsaHandler(IDataProtectionProvider dataProtectionProvider, IWebHostEnvironment env)
    {
        var protector = dataProtectionProvider.CreateProtector("BlazorApp2.RsaHandler.PrivateKey");

        var keyDirectory = Path.Combine(env.ContentRootPath, "App_Data");
        Directory.CreateDirectory(keyDirectory);
        var keyFilePath = Path.Combine(keyDirectory, "rsa-private-key.protected");

        _rsa = RSA.Create(KeySizeBits);

        if (File.Exists(keyFilePath))
        {
            var protectedBytes = File.ReadAllBytes(keyFilePath);
            var pkcs8 = protector.Unprotect(protectedBytes);
            _rsa.ImportPkcs8PrivateKey(pkcs8, out _);
        }
        else
        {
            var pkcs8 = _rsa.ExportPkcs8PrivateKey();
            var protectedBytes = protector.Protect(pkcs8);
            File.WriteAllBytes(keyFilePath, protectedBytes);
        }
    }

    /// <summary>
    /// The public key in PEM-encoded SubjectPublicKeyInfo (X.509 SPKI) format
    /// - the modern, self-describing, broadly interoperable standard for
    /// exchanging public keys (it embeds the algorithm identifier), as
    /// opposed to the older, RSA-specific PKCS#1 format.
    /// </summary>
    public string ExportPublicKeyPem() => _rsa.ExportSubjectPublicKeyInfoPem();

    /// <summary>
    /// Decrypts data encrypted with the matching public key. Uses OAEP
    /// padding - the "extra structured data added to the plaintext before
    /// RSA encryption" the assignment refers to - rather than the legacy
    /// PKCS#1 v1.5 padding, which is vulnerable to padding-oracle attacks.
    /// </summary>
    public byte[] Decrypt(byte[] cipherText) => _rsa.Decrypt(cipherText, RSAEncryptionPadding.OaepSHA256);
}
