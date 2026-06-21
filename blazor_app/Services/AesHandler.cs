using System.Security.Cryptography;

namespace BlazorApp2.Services;

/// <summary>
/// AES-GCM decryption counterpart to the sending app's AesHandler. GCM's
/// authentication tag is verified as part of Decrypt, so tampering with the
/// ciphertext in transit throws a CryptographicException here rather than
/// silently producing garbage plaintext.
/// </summary>
public class AesHandler
{
    public byte[] Decrypt(byte[] cipherText, byte[] key, byte[] nonce, byte[] tag)
    {
        var plainText = new byte[cipherText.Length];
        using var aesGcm = new AesGcm(key);
        aesGcm.Decrypt(nonce, cipherText, tag, plainText);
        return plainText;
    }
}
