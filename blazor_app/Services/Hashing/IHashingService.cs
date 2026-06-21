using System.Security.Cryptography;

namespace BlazorApp2.Services.Hashing;

/// <summary>
/// Custom hashing reference type, registered for dependency injection so Blazor
/// components ("front-end") can call into it directly. Implements the four required
/// methods (SHA-2, HMAC, PBKDF2, bcrypt) plus Argon2id.
///
/// Every method reads the pepper from the EMAIL_HASH_PEPPER environment variable
/// internally — it is never passed in by the caller, so it never ends up in code,
/// logs, or the database. If salt is omitted, a cryptographically random salt is
/// generated and returned in HashResult.SaltBase64 so the caller can persist it.
///
/// Argon2id is the method used for hashing email addresses in this project (see
/// HashArgon2id / VerifyArgon2id). It satisfies all four sub-requirements for the
/// chosen method: a persisted salt, an environment-variable pepper, an explicit
/// iteration ("time cost") count, and a manually specified algorithm (Argon2id,
/// as opposed to Argon2i or Argon2d).
/// </summary>
public interface IHashingService
{
    HashResult HashSha2(string input, byte[]? salt = null, HashAlgorithmName? algorithm = null);

    HashResult HashHmac(string input, byte[]? salt = null, HashAlgorithmName? algorithm = null);

    HashResult HashPbkdf2(string input, byte[]? salt = null, int iterations = 100_000, HashAlgorithmName? algorithm = null);

    HashResult HashBcrypt(string input, int workFactor = 12);

    /// <summary>The method chosen for hashing email addresses.</summary>
    HashResult HashArgon2id(string input, byte[]? salt = null, int iterations = 4, int memorySizeKb = 65536, int parallelism = 2);

    /// <summary>Re-hashes <paramref name="input"/> with the stored salt and compares in constant time.</summary>
    bool VerifyArgon2id(string input, string expectedHashBase64, string saltBase64, int iterations = 4, int memorySizeKb = 65536, int parallelism = 2);

    /// <summary>
    /// Keyed HMAC-SHA256 integrity hash for uploaded file content, computed at
    /// upload time and recomputed at download time to detect tampering. The key
    /// comes from the FILE_INTEGRITY_KEY environment variable - randomly
    /// generated once, never hardcoded in source. This reuses HashHmac's
    /// underlying algorithm, which is the natural fit among the four required
    /// methods since HMAC is specifically a *keyed* hash.
    /// </summary>
    string HashFileIntegrity(byte[] fileBytes);

    /// <summary>Recomputes the file's HMAC and compares against the stored hash in constant time.</summary>
    bool VerifyFileIntegrity(byte[] fileBytes, string expectedHashBase64);
}
