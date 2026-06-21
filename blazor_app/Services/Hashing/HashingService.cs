using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace BlazorApp2.Services.Hashing;

public sealed class HashingService : IHashingService
{
    private const string PepperEnvVarName = "EMAIL_HASH_PEPPER";

    private static string GetPepper()
    {
        var pepper = Environment.GetEnvironmentVariable(PepperEnvVarName);
        if (string.IsNullOrEmpty(pepper))
        {
            throw new InvalidOperationException(
                $"Environment variable '{PepperEnvVarName}' is not set. " +
                "The pepper must never be hardcoded or committed to source control.");
        }
        return pepper;
    }

    private static byte[] GenerateSalt(int sizeBytes = 16) => RandomNumberGenerator.GetBytes(sizeBytes);

    // ---------- SHA-2 ----------
    public HashResult HashSha2(string input, byte[]? salt = null, HashAlgorithmName? algorithm = null)
    {
        salt ??= GenerateSalt();
        var algo = algorithm ?? HashAlgorithmName.SHA256;
        var pepper = GetPepper();

        var payload = Encoding.UTF8.GetBytes(input + pepper).Concat(salt).ToArray();

        using HashAlgorithm hashAlgo = algo.Name switch
        {
            "SHA256" => SHA256.Create(),
            "SHA384" => SHA384.Create(),
            "SHA512" => SHA512.Create(),
            _ => throw new NotSupportedException($"Unsupported SHA-2 variant: {algo.Name}")
        };

        var hash = hashAlgo.ComputeHash(payload);
        return new HashResult(Convert.ToBase64String(hash), Convert.ToBase64String(salt));
    }

    // ---------- HMAC ----------
    public HashResult HashHmac(string input, byte[]? salt = null, HashAlgorithmName? algorithm = null)
    {
        salt ??= GenerateSalt();
        var algo = algorithm ?? HashAlgorithmName.SHA256;
        var pepper = GetPepper();

        // Salt + pepper form the HMAC key — a standard way to bind both into a keyed hash.
        var key = salt.Concat(Encoding.UTF8.GetBytes(pepper)).ToArray();
        var message = Encoding.UTF8.GetBytes(input);

        using HMAC hmac = algo.Name switch
        {
            "SHA256" => new HMACSHA256(key),
            "SHA384" => new HMACSHA384(key),
            "SHA512" => new HMACSHA512(key),
            _ => throw new NotSupportedException($"Unsupported HMAC variant: {algo.Name}")
        };

        var hash = hmac.ComputeHash(message);
        return new HashResult(Convert.ToBase64String(hash), Convert.ToBase64String(salt));
    }

    // ---------- PBKDF2 ----------
    public HashResult HashPbkdf2(string input, byte[]? salt = null, int iterations = 100_000, HashAlgorithmName? algorithm = null)
    {
        salt ??= GenerateSalt();
        var algo = algorithm ?? HashAlgorithmName.SHA256;
        var pepper = GetPepper();

        var hash = Rfc2898DeriveBytes.Pbkdf2(
            password: Encoding.UTF8.GetBytes(input + pepper),
            salt: salt,
            iterations: iterations,
            hashAlgorithm: algo,
            outputLength: 32);

        return new HashResult(Convert.ToBase64String(hash), Convert.ToBase64String(salt));
    }

    // ---------- bcrypt ----------
    public HashResult HashBcrypt(string input, int workFactor = 12)
    {
        var pepper = GetPepper();
        // BCrypt generates and embeds its own salt inside the returned hash string,
        // so there's no separate salt value to hand back here.
        var hash = BCrypt.Net.BCrypt.HashPassword(input + pepper, workFactor: workFactor);
        return new HashResult(hash, SaltBase64: string.Empty);
    }

    // ---------- Argon2id (chosen method for email hashing) ----------
    public HashResult HashArgon2id(string input, byte[]? salt = null, int iterations = 4, int memorySizeKb = 65536, int parallelism = 2)
    {
        salt ??= GenerateSalt();
        var pepper = GetPepper();

        // Explicitly instantiating Argon2id (not Argon2i / Argon2d) — this is the
        // "manually specified hashing algorithm" required for the chosen method.
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(input + pepper))
        {
            Salt = salt,
            DegreeOfParallelism = parallelism,
            Iterations = iterations,
            MemorySize = memorySizeKb
        };

        var hash = argon2.GetBytes(32);
        return new HashResult(Convert.ToBase64String(hash), Convert.ToBase64String(salt));
    }

    public bool VerifyArgon2id(string input, string expectedHashBase64, string saltBase64, int iterations = 4, int memorySizeKb = 65536, int parallelism = 2)
    {
        var salt = Convert.FromBase64String(saltBase64);
        var result = HashArgon2id(input, salt, iterations, memorySizeKb, parallelism);

        var expected = Convert.FromBase64String(expectedHashBase64);
        var actual = Convert.FromBase64String(result.HashBase64);

        // Constant-time comparison to avoid leaking match length via timing.
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    // ---------- File integrity (HMAC, separate key from the email pepper) ----------
    private const string FileIntegrityKeyEnvVarName = "FILE_INTEGRITY_KEY";

    private static byte[] GetFileIntegrityKey()
    {
        var keyBase64 = Environment.GetEnvironmentVariable(FileIntegrityKeyEnvVarName);
        if (string.IsNullOrEmpty(keyBase64))
        {
            throw new InvalidOperationException(
                $"Environment variable '{FileIntegrityKeyEnvVarName}' is not set. " +
                "Generate one with `openssl rand -base64 32` and set it as an environment " +
                "variable - it must never be hardcoded in source.");
        }
        return Convert.FromBase64String(keyBase64);
    }

    public string HashFileIntegrity(byte[] fileBytes)
    {
        var key = GetFileIntegrityKey();
        using var hmac = new HMACSHA256(key);
        var hash = hmac.ComputeHash(fileBytes);
        return Convert.ToBase64String(hash);
    }

    public bool VerifyFileIntegrity(byte[] fileBytes, string expectedHashBase64)
    {
        var actualHashBase64 = HashFileIntegrity(fileBytes);

        var expected = Convert.FromBase64String(expectedHashBase64);
        var actual = Convert.FromBase64String(actualHashBase64);

        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }
}
