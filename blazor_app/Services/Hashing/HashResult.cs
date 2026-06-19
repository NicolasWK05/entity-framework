namespace BlazorApp2.Services.Hashing;

/// <summary>
/// Output of a hashing operation: the resulting hash and the salt used to produce it.
/// Both are Base64-encoded so they can be stored directly as strings in the database.
/// SaltBase64 is empty for algorithms (like bcrypt) that embed their own salt in the hash.
/// </summary>
public sealed record HashResult(string HashBase64, string SaltBase64);
