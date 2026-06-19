namespace BlazorApp2.Data;

/// <summary>
/// Metadata for a file an admin has uploaded to a user. Lives in a separate
/// database (SQLite) from Identity (SQL Server) and from the physical file
/// itself (stored on disk under Files/&lt;username&gt;).
/// </summary>
public class FileMetadata
{
    public int Id { get; set; }

    /// <summary>
    /// ApplicationUser.Id of the file's owner. Intentionally not a real foreign
    /// key - it points into a different database (the Identity store), which is
    /// the whole point of the separation: a breach of one database doesn't
    /// automatically expose the other.
    /// </summary>
    public string OwnerUserId { get; set; } = default!;

    public string FileName { get; set; } = default!;
    public string FileType { get; set; } = default!;

    /// <summary>HMAC-SHA256 integrity hash, Base64-encoded, computed at upload time.</summary>
    public string IntegrityHash { get; set; } = default!;

    public DateTime UploadedAtUtc { get; set; } = DateTime.UtcNow;
}
