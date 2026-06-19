using Microsoft.EntityFrameworkCore;

namespace BlazorApp2.Data;

/// <summary>
/// Separate database for file metadata, intentionally using a different DB
/// engine (SQLite) than the Identity store (SQL Server). This is a deliberate
/// data-compartmentalization technique: a breach of one database doesn't
/// automatically expose the other, and each can have its own access controls.
/// </summary>
public class FileMetadataDbContext(DbContextOptions<FileMetadataDbContext> options) : DbContext(options)
{
    public DbSet<FileMetadata> Files => Set<FileMetadata>();
}
