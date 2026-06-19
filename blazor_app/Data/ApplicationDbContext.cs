using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace BlazorApp2.Data
{
    public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : IdentityDbContext<ApplicationUser>(options)
    {
        public DbSet<PasskeyCredential> PasskeyCredentials => Set<PasskeyCredential>();

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<ApplicationUser>(b =>
            {
                // Username: plain text, max 10 chars (assignment requirement).
                // Uniqueness is already enforced by Identity's default unique index
                // on NormalizedUserName, so nothing extra is needed for that part.
                b.Property(u => u.UserName).HasMaxLength(10);
                b.Property(u => u.NormalizedUserName).HasMaxLength(10);

                // Email is never stored in plain or recoverable form — only its
                // Argon2id hash + salt (EmailHash / EmailSalt below). Remove the
                // inherited Email/NormalizedEmail/EmailConfirmed columns entirely
                // rather than leaving them present-but-unused.
                b.Ignore(u => u.Email);
                b.Ignore(u => u.NormalizedEmail);
                b.Ignore(u => u.EmailConfirmed);

                // Passkey-only: a password must never be persisted, structurally,
                // not just "happens to stay null".
                b.Ignore(u => u.PasswordHash);

                // No password means no 2FA / phone-based flows in this build.
                b.Ignore(u => u.PhoneNumber);
                b.Ignore(u => u.PhoneNumberConfirmed);
                b.Ignore(u => u.TwoFactorEnabled);

                b.Property(u => u.EmailHash).IsRequired();
                b.Property(u => u.EmailSalt).IsRequired();
            });
        }
    }
}
