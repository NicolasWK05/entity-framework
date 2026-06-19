using Microsoft.AspNetCore.Identity;

namespace BlazorApp2.Data
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    public class ApplicationUser : IdentityUser
    {
        public string? CPRNr { get; set; }

        /// <summary>Argon2id hash of the user's email address. Never reversible — see HashingService.HashArgon2id.</summary>
        public string EmailHash { get; set; } = default!;

        /// <summary>Base64-encoded salt used to produce EmailHash.</summary>
        public string EmailSalt { get; set; } = default!;
    }
}
