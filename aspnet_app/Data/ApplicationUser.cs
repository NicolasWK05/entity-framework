using Microsoft.AspNetCore.Identity;

namespace MinimalApi.Data
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    public class ApplicationUser : IdentityUser
    {
        public string? CPRNr { get; set; }
    }

}
