using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using MinimalApi.Models;

namespace MinimalApi.Data
{
    public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : IdentityDbContext<ApplicationUser>(options)
    {
        public DbSet<PasskeyCredential> PasskeyCredentials => Set<PasskeyCredential>();
    }
}
