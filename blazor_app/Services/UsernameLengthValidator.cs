using BlazorApp2.Data;
using Microsoft.AspNetCore.Identity;

namespace BlazorApp2.Services;

/// <summary>
/// Enforces the assignment's "username max 10 characters" rule at the Identity
/// level, in addition to any front-end form validation, so it can't be bypassed
/// by calling UserManager.CreateAsync directly.
/// </summary>
public sealed class UsernameLengthValidator : IUserValidator<ApplicationUser>
{
    private const int MaxUsernameLength = 10;

    public Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, ApplicationUser user)
    {
        if (string.IsNullOrWhiteSpace(user.UserName) || user.UserName.Length > MaxUsernameLength)
        {
            return Task.FromResult(IdentityResult.Failed(new IdentityError
            {
                Code = "UsernameTooLong",
                Description = $"Username must be between 1 and {MaxUsernameLength} characters."
            }));
        }

        return Task.FromResult(IdentityResult.Success);
    }
}
