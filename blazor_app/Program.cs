using BlazorApp2;
using BlazorApp2.Components;
using BlazorApp2.Components.Account;
using BlazorApp2.Data;
using BlazorApp2.Services;
using BlazorApp2.Services.Hashing;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<IdentityRedirectManager>();
builder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();

// NOTE: no separate AddAuthentication()/AddIdentityCookies() call here -
// AddIdentity<>() below already registers the Identity.Application,
// Identity.External etc. cookie schemes. Adding them twice throws
// "Scheme already exists: Identity.Application" at startup.

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// File metadata lives in a separate SQLite database - deliberately a different
// engine than the SQL Server Identity store (see FileMetadataDbContext).
var fileMetadataConnectionString = builder.Configuration.GetConnectionString("FileMetadata") ?? throw new InvalidOperationException("Connection string 'FileMetadata' not found.");
builder.Services.AddDbContext<FileMetadataDbContext>(options =>
    options.UseSqlite(fileMetadataConnectionString));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // No email confirmation flow exists anymore (email is hashed, never sent to
    // a real inbox), so this must stay false or no one could ever sign in.
    options.SignIn.RequireConfirmedAccount = false;
})
.AddRoles<IdentityRole>()
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddUserValidator<UsernameLengthValidator>()
.AddDefaultTokenProviders();

builder.Services.AddScoped<IUserClaimsPrincipalFactory<ApplicationUser>, UserClaimsPrincipalFactory<ApplicationUser, IdentityRole>>();

builder.Services.AddSingleton<IEmailSender<ApplicationUser>, IdentityNoOpEmailSender>();

// Custom hashing service (SHA-2 / HMAC / PBKDF2 / bcrypt / Argon2id), injectable
// into Blazor components and used here for hashing the default admin's email.
builder.Services.AddSingleton<IHashingService, HashingService>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AuthenticatedUser", policy =>
    {
        policy.RequireAuthenticatedUser();
    });
    options.AddPolicy("RequireAdministratorRole", policy =>
    {
        policy.RequireRole("Admin");
    });
});

builder.Services.AddSingleton<IFido2>(_ =>
{
    return new Fido2(new Fido2Configuration
    {
        ServerDomain = "localhost",
        ServerName = "My Blazor App",
        Origins = new HashSet<string>
        {
            "https://localhost:7228",
            "https://[::1]:7228"
        }
    });
});

builder.Services.AddScoped(sp =>
{
    var nav = sp.GetRequiredService<NavigationManager>();
    return new HttpClient { BaseAddress = new Uri(nav.BaseUri) };
});

string kestrelCertPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), @".aspnet/https/Test.pfx");
string kestrelCertPassword = "test";

builder.WebHost.ConfigureKestrel(options =>
{
    // HTTPS listener - accept connections on all network interfaces (0.0.0.0 and IPv6 equivalents)
    options.ListenAnyIP(7228, listenOptions =>
    {
        Console.WriteLine(kestrelCertPath);
        // Load certificate
        var cert = new X509Certificate2(kestrelCertPath, kestrelCertPassword);

        // Present the certificate to clients during TLS negotiation and only allow Allow only: TLS 1.2, TLS 1.3
        listenOptions.UseHttps(httpsOptions =>
        {
            httpsOptions.ServerCertificate = cert;
            httpsOptions.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
        });
    });

    // HTTP listener:
    options.ListenAnyIP(5283);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// Add additional endpoints required by the Identity /Account Razor components.
app.MapAdditionalIdentityEndpoints();

app.MapPost("/webauthn/register/options", async (JsonElement body, UserManager<ApplicationUser> userManager, IFido2 fido2, ApplicationDbContext db) =>
{
    var userName = body.GetProperty("userName").GetString();

    var user = await userManager.FindByNameAsync(userName!);

    if (user is null)
        return Results.BadRequest("User not found");

    var fidoUser = new Fido2User
    {
        Name = user.UserName!,
        DisplayName = user.UserName!,
        Id = Encoding.UTF8.GetBytes(user.Id)
    };

    var existing = db.PasskeyCredentials
    .Where(x => x.UserId == user.Id)
    .Select(x => new PublicKeyCredentialDescriptor(WebEncoders.Base64UrlDecode(x.CredentialId))).ToList();

    var options = fido2.RequestNewCredential(new RequestNewCredentialParams
    {
        User = fidoUser,
        ExcludeCredentials = existing,
        AuthenticatorSelection = new AuthenticatorSelection
        {
            UserVerification = UserVerificationRequirement.Required,
            ResidentKey = ResidentKeyRequirement.Required
        },
        AttestationPreference = AttestationConveyancePreference.None
    });

    return Results.Ok(options);
});

app.MapPost("/webauthn/register", async (CredentialCreateRequest request, IFido2 fido2, ApplicationDbContext db, UserManager<ApplicationUser> userManager) =>
{
    var user = await userManager.FindByNameAsync(request.UserName);

    if (user is null)
        return Results.BadRequest("User not found");

    var result = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
    {
        AttestationResponse = request.AttestationResponse,
        OriginalOptions = request.OriginalOptions,
        IsCredentialIdUniqueToUserCallback = async (args, ct) =>
        {
            var id = WebEncoders.Base64UrlEncode(args.CredentialId);
            return !await db.PasskeyCredentials.AnyAsync(x => x.CredentialId == id, ct);
        }
    });

    db.PasskeyCredentials.Add(new PasskeyCredential
    {
        UserId = user.Id,
        CredentialId = WebEncoders.Base64UrlEncode(result.Id),
        PublicKey = result.PublicKey,
        SignatureCounter = result.SignCount
    });

    await db.SaveChangesAsync();

    return Results.Ok(new { message = "PASSKEY SAVED" });
});

app.MapPost("/webauthn/login/options", async (JsonElement body, UserManager<ApplicationUser> userManager, IFido2 fido2, ApplicationDbContext db) =>
{
    var userName = body.GetProperty("userName").GetString();

    var user = await userManager.FindByNameAsync(userName!);

    if (user is null)
        return Results.BadRequest("User not found");

    var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
    {
        UserVerification = UserVerificationRequirement.Required
    });

    return Results.Ok(options);
});

app.MapPost("/webauthn/login", async (AssertionRequest request, IFido2 fido2, ApplicationDbContext db, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager) =>
{
    var user = await userManager.FindByNameAsync(request.UserName);

    if (user is null)
        return Results.BadRequest("User not found");

    var credentialId = WebEncoders.Base64UrlEncode(request.AssertionResponse.RawId);

    var stored = await db.PasskeyCredentials.FirstOrDefaultAsync(x => x.CredentialId == credentialId);

    if (stored is null)
        return Results.BadRequest("Credential not found");

    var result = await fido2.MakeAssertionAsync(new MakeAssertionParams
    {
        AssertionResponse = request.AssertionResponse,
        OriginalOptions = request.OriginalOptions,
        StoredPublicKey = stored.PublicKey,
        StoredSignatureCounter = stored.SignatureCounter,
        IsUserHandleOwnerOfCredentialIdCallback = async (_, __) => true
    });

    stored.SignatureCounter = result.SignCount;
    await db.SaveChangesAsync();

    await signInManager.SignInAsync(user, isPersistent: true);

    return Results.Ok();
});

using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    var hashingService = scope.ServiceProvider.GetRequiredService<IHashingService>();

    // Create Admin role if it doesn't exist
    if (!await roleManager.RoleExistsAsync("Admin"))
        await roleManager.CreateAsync(new IdentityRole("Admin"));

    // Ensure the default admin account exists. It has no passkey yet at this
    // point - whoever controls this account needs to complete passkey
    // registration against username "admin" once, the first time they use it.
    // TODO: swap "admin@example.com" for whatever the real admin email should be.
    const string adminUserName = "admin";
    var admin = await userManager.FindByNameAsync(adminUserName);

    if (admin is null)
    {
        var adminEmailHash = hashingService.HashArgon2id("admin@example.com");

        admin = new ApplicationUser
        {
            UserName = adminUserName,
            EmailHash = adminEmailHash.HashBase64,
            EmailSalt = adminEmailHash.SaltBase64
        };

        var createResult = await userManager.CreateAsync(admin);
        if (!createResult.Succeeded)
        {
            throw new InvalidOperationException(
                "Failed to create default admin: " + string.Join(", ", createResult.Errors.Select(e => e.Description)));
        }
    }

    if (!await userManager.IsInRoleAsync(admin, "Admin"))
        await userManager.AddToRoleAsync(admin, "Admin");
}

app.Run();
