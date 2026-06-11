using BlazorApp2;
using BlazorApp2.Components;
using BlazorApp2.Components.Account;
using BlazorApp2.Data;
using BlazorApp2.Services;
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

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = IdentityConstants.ApplicationScheme;
    options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
})
.AddIdentityCookies();


var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = true;
})
.AddRoles<IdentityRole>()
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

builder.Services.AddScoped<IUserClaimsPrincipalFactory<ApplicationUser>, UserClaimsPrincipalFactory<ApplicationUser, IdentityRole>>();

//builder.Services.AddIdentityCore<ApplicationUser>(options =>
//    {
//        options.SignIn.RequireConfirmedAccount = true;
//        options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
//    })
//    .AddRoles<IdentityRole>()
//    .AddEntityFrameworkStores<ApplicationDbContext>()
//    .AddSignInManager()
//    .AddDefaultTokenProviders();

builder.Services.AddSingleton<IEmailSender<ApplicationUser>, IdentityNoOpEmailSender>();

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

builder.Services.AddScoped<JwtTokenService>();
builder.Services.AddHttpClient<ApiService>();

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
    var email = body.GetProperty("email").GetString();

    var user = await userManager.FindByEmailAsync(email);

    if (user is null)
        return Results.BadRequest("User not found");

    var fidoUser = new Fido2User
    {
        Name = user.Email!,
        DisplayName = user.Email!,
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
    var user = await userManager.FindByEmailAsync(request.Email);

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
    var email = body.GetProperty("email").GetString();

    var user = await userManager.FindByEmailAsync(email);

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
    var user = await userManager.FindByEmailAsync(request.Email);

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

    // Create Admin role if it doesn't exist
    if (!await roleManager.RoleExistsAsync("Admin"))
        await roleManager.CreateAsync(new IdentityRole("Admin"));

    // Assign Admin role to a specific user
    var user = await userManager.FindByEmailAsync("fff@fff.com");
    if (user != null && !await userManager.IsInRoleAsync(user, "Admin"))
        await userManager.AddToRoleAsync(user, "Admin");
}

app.Run();
