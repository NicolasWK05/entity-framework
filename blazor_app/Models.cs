using BlazorApp2.Data;
using Fido2NetLib;

namespace BlazorApp2;

public class PasskeyCredential
{
    public int Id { get; set; }
    public string UserId { get; set; } = default!;
    public string CredentialId { get; set; } = default!;
    public byte[] PublicKey { get; set; } = default!;
    public uint SignatureCounter { get; set; }
    public ApplicationUser User { get; set; } = default!;
}

public class CredentialCreateRequest
{
    public string Email { get; set; } = default!;
    public AuthenticatorAttestationRawResponse AttestationResponse { get; set; } = default!;
    public CredentialCreateOptions OriginalOptions { get; set; } = default!;
}

public class AssertionRequest
{
    public string Email { get; set; } = default!;
    public AuthenticatorAssertionRawResponse AssertionResponse { get; set; } = default!;
    public AssertionOptions OriginalOptions { get; set; } = default!;
}
