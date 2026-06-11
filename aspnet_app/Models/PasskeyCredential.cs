using MinimalApi.Data;

namespace MinimalApi.Models;

public class PasskeyCredential
{
    public int Id { get; set; }
    public string UserId { get; set; } = default!;
    public string CredentialId { get; set; } = default!;
    public byte[] PublicKey { get; set; } = default!;
    public uint SignatureCounter { get; set; }
    public ApplicationUser User { get; set; } = default!;
}
