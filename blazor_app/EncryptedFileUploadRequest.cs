namespace BlazorApp2;

public record EncryptedFileUploadRequest(
    string FileName,
    string FileType,
    string EncryptedAesKeyBase64,
    string NonceBase64,
    string TagBase64,
    string CipherTextBase64);
