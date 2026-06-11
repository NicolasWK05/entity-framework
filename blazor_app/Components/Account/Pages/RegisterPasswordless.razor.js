window.startPasskeyRegistration = async function (email) {
    // STEP 1: GET OPTIONS
    const optionsResponse =
        await fetch("/webauthn/register/options", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: email })
        });

    if (!optionsResponse.ok) {
        alert("Failed to get passkey options");
        return;
    }

    const options = await optionsResponse.json();
    const publicKey = structuredClone(options);

    // STEP 3: CONVERT BASE64URL -> ARRAYBUFFER
    publicKey.challenge = base64UrlToBuffer(publicKey.challenge);

    publicKey.user.id = base64UrlToBuffer(publicKey.user.id);

    if (publicKey.excludeCredentials)
        publicKey.excludeCredentials = publicKey.excludeCredentials.map(c => ({ ...c, id: base64UrlToBuffer(c.id) }));

    // STEP 4: CREATE PASSKEY
    const credential = await navigator.credentials.create({ publicKey: publicKey });

    // STEP 5: SEND TO SERVER
    const finishResponse =
        await fetch("/webauthn/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                email: email,
                attestationResponse: {
                    id: credential.id,
                    rawId: bufferToBase64Url(credential.rawId),
                    type: credential.type,
                    response: {
                        attestationObject: bufferToBase64Url(credential.response.attestationObject),
                        clientDataJson: bufferToBase64Url(credential.response.clientDataJSON)
                    }
                },
                originalOptions: options // IMPORTANT: SEND ORIGINAL OPTIONS
            })
        });

    if (!finishResponse.ok) {
        const error = await finishResponse.text();
        console.error(error);
        alert(error);
        return;
    }

    window.location.href = "/Account/Login";
};


function bufferToBase64Url(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

function base64UrlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}