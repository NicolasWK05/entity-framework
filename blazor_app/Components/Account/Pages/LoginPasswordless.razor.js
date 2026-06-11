window.webauthnLogin = async function (options) {
    // KEEP ORIGINAL OPTIONS
    const publicKey = structuredClone(options);

    publicKey.challenge = base64UrlToBuffer(publicKey.challenge);

    if (publicKey.allowCredentials) {
        publicKey.allowCredentials.forEach(c => { c.id = base64UrlToBuffer(c.id); });
    }

    const assertion = await navigator.credentials.get({ publicKey: publicKey });

    return {
        id: assertion.id,
        rawId: bufferToBase64Url(assertion.rawId),
        type: assertion.type,
        response: {
            authenticatorData: bufferToBase64Url(assertion.response.authenticatorData),
            clientDataJson: bufferToBase64Url(assertion.response.clientDataJSON),
            signature: bufferToBase64Url(assertion.response.signature),
            userHandle: assertion.response.userHandle ? bufferToBase64Url(assertion.response.userHandle) : null
        }
    };
};

window.finishPasskeyLogin = async function (payload) {
    const response = await fetch("/webauthn/login", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    return {
        ok: response.ok,
        text: await response.text()
    };
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