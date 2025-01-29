async function signMessage(privateKey, message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const signature = await window.crypto.subtle.sign(
        {
            name: "RSA-PSS",
            saltLength: 32,
        },
        privateKey,
        data
    );
    return arrayBufferToBase64(signature);
}

async function verifySignature(publicKey, message, signature) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const signatureBytes = base64ToArrayBuffer(signature);
    return await window.crypto.subtle.verify(
        {
            name: "RSA-PSS",
            saltLength: 32,
        },
        publicKey,
        signatureBytes,
        data
    );
}

async function verifyMessage(username, message, signature) {
    try {
        const response = await $.get(`/messages/get_public_key/${username}`);
        const publicKeyPem = response.public_key;
        const publicKey = await importPublicKey(publicKeyPem);
        return await verifySignature(publicKey, message, signature);
    } catch (error) {
        console.error("Verification error:", error);
        return false;
    }
}

async function importPublicKey(pem) {
    const binaryDer = atob(pem.replace(/-----.*?-----|\n/g, ""));
    const buffer = Uint8Array.from(binaryDer, c => c.charCodeAt(0)).buffer;
    return await window.crypto.subtle.importKey(
        "spki",
        buffer,
        {
            name: "RSA-PSS",
            hash: "SHA-256",
        },
        false,
        ["verify"]
    );
}

function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

async function importPrivateKey(pem) {
    const pemHeader = pem.replace(/-----.*?-----|\n/g, "");
    const binaryDer = base64ToArrayBuffer(pemHeader);
    return await window.crypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        {
            name: "RSA-PSS",
            hash: "SHA-256",
        },
        false,
        ["sign"]
    );
}

async function generateKeyPair() {
    return await window.crypto.subtle.generateKey(
        {
            name: "RSA-PSS",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["sign", "verify"]
    );
}

function convertArrayBufferToPem(buffer, type) {
    const base64String = btoa(String.fromCharCode(...new Uint8Array(buffer)))
        .match(/.{1,64}/g)
        .join("\n");

    return `-----BEGIN ${type}-----\n${base64String}\n-----END ${type}-----`;
}

async function exportPrivateKey(privateKey) {
    try {
        const exported = await window.crypto.subtle.exportKey("pkcs8", privateKey);
        return convertArrayBufferToPem(exported, "PRIVATE KEY");
    } catch (e) {
        console.error("Error exporting private key:", e);
        return null;
    }
}

async function exportPublicKey(publicKey) {
    const exported = await window.crypto.subtle.exportKey("spki", publicKey);
    return convertArrayBufferToPem(exported, "PUBLIC KEY");
}

function savePrivateKeyPem(privateKeyPem) {
    localStorage.setItem("private_key", privateKeyPem);
}

function getPrivateKeyPem() {
    return localStorage.getItem("private_key");
}

