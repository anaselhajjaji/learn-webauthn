// STEP 1
// The server would begin creating a new credential by calling 
// navigator.credentials.create() on the client
async function createCredentials() {
    var randomStringFromServer = 'I am a random string generated from server';
    
    const publicKeyCredentialCreationOptions = {
        // challenge: The challenge is a buffer of cryptographically random bytes generated on the server, and is needed to prevent "replay attacks". 
        // Read the spec: https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-challenge
        challenge: Uint8Array.from(
            randomStringFromServer, c => c.charCodeAt(0)),
        // rp: This stands for “relying party”; it can be considered as describing the organization responsible for registering and authenticating the user. 
        // The id must be a subset of the domain currently in the browser. For example, a valid id for this page is webauthn.guide. 
        // Read the spec: https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-rp
        rp: {
            name: "Anas Localhost",
            id: "localhost", // To make the example work on localhost, otherwise it should be: something.com
        },
        user: {
            id: Uint8Array.from(
                "UZSL85T9AFC", c => c.charCodeAt(0)),
            name: "lee@webauthn.guide",
            displayName: "Lee",
        },
        pubKeyCredParams: [{alg: -7, type: "public-key"}],
        authenticatorSelection: {
            authenticatorAttachment: "cross-platform",
        },
        timeout: 60000,
        attestation: "direct"
    };
    
    const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
    });
}