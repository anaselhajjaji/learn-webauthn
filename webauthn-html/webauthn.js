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
        // user: This is information about the user currently registering. The authenticator uses the id to associate a credential with the user. 
        // It is suggested to not use personally identifying information as the id, as it may be stored in an authenticator. 
        // Read the spec: https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-user
        user: {
            id: Uint8Array.from(
                "THE_ID_OF_THE_USER", c => c.charCodeAt(0)),
            name: "anas@anas.com",
            displayName: "Anas",
        },
        // pubKeyCredParams: This is an array of objects describing what public key types are acceptable to a server. 
        // The alg is a number described in the COSE registry; for example, -7 indicates that the server accepts Elliptic Curve public keys 
        // using a SHA-256 signature algorithm. 
        // Read the spec: https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-pubkeycredparams
        pubKeyCredParams: [{alg: -7, type: "public-key"}],
        // authenticatorSelection: This optional object helps relying parties make further restrictions on the type of authenticators allowed for registration. 
        // If we use "cross-platform" it'll indicate that we want to register a cross-platform authenticator (like a Yubikey) instead of a platform authenticator like Windows Hello or Touch ID. 
        // Read the spec: https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-authenticatorselection
        authenticatorSelection: {
            //authenticatorAttachment: "cross-platform",
        },
        // timeout: The time (in milliseconds) that the user has to respond to a prompt for registration before an error is returned. 
        // Read the spec: https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-timeout
        timeout: 60000,
        // attestation: The attestation data that is returned from the authenticator has information that could be used to track users. 
        // This option allows servers to indicate how important the attestation data is to this registration event. 
        // A value of "none" indicates that the server does not care about attestation. 
        // A value of "indirect" means that the server will allow for anonymized attestation data. 
        // direct means that the server wishes to receive the attestation data from the authenticator. 
        // Read the spec: https://w3c.github.io/webauthn/#attestation-conveyance
        attestation: "direct"
    };
    
    /* The credential object returned from the create() call is an object containing the public key and other attributes used to validate the registration event.
        
        PublicKeyCredential {
            // id: The ID for the newly generated credential; 
            // it will be used to identify the credential when authenticating the user. 
            // The ID is provided here as a base64-encoded string. Read the spec: https://w3c.github.io/webauthn/#ref-for-dom-credential-id
            id: 'ADSUllKQmbqdGtpu4sjseh4cg2TxSvrbcHDTBsv4NSSX9...',
            // rawId: The ID again, but in binary form. 
            // Read the spec: https://w3c.github.io/webauthn/#dom-publickeycredential-rawid
            rawId: ArrayBuffer(59),
            response: AuthenticatorAttestationResponse {
                // clientDataJSON: This represents data passed from the browser to the authenticator in order to associate the new credential with the server and browser. 
                // The authenticator provides it as a UTF-8 byte array. 
                // Read the spec: https://w3c.github.io/webauthn/#dictdef-collectedclientdata
                clientDataJSON: ArrayBuffer(121),
                // attestationObject: This object contains the credential public key, an optional attestation certificate, 
                // and other metadata used also to validate the registration event. It is binary data encoded in CBOR. 
                // Read the spec: https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-attestationobject
                attestationObject: ArrayBuffer(306),
            },
            type: 'public-key'
        }
    */
    const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
    });

    const credentialDiv = document.getElementById('credential');

    // Parsing and validating the registration data
    // After the PublicKeyCredential has been obtained, it is sent to the server for validation. 
    // The WebAuthn specification describes a 19-point procedure to validate the registration data (https://w3c.github.io/webauthn/#registering-a-new-credential); 
    // what this looks like will vary depending on the language your server software is written in. 
    // Duo Labs has provided full example projects implementing WebAuthn written in Python (https://github.com/duo-labs/py_webauthn) and Go (https://github.com/duo-labs/webauthn).
    
    // clientDataJSON
    // The clientDataJSON is parsed by converting the UTF-8 byte array provided by the authenticator into a JSON-parsable string. 
    // On this server, this (and the other PublicKeyCredential data) will be verified to ensure that the registration event is valid.
    /*
        {
            // challenge: This is the same challenge that was passed into the create() call. 
            // The server must validate that this returned challenge matches the one generated for this registration event.
            challenge: "p5aV2uHXr0AOqUk7HQitvi-Ny1....",
            // origin: The server must validate that this "origin" string matches up with the origin of the application.
            origin: "https://webauthn.guide",
            // type: The server validates that this string is in fact "webauthn.create". If another string is provided, 
            // it indicates that the authenticator performed an incorrect operation.
            type: "webauthn.create"
        }
    */
    // decode the clientDataJSON into a utf-8 string
    const utf8Decoder = new TextDecoder('utf-8');
    const decodedClientData = utf8Decoder.decode(credential.response.clientDataJSON)
    // parse the string as an object
    const clientDataObj = JSON.parse(decodedClientData);
    console.log(clientDataObj)
    
    
    
    
    credentialDiv.innerHTML =   '<p><b>Credential ID:</b> ' + credential.id + '</p>' +
                                '<p><b>clientDataJSON:</b> ' + decodedClientData + '</p>' + 
                                '<p><b>attestationObject (base64):</b> ' + btoa(credential.response.attestationObject) + '</p>';
}