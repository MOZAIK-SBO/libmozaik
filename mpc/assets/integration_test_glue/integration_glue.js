import { createAnalysisRequestData, reconstructResult } from "../../../client/libmozaik.js";

window.integration = Object();
window.integration.results = Object();

async function jsonToJWK(keydata) {
    return window.crypto.subtle.importKey(
        "jwk",
        keydata,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
    true,
    ["encrypt"],
    );
}

async function card_wrapper(userId, iotDeviceKey64, algorithm, party1PubkeyJSON, party2PubkeyJSON, party3PubkeyJSON, analysisType, dataIndicesSTR) {
    const iotDeviceKey = Uint8Array.from(atob(iotDeviceKey64), c => c.charCodeAt(0));
    const party1PubKey = await jsonToJWK(party1PubkeyJSON)
    const party2PubKey = await jsonToJWK(party2PubkeyJSON);
    const party3PubKey = await jsonToJWK(party3PubkeyJSON);
    const dataIndices = dataIndicesSTR.map(date => Date.parse(date) / 1000);

    const [c1,c2,c3] = await createAnalysisRequestData(userId, iotDeviceKey,algorithm, party1PubKey, party2PubKey, party3PubKey, analysisType, dataIndices)

    const view_c1 = new Uint8Array(c1);
    const view_c2 = new Uint8Array(c2);
    const view_c3 = new Uint8Array(c3);

    // create some global variables containing the base64 encoded results
    // they will be read by selenium later on
    window.integration.results.createAnalysisRequestData = {
        c1: btoa(String.fromCharCode.apply(null, view_c1)),
        c2: btoa(String.fromCharCode.apply(null, view_c2)),
        c3: btoa(String.fromCharCode.apply(null, view_c3))
    }
}

// To be able to call the module functions, we need to move them into the global scope
// (We don't really need it, but it's the easiest way)
window.integration.createAnalysisRequestData = card_wrapper;
window.integration.reconstructResult = reconstructResult;