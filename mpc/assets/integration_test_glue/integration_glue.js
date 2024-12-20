import { createAnalysisRequestData, createAnalysisRequestDataForStreaming, reconstructResult } from "../../../client/libmozaik.js";

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

// Wrapper for (c)reate(A)nalysis(R)equest(D)ata
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

// Wrapper for (c)reate(A)nalysis(R)equest(D)ata(F)or(S)treaming
async function cardfs_wrapper(userId, iotDeviceKey64, algorithm, party1PubkeyJSON, party2PubkeyJSON, party3PubkeyJSON, analysisType, start, stop) {
    const iotDeviceKey = Uint8Array.from(atob(iotDeviceKey64), c => c.charCodeAt(0));
    const party1PubKey = await jsonToJWK(party1PubkeyJSON)
    const party2PubKey = await jsonToJWK(party2PubkeyJSON);
    const party3PubKey = await jsonToJWK(party3PubkeyJSON);
    const startTime = Date.parse(start);
    const stopTime = Date.parse(stop);

    const [c1,c2,c3] = await createAnalysisRequestDataForStreaming(userId, iotDeviceKey,algorithm, party1PubKey, party2PubKey, party3PubKey, analysisType, startTime, stopTime);

    const view_c1 = new Uint8Array(c1);
    const view_c2 = new Uint8Array(c2);
    const view_c3 = new Uint8Array(c3);

    // create some global variables containing the base64 encoded results
    // they will be read by selenium later on
    window.integration.results.createAnalysisRequestDataForStreaming = {
        c1: btoa(String.fromCharCode.apply(null, view_c1)),
        c2: btoa(String.fromCharCode.apply(null, view_c2)),
        c3: btoa(String.fromCharCode.apply(null, view_c3))
    }
}

// Wrapper for reconstruct result
async function rr_wrapper(userId, iotDeviceKey64, party1PubkeyJSON, party2PubkeyJSON, party3PubkeyJSON, computationId, analysisType, encryptedResult64) {
    const iotDeviceKey = Uint8Array.from(atob(iotDeviceKey64), c => c.charCodeAt(0));
    const party1PubKey = await jsonToJWK(party1PubkeyJSON)
    const party2PubKey = await jsonToJWK(party2PubkeyJSON);
    const party3PubKey = await jsonToJWK(party3PubkeyJSON);
    const encryptedResult = Uint8Array.from(atob(encryptedResult64), c => c.charCodeAt(0));

    const msg = await reconstructResult(userId, iotDeviceKey, party1PubKey, party2PubKey, party3PubKey, computationId, analysisType, encryptedResult);
    const view_msg = new Uint8Array(msg);
    window.integration.results.reconstructResult = btoa(String.fromCharCode.apply(null, view_msg));

}

// To be able to call the module functions, we need to move them into the global scope
// (We don't really need it, but it's the easiest way)
window.integration.createAnalysisRequestData = card_wrapper;
window.integration.createAnalysisRequestDataForStreaming = cardfs_wrapper;
window.integration.reconstructResult = rr_wrapper;
