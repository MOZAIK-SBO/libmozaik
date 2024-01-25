var crypto = window.crypto.subtle;

function append(arrays) {
    const totalLength = arrays.reduce((acc, arr) => acc + arr.byteLength, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.byteLength;
    }
    return result;
}

async function pkEnc(share, pubKey, pubKeyBuf, context) {
    var label = new Uint8Array(context.byteLength + pubKeyBuf.byteLength);
    label.set(context, 0);
    label.set(pubKeyBuf, context.byteLength);
    return crypto.encrypt({name: "RSA-OAEP", label: label}, pubKey, share);
}

export async function createAnalysisRequestData(userId, iotDeviceKey, algorithm, party1Pubkey, party2Pubkey, party3Pubkey, analysisType, dataIndices) {
    // create context
    var textEncoder = new TextEncoder();
    var userIdBuffer = textEncoder.encode(userId);
    var party1PubkeyBuffer = await crypto.exportKey("spki", party1Pubkey);
    var party2PubkeyBuffer = await crypto.exportKey("spki", party2Pubkey);
    var party3PubkeyBuffer = await crypto.exportKey("spki", party3Pubkey);
    var analysisTypeBuffer = textEncoder.encode(analysisType);
    var dataIndicesBuffer = new Uint8Array(dataIndices.length * 4);
    for (var i = 0; i < dataIndices.length; i++) {
        const int32 = dataIndices[i];
        // load the buffer in little endian order
        dataIndicesBuffer[4*i] = int32 & 0xff;
        dataIndicesBuffer[4*i+1] = (int32 >> 8) & 0xff;
        dataIndicesBuffer[4*i+2] = (int32 >> 16) & 0xff;
        dataIndicesBuffer[4*i+3] = (int32 >> 24) & 0xff;
    }
    var algorithmBuffer = textEncoder.encode(algorithm);
    var contextBuffer = append([userIdBuffer, party1PubkeyBuffer, party2PubkeyBuffer, party3PubkeyBuffer, dataIndicesBuffer, analysisTypeBuffer, algorithmBuffer]);

    if (algorithm == "AES-GCM-128") {
        if (iotDeviceKey.byteLength != 16) {
            throw "Expected key size of 128bit";
        }
        var share1 = new Uint8Array(16);
        var share2 = new Uint8Array(16);
        window.crypto.getRandomValues(share1);
        window.crypto.getRandomValues(share2);
        var share3 = new Uint8Array(16);
        for (var i=0; i<16; i++) {
            share3[i] = iotDeviceKey[i] ^ share1[i] ^ share2[i];
        }
        var c1 = await pkEnc(share1, party1Pubkey, party1PubkeyBuffer, contextBuffer);
        var c2 = await pkEnc(share2, party2Pubkey, party2PubkeyBuffer, contextBuffer);
        var c3 = await pkEnc(share3, party3Pubkey, party3PubkeyBuffer, contextBuffer);
        return [c1, c2, c3];
    }else{
        throw "Unsupported algorithm";
    }
}