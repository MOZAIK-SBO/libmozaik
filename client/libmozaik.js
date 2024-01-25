var crypto = window.crypto.subtle;

function append(arrays) {
    const totalLength = arrays.reduce((acc, arr) => acc + arr.byteLength, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(new Uint8Array(arr, 0, arr.byteLength), offset);
        
        offset += arr.byteLength;
    }
    return result;
}

async function pkEnc(share, pubKey, pubKeyBuf, context) {
    const label = append([context, pubKeyBuf]);
    return crypto.encrypt({name: "RSA-OAEP", label: label}, pubKey, share);
}

async function createUserIdAndPubkeyContext(textEncoder, userId, party1Pubkey, party2Pubkey, party3Pubkey) {
    const userIdBuffer = textEncoder.encode(userId);
    const party1PubkeyBuffer = await crypto.exportKey("spki", party1Pubkey);
    const party2PubkeyBuffer = await crypto.exportKey("spki", party2Pubkey);
    const party3PubkeyBuffer = await crypto.exportKey("spki", party3Pubkey);
    return {
        "contextBuf": append([userIdBuffer, party1PubkeyBuffer, party2PubkeyBuffer, party3PubkeyBuffer]),
        "pk1Buf": party1PubkeyBuffer,
        "pk2Buf": party2PubkeyBuffer,
        "pk3Buf": party3PubkeyBuffer,
    };
}

export async function createAnalysisRequestData(userId, iotDeviceKey, algorithm, party1Pubkey, party2Pubkey, party3Pubkey, analysisType, dataIndices) {
    // create context
    const textEncoder = new TextEncoder();
    const userIdAndPubkeyBuffer = await createUserIdAndPubkeyContext(textEncoder, userId, party1Pubkey, party2Pubkey, party3Pubkey);
    const analysisTypeBuffer = textEncoder.encode(analysisType);
    const dataIndicesBuffer = new Uint8Array(dataIndices.length * 4);
    for (var i = 0; i < dataIndices.length; i++) {
        const int32 = dataIndices[i];
        // load the buffer in little endian order
        dataIndicesBuffer[4*i] = int32 & 0xff;
        dataIndicesBuffer[4*i+1] = (int32 >> 8) & 0xff;
        dataIndicesBuffer[4*i+2] = (int32 >> 16) & 0xff;
        dataIndicesBuffer[4*i+3] = (int32 >> 24) & 0xff;
    }
    const algorithmBuffer = textEncoder.encode(algorithm);
    const contextBuffer = append([userIdAndPubkeyBuffer["contextBuf"], dataIndicesBuffer, analysisTypeBuffer, algorithmBuffer]);

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
        var c1 = await pkEnc(share1, party1Pubkey, userIdAndPubkeyBuffer["pk1Buf"], contextBuffer);
        var c2 = await pkEnc(share2, party2Pubkey, userIdAndPubkeyBuffer["pk2Buf"], contextBuffer);
        var c3 = await pkEnc(share3, party3Pubkey, userIdAndPubkeyBuffer["pk3Buf"], contextBuffer);
        return [c1, c2, c3];
    }else{
        throw "Unsupported algorithm";
    }
}

export async function reconstructResult(userId, iotDeviceKey, party1Pubkey, party2Pubkey, party3Pubkey, computationId, analysisType, encryptedResult) {
    // create context
    const textEncoder = new TextEncoder();
    const userIdAndPubkeyBuffer = await createUserIdAndPubkeyContext(textEncoder, userId, party1Pubkey, party2Pubkey, party3Pubkey)["contextBuf"];
    const compIdBuf = textEncoder.encode(computationId);
    const analysisTypeBuf = textEncoder.encode(analysisType);
    const context = append([userIdAndPubkeyBuffer, compIdBuf, analysisTypeBuf]);

    // derive nonce from context
    const fullNonce = await crypto.digest("SHA-256", context);
    // the full nonce is too large, AES-GCM can only handle 96-bit
    const msg = await crypto.decrypt({name: "AES-GCM", iv: fullNonce.slice(0,12), additionalData: context, tagLength: 128}, iotDeviceKey, encryptedResult);
    return msg;
}