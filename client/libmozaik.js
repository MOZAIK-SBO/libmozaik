import { Aes as SJCLAes } from "./aes.js";

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
    console.log(share)
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

/**
 * Outputs the key schedule of AES-128 as Uint8Array.
 * @param key: Uint8Array of length 16
 */
function computeAes128KeySchedule(key) {
    console.assert(key.length == 16);
    // convert into correct format: SJCL expects 4 32-bit words
    const aesKey = [0, 0, 0, 0];
    for (var i=0; i<4; i++) {
        aesKey[i] = (key[4*i] << 24) + (key[4*i+1] << 16) + (key[4*i+2] << 8) + key[4*i+3];
    }
    const aesCipher = new SJCLAes(aesKey);
    const keyscheduleList = aesCipher._key[0]; // _key[0] is the forward keyschedule
    // keyscheduleList is a list of 44 32-bit words
    const ks = new Uint8Array(44*4);
    // write keyschedule in big-endian byte order
    for (var i=0; i<44; i++) {
        const word = keyscheduleList[i];
        ks[4*i] = (word >> 24) & 0xff;
        ks[4*i+1] = (word >> 16) & 0xff;
        ks[4*i+2] = (word >> 8) & 0xff;
        ks[4*i+3] = word & 0xff;
    }
    return ks;
}

async function createAnalysisRequestDataHelper(stateSeparation, userId, iotDeviceKey, algorithm, party1Pubkey, party2Pubkey, party3Pubkey, analysisType, dataIndices) {
    // create context
    const textEncoder = new TextEncoder();
    const userIdAndPubkeyBuffer = await createUserIdAndPubkeyContext(textEncoder, userId, party1Pubkey, party2Pubkey, party3Pubkey);
    const analysisTypeBuffer = textEncoder.encode(analysisType);
    // dataIndices are 64-bit timestamps
    const dataIndicesBuffer = new ArrayBuffer(dataIndices.length * 8);
    const view = new DataView(dataIndicesBuffer);
    console.log(dataIndices);
    for (var i = 0; i < dataIndices.length; i++) {
        const int64 = dataIndices[i];
        // load the buffer in little endian order
        view.setBigUint64(8*i, BigInt(int64), true);
    }
    const algorithmBuffer = textEncoder.encode(algorithm);
    const sepBuffer = new Uint8Array(1);
    sepBuffer[0] = stateSeparation;
    const contextBuffer = append([sepBuffer, userIdAndPubkeyBuffer["contextBuf"], dataIndicesBuffer, analysisTypeBuffer, algorithmBuffer]);

    if (algorithm == "AES-GCM-128") {
        if (iotDeviceKey.byteLength != 16) {
            throw "Expected key size of 128bit";
        }
        const ks = computeAes128KeySchedule(iotDeviceKey);
        var share1 = new Uint8Array(176);
        var share2 = new Uint8Array(176);
        window.crypto.getRandomValues(share1);
        window.crypto.getRandomValues(share2);
        var share3 = new Uint8Array(176);
        for (var i=0; i<176; i++) {
            share3[i] = ks[i] ^ share1[i] ^ share2[i];
        }
        var c1 = await pkEnc(share1, party1Pubkey, userIdAndPubkeyBuffer["pk1Buf"], contextBuffer);
        var c2 = await pkEnc(share2, party2Pubkey, userIdAndPubkeyBuffer["pk2Buf"], contextBuffer);
        var c3 = await pkEnc(share3, party3Pubkey, userIdAndPubkeyBuffer["pk3Buf"], contextBuffer);
        return [c1, c2, c3];
    }else{
        throw "Unsupported algorithm";
    }
}

export async function createAnalysisRequestData(userId, iotDeviceKey, algorithm, party1Pubkey, party2Pubkey, party3Pubkey, analysisType, dataIndices) {
    return createAnalysisRequestDataHelper(0x1, userId, iotDeviceKey, algorithm, party1Pubkey, party2Pubkey, party3Pubkey, analysisType, dataIndices);
}

export async function createAnalysisRequestDataForStreaming(userId, iotDeviceKey, algorithm, party1Pubkey, party2Pubkey, party3Pubkey, analysisType, streamingBegin, streamingEnd) {
    return createAnalysisRequestDataHelper(0x2, userId, iotDeviceKey, algorithm, party1Pubkey, party2Pubkey, party3Pubkey, analysisType, [streamingBegin, streamingEnd]);
}

export async function reconstructResult(userId, iotDeviceKey, party1Pubkey, party2Pubkey, party3Pubkey, computationId, analysisType, encryptedResult) {
    // create context
    const textEncoder = new TextEncoder();
    const userIdAndPubkeyBuffer = (await createUserIdAndPubkeyContext(textEncoder, userId, party1Pubkey, party2Pubkey, party3Pubkey))["contextBuf"];
    const compIdBuf = textEncoder.encode(computationId);
    const analysisTypeBuf = textEncoder.encode(analysisType);
    const context = append([userIdAndPubkeyBuffer, compIdBuf, analysisTypeBuf]);

    // convert key
    const key = await crypto.importKey("raw", iotDeviceKey, {name: "AES-GCM"}, true, ["decrypt"]);

    // derive nonce from context
    const fullNonce = await crypto.digest("SHA-256", context);
    // the full nonce is too large, AES-GCM can only handle 96-bit
    const msg = await crypto.decrypt({name: "AES-GCM", iv: fullNonce.slice(0,12), additionalData: context, tagLength: 128}, key, encryptedResult);
    return msg;
}

