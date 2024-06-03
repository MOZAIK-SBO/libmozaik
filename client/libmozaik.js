import Module from "./openfhe_pke_es6.js";

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

export async function createAnalysisRequestData(userId, iotDeviceKey, algorithm, party1Pubkey, party2Pubkey, party3Pubkey, analysisType, dataIndices) {
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

export async function createAnalysisRequestFHE(userId, analysisType, dataIndices) {
    return [userId, analysisType, dataIndices];
}

async function parse_plaintext_from_string(pt_in) {
    // this function exists because the function "GetPackedCoefsReal" is broken in wasm (no reason why, but it's like that)
    let plaintext_string = `${pt_in}`;
    let idx_part = plaintext_string.indexOf(")");
    let pt_vec = plaintext_string.slice(1, idx_part);
    let coef_str_arr = pt_vec.split(",");
    // last entry will be nan since openfhe truncates output after index=batchsize
    let vals = coef_str_arr.map(parseFloat).slice(0, 5);
    // In the end, we compute softmax here, for both accuracy and speed
	// There is no loss in privacy, since softmax can be inverted up to a constant
	// equal in every slot, i.e. only the mean of the input distribution
	// is shifted, not the other parameters. This is also a reason
	// why there are alternatives if one is concerned about adversarial ml
    let val_exp = vals.map(Math.exp);
    let norm = val_exp.reduce((acc,x) => acc + x, 0);
    return val_exp.map((x) => x / norm);
}

async function DecryptCKKSCipherText(cryptoContextSer, encryptedResultSer, secretKeySer){

    let OpenFHE = await Module();

    const sertype = OpenFHE.SerType.JSON;

    let enc = new TextEncoder();
    var cc_arr;
    var ct_arr;
    var sk_arr;	

    if (sertype != OpenFHE.SerType.JSON) {
	let cc_bin = atob(cryptoContextSer.replace(/_/g, '/').replace(/-/g, '+'));
	let ct_bin = atob(encryptedResultSer.replace(/_/g, '/').replace(/-/g, '+'));
	let sk_bin = atob(secretKeySer.replace(/_/g, '/').replace(/-/g, '+'));
	cc_arr = [...Array(cc_bin.length).keys()].map((x) => cc_bin.charCodeAt(x));
	ct_arr = [...Array(ct_bin.length).keys()].map((x) => ct_bin.charCodeAt(x));
	sk_arr = [...Array(sk_bin.length).keys()].map((x) => sk_bin.charCodeAt(x));
    } else {
    	cc_arr = enc.encode(cryptoContextSer);
    	ct_arr = enc.encode(encryptedResultSer);
    	sk_arr = enc.encode(secretKeySer);
    }

    console.log(cc_arr);
    console.log(ct_arr);
    console.log(sk_arr);

    // Sample Program: Step 1: Set CryptoContext
    console.log("Setting up the Cryptocontext")

    const cc = await OpenFHE.DeserializeCryptoContextFromBuffer(cc_arr, sertype);
    console.log("CryptoContext was deserialized properly");

    const ct1 = await OpenFHE.DeserializeCiphertextFromBuffer(ct_arr, sertype);
    console.debug("CipherText was deserialized properly");

    const sk = await OpenFHE.DeserializePrivateKeyFromBuffer(sk_arr, sertype);
    console.debug("SecretKey was deserialized properly");

    // Decrypt the result of additions
    const plaintext = cc.Decrypt(sk, ct1);
    plaintext.SetLength(5);

    OpenFHE.ReleaseAllContexts();

    return await parse_plaintext_from_string(plaintext);
}

export async function reconstructResultFHE(userId,cryptoContextSer,secretKeySer,encryptedResultSer) {
	console.log(cryptoContextSer);
    console.debug("Executing Reconstruct");
    // result is an array of doubles
    return await DecryptCKKSCipherText(cryptoContextSer, encryptedResultSer, secretKeySer);
}
