import { createAnalysisRequestData, reconstructResult } from "./libmozaik.js";
import { Aes as SJCLAes } from "./aes.js";

var crypto = window.crypto;

const mpc1Pubkey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp4dGwZNh2/98PHo9G5zb
dt+tOOab9FYYSvV1JE/bDHdwNY2/Y3ve6gX8UNMQte0aYYWfZqOKoe3kLF+yiRtk
Cro0pqm6kG5BQzf46BVz/Gkj8/psG3U46gQdEJhk1Bg/I3+ILl7kryFDEdfbKY6d
oqALuwTERTmg/YZGjGDDCmmbyNQbu+917WOk1SN3avYh+bOwDCfDasojopDik2iD
Uf37kZyQezdYrMm540NolydZhjqpD3bAT8Ui1zHWzxd5Bp5OByVLr9nF95wkmnxf
utQ/PdxNPVQpJg2R1e1FBvaqOA507lamNvemFXmSSX8Ysl2WP+I2QWKsCPaF31pX
CQIDAQAB
-----END PUBLIC KEY-----`;

const mpc2Pubkey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzMtiarObZEq3ybtnhWFv
FonjmZvfy2T1V1p30a+K2ONx5PQ7242ZF0/OT2zwy1Rzg2K2T06Qia2uwlVylKfJ
BshUmyyR22waVpopxh0DoZaIfjv0C7BzAqoFVhvvp7P/0sKV+1OJRDgZQ/GwPgRu
6xDp5bZ8F3MYWoXwaqnVWM1h9AfyCEF0zv0q6OUKibl8oGnyAb1GYvdxXYP73LnQ
JZBRI1Wg4KZ/apkad61xWTb6gLxgERcn7LVuc16cLK+QJH10uKuoLLAiLP7WQP3j
SkbVB9qYue5AmHNH+n1W+U80dMt7P+eAtN/pJVh+ltVgbR/k3MtLgFTVMr2u6Tu5
vwIDAQAB
-----END PUBLIC KEY-----`;

const mpc3Pubkey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2K5m3e1qjY59qo7Y/k4D
tuEH2zsj2Bt4mohbgE3vmKOP2Cb5NIlDjcxpRADlEyYAqdi6Ft9mYuYJ7qwQrYA/
vDGYLUCBGNxUeIAs2WjmF4dInJ8thb0tHCSlw4gyJrYdmw6nTKiafUazY7Y140lx
G/FcN17hjcUP0++sPyMVZLTqBgcfq90cGD6wJUC8n36t9hdT8lOPu9awDchaYn1d
lxZJyAFLEqOQPCrXOQhPzu4rJEzC6xBBTsTvQCJD/zbTvGY64U4Y1EaoUbo4qK7a
xTmi+Jz9Cy6Y906SSy+dTZbSbM5JkTO5XiFR9BlPUNFwGsdnUAQaTecSW616gP2R
pwIDAQAB
-----END PUBLIC KEY-----`;

function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

function importRsaKey(pem) {
  // fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemContents = pem.substring(
    pemHeader.length,
    pem.length - pemFooter.length - 1,
  );
  // base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString);

  return crypto.subtle.importKey(
    "spki",
    binaryDer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"],
  );
}

function bufferToHex (buffer) {
  return [...new Uint8Array (buffer)]
      .map (b => b.toString (16).padStart (2, "0"))
      .join ("");
}

async function testCreateAnalysisRequestData() {
  const userId = "4d14750e-2353-4d30-ac2b-e893818076d2";
  const iotDeviceKey = new Uint8Array([0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01]);
  // data indices in Obelisk are UTC timestamps with precision of milliseconds
  const dataIndices = ["2024-01-24T12:00:00", "2024-01-24T12:00:01", "2024-01-24T12:00:02", "2024-01-24T12:00:03", "2024-01-24T12:00:04", "2024-01-24T12:00:05", "2024-01-24T12:00:06", "2024-01-24T12:00:07", "2024-01-24T12:00:08", "2024-01-24T12:00:08.001"]
    .map(datestring => Date.parse(datestring));
  
  const pk1 = await importRsaKey(mpc1Pubkey);
  const pk2 = await importRsaKey(mpc2Pubkey);
  const pk3 = await importRsaKey(mpc3Pubkey);



  const cts = await createAnalysisRequestData(userId, iotDeviceKey, "AES-GCM-128", pk1, pk2, pk3, "Heartbeat-Demo-1", dataIndices);

  console.log("testCreateAnalysisRequestData ciphertexts:")
  console.log(bufferToHex(cts[0]));
  console.log(bufferToHex(cts[1]));
  console.log(bufferToHex(cts[2]));
}

function hexToBuffer(s) {
  const ct = new Uint8Array(s.length/2)
  for (var i=0; i<ct.byteLength; i++) {
    ct[i] = parseInt(s.substring(2*i, 2*i+2), 16);
  }
  return ct;
}

async function testReconstructResult() {
  const userId = "4d14750e-2353-4d30-ac2b-e893818076d2";
  const iotDeviceKey = new Uint8Array([0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01]);
  const pk1 = await importRsaKey(mpc1Pubkey);
  const pk2 = await importRsaKey(mpc2Pubkey);
  const pk3 = await importRsaKey(mpc3Pubkey);

  const computationId = "28341f07-286a-4761-8fde-220b7be3d4cc"
  const analysisType = "Heartbeat-Demo-1";

  // load hex encoded ciphertext
  const ct = hexToBuffer("2bb048962628f451545a2ff60224f46e8e2a464f0160fea8ca4dd9bfd91475af2d7c197d5c1c66e40a91a14da799fde85a089e5621df6c07");
  const result = await reconstructResult(userId, iotDeviceKey, pk1, pk2, pk3, computationId, analysisType, ct);

  console.assert(result.byteLength == 5*8);
  const expected = hexToBuffer("2bb048962628f451545a2ff60224f46e8e2a464f0160fea8ca4dd9bfd91475af2d7c197d5c1c66e4");
  console.assert(bufferToHex(result) == "884fe77815f1575505ac82e65f6a3b2c02ead604f029ca2e516e0650b866f111585ef5ec4546e010");
}

function testAesKeyschedule() {
  const iotDeviceKey = new Uint8Array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]);
  // convert into correct format
  const aesKey = [0, 0, 0, 0];
  for (var i=0; i<4; i++) {
    aesKey[i] = (iotDeviceKey[4*i] << 24) + (iotDeviceKey[4*i+1] << 16) + (iotDeviceKey[4*i+2] << 8) + iotDeviceKey[4*i+3];
  }
  const aesCipher = new SJCLAes(aesKey);
  const aesKeyschedule = new Uint32Array(aesCipher._key[0]); // _key[0] is the forward keyschedule 

  const expected = new Uint32Array([
    0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
    0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
    0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
    0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
    0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
    0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
    0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
    0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
    0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
    0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
    0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6
  ]);
  console.assert(aesKeyschedule.length == 44);
  for (var i=0; i<44; i++) {
    console.assert(aesKeyschedule[i] == expected[i]);
  }
  console.log("Test testAesKeyschedule ok");
}

testCreateAnalysisRequestData()
  .then(() => {
    console.log("Test CreateAnalysisRequestData ok");
  });
  // ,
  // error => {
  //   console.log("Error: ");
  //   console.log(error);
  // })

testReconstructResult()
  .then(() => {
    console.log("Test ReconstructResult ok");
  });

testAesKeyschedule();