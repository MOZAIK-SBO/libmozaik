import { createAnalysisRequestData } from "./libmozaik.js";

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

async function test() {
  const userId = "4d14750e-2353-4d30-ac2b-e893818076d2";
  const iotDeviceKey = new Uint8Array([0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01]);
  // data indices in Obelisk are UTC timestamps with precision of seconds
  const dataIndices = ["2024-01-24T12:00:00", "2024-01-24T12:00:01", "2024-01-24T12:00:02", "2024-01-24T12:00:03", "2024-01-24T12:00:04", "2024-01-24T12:00:05", "2024-01-24T12:00:06", "2024-01-24T12:00:07", "2024-01-24T12:00:08", "2024-01-24T12:00:09"]
    .map(datestring => Date.parse(datestring) / 1000);
  
  const pk1 = await importRsaKey(mpc1Pubkey);
  const pk2 = await importRsaKey(mpc2Pubkey);
  const pk3 = await importRsaKey(mpc3Pubkey);

  const cts = await createAnalysisRequestData(userId, iotDeviceKey, "AES-GCM-128", pk1, pk2, pk3, "Heartbeat-Demo-1", dataIndices);

  console.log(cts[0]);
  console.log(cts[1]);
  console.log(cts[2]);
}

test()
  .then(() => {
    console.log("Test ok");
  });
  // ,
  // error => {
  //   console.log("Error: ");
  //   console.log(error);
  // })