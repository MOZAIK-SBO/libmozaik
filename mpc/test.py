import unittest

from key_share import MpcPartyKeys, decrypt_key_share

class TestDecryptKeyShare(unittest.TestCase):
    def get_config(party_index):
        party_keys = ['tls_certs/server1.crt', 'tls_certs/server2.crt', 'tls_certs/server3.crt']
        return {
            "server_key": f'tls_certs/server{party_index+1}.key',
            "server_cert": f'tls_certs/server{party_index+1}.crt',
            "party_index": party_index,
            "party_certs": party_keys
        }

    ciphertexts = [
        bytes.fromhex('8ca86d5cf34aaf3f271f758df5a29298b861ebc0f5cd9b3b41290b466541024e9cce3407e6d7d5fa9ab9e9e09150393e27ae241da61e51beccf2a86d663b89acad66cd6ec9b8325d8067f560e034987421298efdf5d5f6740ef5ebeb1b86312edd66dc7bccc04fac94d99912a250bb9fe6a208586f2dc30bcf81b8fa910faee7153974f8c07cc8f9bda2f265c08687b888a1905253d3274089cb857a8860809bc75d839f58c3e3b720a515105190181b5b350c97caa57f2e0126bb8452709f27c0b5d91f29e8f822631e0911de4b6d51b5e7848d74aa393c51899d91fcaf1eb60e95771bd9066d09cfdaafdee6c4bd0215c7aa5afa560d3028c50640b904716b'),
        bytes.fromhex('1770ee77177e6591020780779d07e890f97364efaa854a5f21e035fd9c5cd1ee019164723bb837ffe2311993166d78e21ab22fba8a179abe618aecfcf77289f6814769906f61ca46eaab9159e959d7a4d9abfb06810f326f4f37b234f08c1632e1e563ebe3730af948d7f0b37b7c6dc1006c1c4db8e9bdbe20a7fd648a2ff5df1e1f1d7e106fb99ff6611fc30ec55587ca58001804e0a15d126d7e80f9fd0249590ce11ae44abbabec0d58fdc6d45e6378ecca7c548ce78247b32b81a84578b8d58b8d2cd2b4f8555e3985d1e887f4de637e56f861b35a30297ce924a3e7389581537e7895a14eab9f106a5afcb62901eaf90cfb0e107aff5ad9711df5e09162'),
        bytes.fromhex('7c372f33db0d740f150f0827851c5d66f3477eb817b139315e06fe6cb8ce312433bea5642548e50f07be3422f274255960fdcf8ff576a78df523668c720e960489f8f2f325454e35633bda81a8e920deb4639d8e8a55e099b164d9d215d6bc241fb2542ecb985b73f9cb6abfbdc4032978e5da5f44331415be9ab239738282615aedc1729edb4736e05792d6237843ad00cde81f66b3e645cf345007f8140bf5cd658756332fe05ffabeae1673d71e6d8a00dcb859dc029c0adfca4e724e7b2ae2a1229127de203d03816135826263683b14ac1c4d954ac07f94d2273785474a68014bed61bf5b23b9c344a52cad4af543a1978d3dca6ebab36f2faf26b5a01a')
    ]
    expected_key = bytes.fromhex('12233445566778899aabbccddeeff001')

    def test_correct_decryption(self):
        shares = list()
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        analysis_type = "Heartbeat-Demo-1"
        data_indices = [1706094000, 1706094001, 1706094002, 1706094003, 1706094004, 1706094005, 1706094006, 1706094007, 1706094008, 1706094009]
        for i in range(3):
            keys = MpcPartyKeys(TestDecryptKeyShare.get_config(i))
            ct = TestDecryptKeyShare.ciphertexts[i]
            key_share = decrypt_key_share(keys, user_id, "AES-GCM-128", data_indices, analysis_type, ct)
            assert key_share != None
            shares.append(key_share)
        
        assert all(len(s) == 16 for s in shares)
        # reconstruct and check
        computed_key = bytearray(16)
        for i in range(16):
            computed_key[i] = shares[0][i] ^ shares[1][i] ^ shares[2][i]
        assert computed_key == TestDecryptKeyShare.expected_key


if __name__ == '__main__':
    unittest.main()
