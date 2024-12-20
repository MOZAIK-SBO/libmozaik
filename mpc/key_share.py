from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

import time


class MpcPartyKeys:
    def __init__(self, config):
        """ Inititialize from config """
        with open(config['server_key'], 'r') as fp:
            self.my_priv_key = RSA.import_key(fp.read())
            assert self.my_priv_key.has_private()
        self.my_pub_key = MpcPartyKeys._load_public_key(config['server_cert'])
        self.party_keys = [MpcPartyKeys._load_public_key(p) for p in config['party_certs']]
        assert len(self.party_keys) == 3
        assert self.party_keys[config['party_index']] == self.my_pub_key

    @staticmethod
    def _load_public_key(path: str):
        with open(path, "r") as fp:
            pk = RSA.import_key(fp.read())
            assert not pk.has_private()
            return pk

    def get_party_keys_as_bytes(self):
        buffer = list(pk.export_key(format='DER') for pk in self.party_keys)
        return b''.join(buffer)


def _decrypt_key_share_helper(keys, separation, user_id, algorithm, data_indices, analysis_type, ciphertext):
    # create context
    sep_byte = bytearray(1)
    sep_byte[0] = separation & 0xff
    context = sep_byte + bytes(user_id, encoding='utf-8') + keys.get_party_keys_as_bytes()
    # data_indices are 64-bit numbers
    data_indices_buf = bytearray(len(data_indices) * 8)
    for i, d in enumerate(data_indices):
        data_indices_buf[8 * i] = d & 0xff
        data_indices_buf[8 * i + 1] = (d >> 8) & 0xff
        data_indices_buf[8 * i + 2] = (d >> 16) & 0xff
        data_indices_buf[8 * i + 3] = (d >> 24) & 0xff
        data_indices_buf[8 * i + 4] = (d >> 32) & 0xff
        data_indices_buf[8 * i + 5] = (d >> 40) & 0xff
        data_indices_buf[8 * i + 6] = (d >> 48) & 0xff
        data_indices_buf[8 * i + 7] = (d >> 56) & 0xff
    context += data_indices_buf
    context += bytes(analysis_type, encoding='utf-8') + bytes(algorithm, encoding='utf-8') + keys.my_pub_key.export_key(
        format='DER')

    instance = PKCS1_OAEP.new(keys.my_priv_key, hashAlgo=SHA256, label=context)
    try:
        return instance.decrypt(ciphertext)
    except ValueError as e:
        # the integrity check of the decryption failed
        raise Exception("Integrity check of key share decryption failed")

def decrypt_key_share(keys, user_id, algorithm, data_indices, analysis_type, ciphertext):
    return _decrypt_key_share_helper(keys, 0x1, user_id, algorithm, data_indices, analysis_type, ciphertext)

def decrypt_key_share_for_streaming(keys, user_id, algorithm, streaming_begin, streaming_end, analysis_type, ciphertext):
    # check correct time # UTC timestamp in milliseconds
    t = time.time() * 1000
    if streaming_begin <= t < streaming_end:
        return _decrypt_key_share_helper(keys, 0x2, user_id, algorithm, [streaming_begin, streaming_end], analysis_type, ciphertext)
    else:
        raise Exception("Integrity check of key share decryption failed (invalid time)")


def prepare_params_for_dist_enc(keys, user_id, computation_id, analysis_type):
    # create context
    context = bytes(user_id, encoding='utf-8') + keys.get_party_keys_as_bytes() + bytes(computation_id,
                                                                                        encoding='utf-8') + bytes(
        analysis_type, encoding='utf-8')
    # derive nonce
    instance = SHA256.new()
    instance.update(context)
    nonce = instance.digest()[:12]
    return (nonce, context)  # nonce and associated data
