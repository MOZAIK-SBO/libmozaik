from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

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
    
    def _load_public_key(path):
        with open(path, 'r') as fp:
            pk = RSA.import_key(fp.read())
            assert not pk.has_private()
            return pk
        
        

def decrypt_key_share(keys, user_id, algorithm, data_indices, analysis_type, ciphertext):
    pk1, pk2, pk3 = keys.party_keys
    # create context
    context = bytes(user_id, encoding='utf-8') + pk1.export_key(format='DER') + pk2.export_key(format='DER') + pk3.export_key(format='DER')
    data_indices_buf = bytearray(len(data_indices) * 4)
    for i,d in enumerate(data_indices):
        data_indices_buf[4*i] = d & 0xff
        data_indices_buf[4*i+1] = (d >> 8) & 0xff
        data_indices_buf[4*i+2] = (d >> 16) & 0xff
        data_indices_buf[4*i+3] = (d >> 24) & 0xff
    context += data_indices_buf
    context += bytes(analysis_type, encoding='utf-8') + bytes(algorithm, encoding='utf-8') + keys.my_pub_key.export_key(format='DER')

    instance = PKCS1_OAEP.new(keys.my_priv_key, hashAlgo=SHA256, label=context)
    try:
        return instance.decrypt(ciphertext)
    except ValueError as e:
        # the integrity check of the decryption failed
        return None