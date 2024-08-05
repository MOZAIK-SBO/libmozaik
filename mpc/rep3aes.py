from key_share import prepare_params_for_dist_enc

import subprocess
import json

class Rep3AesConfig:
    def __init__(self, path_to_config, path_to_bin):
        self.config = path_to_config
        self.bin = path_to_bin

def dist_enc(config, keys, params):
    """
    Arguments
     - config: Rep3AesConfig
     - keys: MpcPartyKeys
     - params: list of tuples
        - user_id: string
        - computation_id: string
        - analysis_type: string
        - key_share: bytes-like of length 16 or 176
        - message_share: list-like of 64-bit numbers in pairs (e.g. [[1,2], [3,4]])
    
    Returns list of ciphertext (bytes) or error (string)
    """
    batched = True # compute in batched mode except if a key share is given
    # batched mode is currently only supported for key schedule shares
    input_args = []
    for (user_id, computation_id, analysis_type, key_share, message_share) in params:
        if len(key_share) != 16 and len(key_share) != 176:
            raise ValueError("Expected key_share to be 16 or 176 bytes")
        for (i,(v1,v2)) in enumerate(message_share):
            if abs(v1) >= 2**64 or abs(v2) >= 2**64:
                raise ValueError(f'Message share at index {i} is larger than 64-bits: {v}')
        (nonce, ad) = prepare_params_for_dist_enc(keys, user_id, computation_id, analysis_type)
        args = {
            'nonce': nonce.hex(),
            'associated_data': ad.hex(),
            'message_share': message_share
        }
        if len(key_share) == 16:
            args['key_share'] = key_share.hex()
            batched = False
        elif len(key_share) == 176:
            args['key_schedule_share'] = key_share.hex()
        else:
            raise ValueError("Unsupported key_share length")
        input_args.append(args)
    if batched:
        return _dist_enc_call(config, input_args)
    else:
        output = list()
        for arg in input_args:
            output.append(_dist_enc_call(config, [arg])[0])
        return output

def dist_dec(config, args):
    """
    Arguments
    - config: Rep3AesConfig
    - args: list of (user_id, key_share, ciphertext) with
        - user_id: string
        - key_share: bytes-like of length 16 or 176
        - ciphertext: bytes-like

    Returns [res1, res2, ...] where
    res is either a list of pairs of 64-bit numbers or None if the decryption failed for this argument
    """
    inputs = []
    batched = True # compute in batched mode except if a key share is given
    # batched mode is currently only supported for key schedule shares
    for (user_id, key_share, ciphertext) in args:
        if len(key_share) != 16 and len(key_share) != 176:
            raise ValueError("Expected key_share to be 16 or 176 bytes")
        if len(ciphertext) < 28:
            raise ValueError("Expected ciphertext to be at least 28 bytes (12 byte nonce + 16 byte tag)")
        # print(key_share.hex(), ciphertext.hex())
        nonce = ciphertext[:12]
        ad = bytes(user_id, encoding='utf-8') + nonce
        args = {
            'nonce': nonce.hex(),
            'associated_data': ad.hex(),
            'ciphertext': ciphertext[12:].hex()
        }
        if len(key_share) == 16:
            args['key_share'] = key_share.hex()
            batched = False
        elif len(key_share) == 176:
            args['key_schedule_share'] = key_share.hex()
        else:
            raise ValueError("Unsupported key_share length")
        inputs.append(args)
    if batched:
        return _dist_dec_call(config, inputs)
    else:
        output = list()
        for arg in inputs:
            output.append(_dist_dec_call(config, [arg])[0])
        return output

def _dist_enc_call(config, input_args):
    command = [config.bin, '--config', config.config, 'encrypt', '--mode', 'AES-GCM-128']
    input_args = json.dumps(input_args)
    # print(f'Running "{" ".join(command)}" with input {input_args}')
    result = subprocess.run(command, text=True, input=input_args, capture_output=True)
    if result.returncode != 0:
        print(f'Command "{" ".join(command)}" exited with code {result.returncode}')
        print(result.stderr)
        print(result.stdout)
        raise RuntimeError("Dist_enc failed")
    # try to parse the output of the program
    output = json.loads(result.stdout)
    if not isinstance(output, list):
        raise RuntimeError(f'Unexpected output: {output}')
    encryption_result = []
    for output_part in output:
        # this expects the following JSON
        # { "ciphertext": hex-string, "error": error string }
        if "ciphertext" in output_part and "error" not in output_part:
            encryption_result.append(bytes.fromhex(output_part["ciphertext"]))
        elif "error" in output_part:
            encryption_result.append(output_part['error'])
        else:
            raise RuntimeError(f'Unexpected output: {output_part}')
    return encryption_result

def _dist_dec_call(config, input_args):
    command = [config.bin, '--config', config.config, 'decrypt', '--mode', 'AES-GCM-128']
    
    input_args = json.dumps(input_args)
    # print(f'Running "{" ".join(command)}" with input {input_args}')
    result = subprocess.run(command, text=True, input=input_args, capture_output=True)
    if result.returncode != 0:
        command = " ".join(str(path) for path in command)
        print(f'Command "{command}" exited with code {result.returncode}')
        print(result.stderr)
        print(result.stdout)
        raise RuntimeError("Dist_dec failed")
    # try to parse the output of the program
    output = json.loads(result.stdout)
    outputs = []
    for res in output:
        if "message_share" in res and "error" not in res and "tag_error" not in res:
            # message share should be a list of pairs of numbers
            message_share = res["message_share"]
            for m in message_share:
                if len(m) != 2:
                    raise RuntimeError(f'Dist_dec output unexpected: {m}')
                m1,m2 = m
                if not isinstance(m1, int) or abs(m1) >= 2**64 or not isinstance(m2, int) or abs(m2) >= 2**64:
                    raise RuntimeError(f'Dist_dec output unexpected: {m1} {m2}')
            outputs.append(message_share)
        elif "tag_error" in res and "error" not in res:
            outputs.append(None)
        elif "error" in res:
            raise RuntimeError(f'Dist_dec failed: {res["error"]}')
        else:
            raise RuntimeError(f'Unexpected output: {res}')
    return outputs