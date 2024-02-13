from key_share import prepare_params_for_dist_enc

import subprocess
import json

class Rep3AesConfig:
    def __init__(self, path_to_config, path_to_bin):
        self.config = path_to_config
        self.bin = path_to_bin

def dist_enc(config, keys, user_id, computation_id, analysis_type, key_share, message_share):
    if len(key_share) != 16:
        raise ValueError("Expected key_share to be 16 bytes")
    (nonce, ad) = prepare_params_for_dist_enc(keys, user_id, computation_id, analysis_type)
    command = [config.bin, '--config', config.config, 'encrypt', '--mode', 'AES-GCM-128']
    input_args = json.dumps({
        'key_share': key_share.hex(),
        'nonce': nonce.hex(),
        'associated_data': ad.hex(),
        'message_share': message_share.hex()
    })

    # print(f'Running "{" ".join(command)}" with input {input_args}')
    result = subprocess.run(command, text=True, input=input_args, capture_output=True)
    if result.returncode != 0:
        print(f'Command "{" ".join(command)}" exited with code {result.returncode}')
        print(result.stderr)
        print(result.stdout)
        raise RuntimeError("Dist_enc failed")
    # try to parse the output of the program
    output = json.loads(result.stdout)
    # this expects the following JSON
    # { "ciphertext": hex-string, "error": error string }
    if "ciphertext" in output and "error" not in output:
        return bytes.fromhex(output["ciphertext"])
    elif "error" in output:
        raise RuntimeError(f"Dist_enc failed: {output['error']}")
    else:
        raise RuntimeError(f'Unexpected output: {output}')

def dist_dec(config, user_id, key_share, ciphertext):
    if len(key_share) != 16:
        raise ValueError("Expected key_share to be 16 bytes")
    if len(ciphertext) < 28:
        raise ValueError("Expected ciphertext to be at least 28 bytes (12 byte nonce + 16 byte tag)")
    nonce = ciphertext[:12]
    ad = bytes(user_id, encoding='utf-8') + nonce
    command = [config.bin, '--config', config.config, 'decrypt', '--mode', 'AES-GCM-128']
    input_args = json.dumps({
        'key_share': key_share.hex(),
        'nonce': nonce.hex(),
        'associated_data': ad.hex(),
        'ciphertext': ciphertext[12:].hex()
    })
    # print(f'Running "{" ".join(command)}" with input {input_args}')
    result = subprocess.run(command, text=True, input=input_args, capture_output=True)
    if result.returncode != 0:
        print(f'Command "{" ".join(command)}" exited with code {result.returncode}')
        print(result.stderr)
        print(result.stdout)
        raise RuntimeError("Dist_dec failed")
    # try to parse the output of the program
    output = json.loads(result.stdout)
    if "message_share" in output and "error" not in output and "tag_error" not in output:
        return bytes.fromhex(output["message_share"])
    elif "tag_error" in output and "error" not in output:
        raise RuntimeError("Dist_dec failed: Tag verification error")
    elif "error" in output:
        raise RuntimeError(f'Dist_dec failed: {output["error"]}')
    else:
        raise RuntimeError(f'Unexpected output: {output}')