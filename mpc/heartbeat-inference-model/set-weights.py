import os
import struct
import numpy as np

def read_model_from_file(file_path):
        data = []
        with open(file_path, 'r') as file:
            for line in file:
                pairs = line.strip().split()
                pairs = [tuple(map(int, pair.split(','))) for pair in pairs]
                data.append(pairs)
        return data
        
def write_shares(party, data):
        # Define the data to be written at the beginning
        header_data = bytearray([
            0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x6d, 0x61, 0x6c, 0x69, 0x63, 0x69, 0x6f, 0x75, 
            0x73, 0x20, 0x72, 0x65, 0x70, 0x6c, 0x69, 0x63,
            0x61, 0x74, 0x65, 0x64, 0x20, 0x5a, 0x32, 0x5e, 
            0x36, 0x34, 0x40, 0x00, 0x00, 0x00
        ])

        # Open the binary file in write mode
        if os.path.exists(f'../MP-SPDZ/Persistence/Transactions-P{party}.data'):
            with open(f'../MP-SPDZ/Persistence/Transactions-P{party}.data', 'wb') as file:
                # Write the header data at the beginning of the file
                file.write(header_data)
                # Encode and write the input 64-bit integers in little endian format
                for rss_share in data:
                    # print(rss_share)
                    for share in rss_share:
                        packed_share = struct.pack('<q', share)
                        file.write(packed_share)


for i in range(3):
     model = [] 
     weights = read_model_from_file(f'model_shares{i+1}.txt')
     biases = read_model_from_file(f'biases_shares{i+1}.txt')
     for weight_pair in weights[0]:
          model.append(weight_pair)
     for biases_pair in biases[0]:
          model.append(biases_pair)
     write_shares(i, model)
